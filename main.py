from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from collections import Counter
from pathlib import Path
from urllib.parse import quote_plus, urlencode
from typing import Any

import httpx
import requests
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Form, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from openai import OpenAI
from pydantic import BaseModel, Field
from starlette.requests import Request

from database import init_scam_db, load_scoring_context, save_analysis_event
from playwright.async_api import async_playwright
from scoring_engine import calculate_scam_probability

load_dotenv(override=True)

# ==========================================================
# CONFIG
# ==========================================================

API_KEY = os.getenv("HONEYPOT_API_KEY", "kranusapikey123")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
CALLBACK_URL = os.getenv("CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_ALERTS_ENABLED = os.getenv("TELEGRAM_ALERTS_ENABLED", "true").lower() == "true"
TELEGRAM_USERS_FILE = Path(os.getenv("TELEGRAM_USERS_FILE", str(Path.cwd() / "users.json")))
SCREENSHOT_DIR = Path(os.getenv("SCREENSHOT_DIR", str(Path.cwd() / "sandbox_shots")))
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.getenv("DB_PATH", "users.db"))
AUTH_COOKIE_NAME = "honeypot_auth"
AUTH_SECRET = os.getenv("AUTH_SECRET", "change-this-secret")
PBKDF2_ROUNDS = 200_000
GOOGLE_CLIENT_ID = (os.getenv("GOOGLE_CLIENT_ID") or "").strip().strip('"').strip("'")
GOOGLE_CLIENT_SECRET = (os.getenv("GOOGLE_CLIENT_SECRET") or "").strip().strip('"').strip("'")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

app = FastAPI(title="Agentic Honeypot AI (Dashboard Edition)")
client = OpenAI(api_key=OPENAI_KEY) if OPENAI_KEY else None

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


# ==========================================================
# AUTH + USERS
# ==========================================================


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                password_salt TEXT,
                password_hash TEXT,
                google_sub TEXT UNIQUE,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    init_scam_db()


def hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return digest.hex()


def create_password_pair(password: str) -> tuple[str, str]:
    salt = os.urandom(16)
    return base64.b64encode(salt).decode("utf-8"), hash_password(password, salt)


def verify_password(password: str, salt_b64: str, stored_hash: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64.encode("utf-8"))
    except Exception:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored_hash)


def sign_auth_token(payload: dict[str, Any]) -> str:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")
    signature = hmac.new(AUTH_SECRET.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"


def parse_auth_token(token: str | None) -> dict[str, Any] | None:
    if not token or "." not in token:
        return None
    payload_b64, signature = token.rsplit(".", 1)
    expected = hmac.new(AUTH_SECRET.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8"))
    except Exception:
        return None
    if payload.get("exp", 0) < int(time.time()):
        return None
    return payload


def issue_auth_cookie(response: RedirectResponse, user: sqlite3.Row) -> None:
    token = sign_auth_token(
        {
            "uid": int(user["id"]),
            "email": user["email"],
            "name": user["display_name"],
            "exp": int(time.time()) + (60 * 60 * 24 * 7),
        }
    )
    response.set_cookie(
        AUTH_COOKIE_NAME,
        token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )


def clear_auth_cookie(response: RedirectResponse) -> None:
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")


def current_user_from_request(request: Request) -> dict[str, Any] | None:
    payload = parse_auth_token(request.cookies.get(AUTH_COOKIE_NAME))
    if not payload:
        return None
    return {"id": payload["uid"], "email": payload["email"], "name": payload["name"]}


def current_user_from_ws(ws: WebSocket) -> dict[str, Any] | None:
    payload = parse_auth_token(ws.cookies.get(AUTH_COOKIE_NAME))
    if not payload:
        return None
    return {"id": payload["uid"], "email": payload["email"], "name": payload["name"]}


def get_google_redirect_uri(request: Request | None = None) -> str:
    if GOOGLE_REDIRECT_URI:
        return GOOGLE_REDIRECT_URI
    if request is not None:
        return str(request.url_for("google_callback"))
    return "http://127.0.0.1:8000/auth/google/callback"


def get_user_by_email(email: str) -> sqlite3.Row | None:
    with db_connect() as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()


def create_local_user(email: str, password: str, display_name: str) -> sqlite3.Row:
    salt_b64, password_hash = create_password_pair(password)
    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO users(email, display_name, password_salt, password_hash, created_at)
            VALUES(?, ?, ?, ?, ?)
            """,
            (email.strip().lower(), display_name, salt_b64, password_hash, int(time.time())),
        )
        conn.commit()
        return conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()


def upsert_google_user(email: str, display_name: str, google_sub: str) -> sqlite3.Row:
    with db_connect() as conn:
        existing = conn.execute("SELECT * FROM users WHERE google_sub = ?", (google_sub,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET email = ?, display_name = ? WHERE google_sub = ?",
                (email.strip().lower(), display_name, google_sub),
            )
            conn.commit()
            return conn.execute("SELECT * FROM users WHERE google_sub = ?", (google_sub,)).fetchone()

        by_email = conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
        if by_email:
            conn.execute(
                "UPDATE users SET google_sub = ?, display_name = ? WHERE email = ?",
                (google_sub, display_name, email.strip().lower()),
            )
            conn.commit()
            return conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()

        conn.execute(
            """
            INSERT INTO users(email, display_name, google_sub, created_at)
            VALUES(?, ?, ?, ?)
            """,
            (email.strip().lower(), display_name, google_sub, int(time.time())),
        )
        conn.commit()
        return conn.execute("SELECT * FROM users WHERE google_sub = ?", (google_sub,)).fetchone()


# ==========================================================
# MEMORY
# ==========================================================

sessions: dict[str, dict[str, Any]] = {}
sessions_lock = asyncio.Lock()
telegram_users_file_lock = threading.Lock()


class ConnectionManager:
    def __init__(self) -> None:
        self.connections: list[WebSocket] = []
        self.lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self.lock:
            self.connections.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self.lock:
            if ws in self.connections:
                self.connections.remove(ws)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        message = json.dumps(payload)
        stale: list[WebSocket] = []
        async with self.lock:
            for ws in self.connections:
                try:
                    await ws.send_text(message)
                except Exception:
                    stale.append(ws)
            for ws in stale:
                if ws in self.connections:
                    self.connections.remove(ws)


manager = ConnectionManager()


def get_session(session_id: str) -> dict[str, Any]:
    if session_id not in sessions:
        sessions[session_id] = {
            "createdAt": int(time.time()),
            "updatedAt": int(time.time()),
            "telegramScreenshotSent": False,
            "scamProbability": 0.0,
            "riskLevel": "LOW",
            "riskReasons": [],
            "history": [],
            "intel": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
                "linkReports": [],
            },
            "riskScore": 0.0,
            "status": "active",
        }
    return sessions[session_id]


# ==========================================================
# TELEGRAM USERS + ALERTS
# ==========================================================


def load_users() -> list[int]:
    if not TELEGRAM_USERS_FILE.exists():
        return []
    try:
        raw = json.loads(TELEGRAM_USERS_FILE.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            return []
        cleaned = []
        seen: set[int] = set()
        for item in raw:
            try:
                chat_id = int(item)
            except Exception:
                continue
            if chat_id in seen:
                continue
            seen.add(chat_id)
            cleaned.append(chat_id)
        return cleaned
    except Exception:
        return []


def save_user(chat_id: int) -> bool:
    chat_id = int(chat_id)
    with telegram_users_file_lock:
        users = load_users()
        if chat_id in users:
            return False
        users.append(chat_id)
        TELEGRAM_USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")
        return True


async def send_telegram_message(text: str) -> bool:
    if not (TELEGRAM_ALERTS_ENABLED and TELEGRAM_BOT_TOKEN):
        return False

    users = await asyncio.to_thread(load_users)
    if not users:
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    async def _send(chat_id: int) -> bool:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }

        def _post() -> bool:
            try:
                res = requests.post(url, json=payload, timeout=8)
                return 200 <= res.status_code < 300
            except Exception:
                return False

        return await asyncio.to_thread(_post)

    results = await asyncio.gather(*[_send(chat_id) for chat_id in users], return_exceptions=True)
    return any(result is True for result in results)


async def _send_telegram_message_to_chat(chat_id: int, text: str) -> bool:
    if not (TELEGRAM_ALERTS_ENABLED and TELEGRAM_BOT_TOKEN):
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": int(chat_id),
        "text": text,
        "disable_web_page_preview": True,
    }

    def _post() -> bool:
        try:
            res = requests.post(url, json=payload, timeout=8)
            return 200 <= res.status_code < 300
        except Exception:
            return False

    return await asyncio.to_thread(_post)


async def send_telegram_screenshot(image_path: str) -> bool:
    if not (TELEGRAM_ALERTS_ENABLED and TELEGRAM_BOT_TOKEN):
        return False

    image = Path(image_path)
    if not image.exists():
        return False

    users = await asyncio.to_thread(load_users)
    if not users:
        return False

    try:
        image_bytes = image.read_bytes()
    except Exception:
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendPhoto"

    async def _send(chat_id: int) -> bool:
        def _post() -> bool:
            try:
                files = {"photo": (image.name, image_bytes, "image/png")}
                data = {"chat_id": chat_id}
                res = requests.post(url, data=data, files=files, timeout=12)
                return 200 <= res.status_code < 300
            except Exception:
                return False

        return await asyncio.to_thread(_post)

    results = await asyncio.gather(*[_send(chat_id) for chat_id in users], return_exceptions=True)
    return any(result is True for result in results)


def _select_first_screenshot(intel: dict[str, Any]) -> str | None:
    for report in intel.get("linkReports", []):
        shot = report.get("screenshot")
        if shot and Path(shot).exists():
            return shot
    return None


# ==========================================================
# RULE DETECTION
# ==========================================================

PATTERNS = [
    r"otp",
    r"upi",
    r"verify",
    r"blocked",
    r"urgent",
    r"click.*link",
    r"refund",
    r"bank",
    r"account",
    r"password",
    r"transfer",
    r"pin",
    r"login",
    r"secure",
]


def rule_score(text: str) -> float:
    text = text.lower()
    hits = sum(bool(re.search(p, text)) for p in PATTERNS)
    return round(hits / len(PATTERNS), 3)


# ==========================================================
# URL EXTRACTION
# ==========================================================


def extract_urls(text: str) -> list[str]:
    urls = re.findall(r"http[s]?://\S+|www\.\S+", text)
    normalized: list[str] = []
    for url in urls:
        if url.startswith("www."):
            normalized.append(f"https://{url}")
        else:
            normalized.append(url)
    return normalized


# ==========================================================
# PLAYWRIGHT SANDBOX
# ==========================================================

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "bank",
    "otp",
    "password",
    "account",
    "secure",
    "update",
]


async def sandbox_scan_url(url: str, session_id: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "url": url,
        "loginForm": False,
        "keywords": [],
        "title": "",
        "screenshot": "",
        "verdict": "SAFE",
        "timestamp": int(time.time()),
    }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page()
            await page.goto(url, timeout=12000, wait_until="domcontentloaded")

            html = (await page.content()).lower()
            title = (await page.title()).strip()
            report["title"] = title

            if 'type="password"' in html:
                report["loginForm"] = True

            for word in SUSPICIOUS_WORDS:
                if word in html:
                    report["keywords"].append(word)

            session_dir = SCREENSHOT_DIR / session_id
            session_dir.mkdir(parents=True, exist_ok=True)

            shot = session_dir / f"{int(time.time() * 1000)}.png"
            await page.screenshot(path=str(shot), full_page=True)
            report["screenshot"] = str(shot)

            await browser.close()

        score = 0
        if report["loginForm"]:
            score += 2
        if len(report["keywords"]) >= 3:
            score += 2

        if score >= 3:
            report["verdict"] = "PHISHING"
        elif score == 2:
            report["verdict"] = "SUSPICIOUS"

        return report
    except Exception as exc:
        return {"url": url, "verdict": "ERROR", "error": str(exc), "timestamp": int(time.time())}


async def scan_links(text: str, intel: dict[str, Any], session_id: str) -> tuple[bool, list[dict[str, Any]]]:
    urls = extract_urls(text)
    phishing = False
    reports: list[dict[str, Any]] = []

    for url in urls:
        report = await sandbox_scan_url(url, session_id)
        intel["phishingLinks"].append(url)
        intel["linkReports"].append(report)
        reports.append(report)

        if report.get("verdict") == "PHISHING":
            phishing = True

    return phishing, reports


# ==========================================================
# INTEL EXTRACTION
# ==========================================================


def dedup_ordered(values: list[Any]) -> list[Any]:
    seen = set()
    result = []
    for value in values:
        marker = json.dumps(value, sort_keys=True) if isinstance(value, dict) else value
        if marker in seen:
            continue
        seen.add(marker)
        result.append(value)
    return result


def extract_intel(text: str, intel: dict[str, Any]) -> dict[str, Any]:
    intel["bankAccounts"] += re.findall(r"\b\d{12,18}\b", text)
    intel["upiIds"] += re.findall(r"\b[\w.-]+@[\w.-]+\b", text)
    intel["phoneNumbers"] += re.findall(r"(?:\+91[- ]?)?[6-9]\d{4}[- ]?\d{5}", text)

    for word in ["urgent", "verify", "blocked", "otp"]:
        if word in text.lower():
            intel["suspiciousKeywords"].append(word)

    for key, value in intel.items():
        if isinstance(value, list) and value and not isinstance(value[0], dict):
            intel[key] = dedup_ordered(value)

    return intel


# ==========================================================
# LLM REPLY
# ==========================================================


def detect_language(text: str) -> str:
    # Basic language detection:
    # 1) Devanagari -> Hindi mode
    # 2) Romanized Hindi keywords -> Hindi mode (Hinglish output)
    if re.search(r"[\u0900-\u097F]", text):
        return "hi"
    lowered = f" {text.lower()} "
    romanized_hindi_markers = [
        " aap ",
        " tum ",
        " kya ",
        " mera ",
        " meri ",
        " kr ",
        " kar ",
        " hai ",
        " nhi ",
        " nahi ",
        " paise ",
        " bank ",
        " otp ",
        " link ",
        " bhejo ",
        " jaldi ",
    ]
    if sum(marker in lowered for marker in romanized_hindi_markers) >= 2:
        return "hi"
    return "en"


def fallback_reply(language: str = "en") -> str:
    if language == "hi":
        return "Mujhe abhi poori tarah samajh nahi aaya. Kripya thoda aur clearly batayein."
    return "I am not sure yet. Can you explain the issue again?"


def generate_reply(history: list[dict[str, Any]], language: str = "en") -> str:
    conversation = "\n".join(msg.get("text", "") for msg in history[-12:])
    language_instruction = (
        "Respond only in Hindi using English letters (Hinglish / romanized Hindi), never Devanagari script."
        if language == "hi"
        else "Respond only in English."
    )

    prompt = f"""
You are a normal innocent bank customer.

Behavior rules:
- Always reply naturally to the latest message, even if it does not look suspicious.
- If suspicious, ask follow-up questions and gather details while staying natural.
- Never reveal you are an AI or a honeypot.
- Keep the scammer engaged.
- Two short sentences only.
{language_instruction}

Conversation:
{conversation}
"""

    if client:
        try:
            res = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=120,
                temperature=0.6,
            )
            return res.choices[0].message.content.strip()
        except Exception:
            pass

    try:
        payload = {"model": "llama3", "prompt": prompt, "stream": False}
        with httpx.Client(timeout=30) as http:
            response = http.post(OLLAMA_URL, json=payload)
            response.raise_for_status()
            return response.json().get("response", "").strip() or fallback_reply(language)
    except Exception:
        return fallback_reply(language)


# ==========================================================
# CALLBACK
# ==========================================================


async def post_with_retry(
    http: httpx.AsyncClient,
    url: str,
    json_payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    attempts: int = 1,
    base_delay_seconds: float = 0.5,
) -> bool:
    for attempt in range(1, attempts + 1):
        try:
            response = await http.post(url, json=json_payload, headers=headers)
            if 200 <= response.status_code < 300:
                return True

            # 4xx (except 429) is typically a permanent payload/auth issue.
            if 400 <= response.status_code < 500 and response.status_code != 429:
                return False
        except Exception:
            pass

        if attempt < attempts:
            await asyncio.sleep(base_delay_seconds * (2 ** (attempt - 1)))

    return False


async def send_telegram_alert(
    session_id: str,
    history: list[dict[str, Any]],
    intel: dict[str, Any],
    scam_detected: bool,
    screenshot_path: str | None = None,
) -> bool:
    if not (TELEGRAM_ALERTS_ENABLED and TELEGRAM_BOT_TOKEN):
        return False

    link_reports = intel.get("linkReports", [])
    phishing_hits = [r for r in link_reports if r.get("verdict") == "PHISHING"]
    suspicious_hits = [r for r in link_reports if r.get("verdict") == "SUSPICIOUS"]
    upi_ids = intel.get("upiIds", [])
    phone_numbers = intel.get("phoneNumbers", [])
    phishing_links = intel.get("phishingLinks", [])

    detailed_text = "\n".join(
        [
            "🚨 HONEYPOT ALERT 🚨",
            "",
            f"Session ID: {session_id}",
            "",
            "UPI IDs:",
            f"{upi_ids}",
            "",
            "Phone Numbers:",
            f"{phone_numbers}",
            "",
            "Phishing Links:",
            f"{phishing_links}",
            "",
            "Total Messages:",
            f"{len(history)}",
        ]
    )

    summary_text = "\n".join(
        [
            "Honeypot Alert (Summary)",
            f"Session: {session_id}",
            f"Scam Detected: {scam_detected}",
            f"Messages: {len(history)}",
            "Intel Summary:",
            f"- Bank Accounts: {len(intel.get('bankAccounts', []))}",
            f"- UPI IDs: {len(upi_ids)}",
            f"- Phone Numbers: {len(phone_numbers)}",
            f"- Keywords: {', '.join(intel.get('suspiciousKeywords', [])[:8]) or '-'}",
            f"- Phishing Links: {len(phishing_hits)}",
            f"- Suspicious Links: {len(suspicious_hits)}",
        ]
    )

    first_sent = await send_telegram_message(detailed_text)
    second_sent = await send_telegram_message(summary_text)
    screenshot_sent = True
    if screenshot_path:
        screenshot_sent = await send_telegram_screenshot(screenshot_path)
    return (first_sent and second_sent) and screenshot_sent


async def send_callback(session_id: str, history: list[dict[str, Any]], intel: dict[str, Any], scam_detected: bool) -> None:
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": len(history),
        "extractedIntelligence": intel,
        "agentNotes": "Agent engaged scammer",
    }

    async with httpx.AsyncClient(timeout=8) as http:
        await post_with_retry(http, CALLBACK_URL, payload, attempts=2, base_delay_seconds=0.5)
    async with sessions_lock:
        session = sessions.get(session_id)
        should_send_screenshot = bool(session and not session.get("telegramScreenshotSent", False))
        screenshot_path = _select_first_screenshot(intel) if should_send_screenshot else None

    sent = await send_telegram_alert(
        session_id=session_id,
        history=history,
        intel=intel,
        scam_detected=scam_detected,
        screenshot_path=screenshot_path,
    )

    if sent and screenshot_path:
        async with sessions_lock:
            session = sessions.get(session_id)
            if session:
                session["telegramScreenshotSent"] = True


# ==========================================================
# MODELS
# ==========================================================


class Message(BaseModel):
    sender: str
    text: str
    timestamp: int | None = None


class RequestBody(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TelegramTestBody(BaseModel):
    sessionId: str | None = None
    message: str | None = None


class AnalyzeBody(BaseModel):
    message: str
    phone: str | None = None
    upi: str | None = None
    links: list[str] = Field(default_factory=list)


# ==========================================================
# DASHBOARD HELPERS
# ==========================================================


def build_overview() -> dict[str, Any]:
    total_sessions = len(sessions)
    total_messages = sum(len(sess["history"]) for sess in sessions.values())
    total_links = sum(len(sess["intel"].get("linkReports", [])) for sess in sessions.values())

    verdict_counter: Counter[str] = Counter()
    keyword_counter: Counter[str] = Counter()
    intel_totals = {"bankAccounts": 0, "upiIds": 0, "phoneNumbers": 0}
    recent_alerts: list[dict[str, Any]] = []
    avg_risk = 0.0
    risk_level_counter: Counter[str] = Counter()

    for sid, sess in sessions.items():
        avg_risk += float(sess.get("riskScore", 0))
        risk_level_counter[str(sess.get("riskLevel", "LOW")).upper()] += 1
        intel_totals["bankAccounts"] += len(sess["intel"].get("bankAccounts", []))
        intel_totals["upiIds"] += len(sess["intel"].get("upiIds", []))
        intel_totals["phoneNumbers"] += len(sess["intel"].get("phoneNumbers", []))

        for report in sess["intel"].get("linkReports", []):
            verdict = report.get("verdict", "UNKNOWN")
            verdict_counter[verdict] += 1
            if verdict in {"PHISHING", "SUSPICIOUS", "ERROR"}:
                recent_alerts.append(
                    {
                        "sessionId": sid,
                        "url": report.get("url", ""),
                        "title": report.get("title", ""),
                        "verdict": verdict,
                        "timestamp": report.get("timestamp", 0),
                    }
                )
        for keyword in sess["intel"].get("suspiciousKeywords", []):
            keyword_counter[keyword] += 1

    recent_alerts.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    avg_risk = round(avg_risk / total_sessions, 3) if total_sessions else 0.0

    threat_score = (
        (verdict_counter.get("PHISHING", 0) * 3)
        + (verdict_counter.get("SUSPICIOUS", 0) * 2)
        + (avg_risk * 10)
    )
    if threat_score >= 10:
        threat_level = "CRITICAL"
    elif threat_score >= 5:
        threat_level = "ELEVATED"
    elif threat_score > 0:
        threat_level = "GUARDED"
    else:
        threat_level = "LOW"

    return {
        "totalSessions": total_sessions,
        "totalMessages": total_messages,
        "totalScannedLinks": total_links,
        "phishingLinks": verdict_counter.get("PHISHING", 0),
        "suspiciousLinks": verdict_counter.get("SUSPICIOUS", 0),
        "errors": verdict_counter.get("ERROR", 0),
        "safeLinks": verdict_counter.get("SAFE", 0),
        "avgRiskScore": avg_risk,
        "threatLevel": threat_level,
        "threatScore": round(threat_score, 2),
        "criticalSessions": risk_level_counter.get("CRITICAL", 0),
        "highRiskSessions": risk_level_counter.get("HIGH", 0),
        "riskLevelBreakdown": {
            "LOW": risk_level_counter.get("LOW", 0),
            "MEDIUM": risk_level_counter.get("MEDIUM", 0),
            "HIGH": risk_level_counter.get("HIGH", 0),
            "CRITICAL": risk_level_counter.get("CRITICAL", 0),
        },
        "verdictBreakdown": {
            "SAFE": verdict_counter.get("SAFE", 0),
            "SUSPICIOUS": verdict_counter.get("SUSPICIOUS", 0),
            "PHISHING": verdict_counter.get("PHISHING", 0),
            "ERROR": verdict_counter.get("ERROR", 0),
        },
        "intelTotals": intel_totals,
        "recentAlerts": recent_alerts[:8],
        "topKeywords": [{"word": k, "count": v} for k, v in keyword_counter.most_common(5)],
        "updatedAt": int(time.time()),
    }


def list_sessions_summary() -> list[dict[str, Any]]:
    result = []
    for sid, sess in sessions.items():
        reports = sess["intel"].get("linkReports", [])
        latest_verdict = reports[-1].get("verdict") if reports else "-"
        result.append(
            {
                "sessionId": sid,
                "messages": len(sess["history"]),
                "riskScore": sess.get("riskScore", 0),
                "scamProbability": sess.get("scamProbability", 0.0),
                "riskLevel": sess.get("riskLevel", "LOW"),
                "latestVerdict": latest_verdict,
                "updatedAt": sess.get("updatedAt", 0),
            }
        )
    result.sort(key=lambda x: x["updatedAt"], reverse=True)
    return result


# ==========================================================
# MAIN ENDPOINT
# ==========================================================


@app.post("/honeypot")
async def honeypot(
    body: RequestBody,
    background_tasks: BackgroundTasks,
    x_api_key: str | None = Header(None),
) -> dict[str, Any]:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    async with sessions_lock:
        session = get_session(body.sessionId)
        session["history"].append(body.message.model_dump())
        session["updatedAt"] = int(time.time())
        session["intel"] = extract_intel(body.message.text, session["intel"])

    language = detect_language(body.message.text)
    phishing, reports = await scan_links(body.message.text, session["intel"], body.sessionId)
    score = rule_score(body.message.text)

    # Real-time production scoring engine integration.
    message_text = (body.message.text or "").strip()
    latest_phone = session["intel"].get("phoneNumbers", [])[-1] if session["intel"].get("phoneNumbers") else None
    latest_upi = session["intel"].get("upiIds", [])[-1] if session["intel"].get("upiIds") else None
    explicit_links = extract_urls(message_text)

    try:
        scoring_context = await asyncio.to_thread(load_scoring_context, latest_phone, latest_upi, message_text)
        scoring_result = calculate_scam_probability(
            message=message_text,
            phone=latest_phone,
            upi=latest_upi,
            links=explicit_links,
            context=scoring_context,
        )
        await asyncio.to_thread(
            save_analysis_event,
            message_text,
            latest_phone,
            latest_upi,
            scoring_result.get("links", []),
            float(scoring_result["scam_probability"]),
            str(scoring_result["risk_level"]),
        )
    except Exception:
        scoring_result = {
            "scam_probability": round(score * 100, 2),
            "risk_level": "LOW" if score < 0.35 else ("MEDIUM" if score < 0.65 else "HIGH"),
            "reasons": [],
        }

    async with sessions_lock:
        session["riskScore"] = max(session.get("riskScore", 0), float(scoring_result["scam_probability"]) / 100.0)
        session["scamProbability"] = float(scoring_result["scam_probability"])
        session["riskLevel"] = str(scoring_result["risk_level"])
        session["riskReasons"] = list(scoring_result.get("reasons", []))[:8]

    if phishing:
        reply = "Yeh link suspicious lag raha hai. Main ise nahi kholunga." if language == "hi" else "That link looks suspicious. I will not open it."
        background_tasks.add_task(send_callback, body.sessionId, session["history"], session["intel"], True)
    else:
        reply = generate_reply(session["history"], language)
        async with sessions_lock:
            session["history"].append({"sender": "honeypot", "text": reply, "timestamp": int(time.time())})
            session["updatedAt"] = int(time.time())
            if (score > 0.2 or float(scoring_result["scam_probability"]) >= 65.0) and len(session["history"]) >= 8:
                background_tasks.add_task(send_callback, body.sessionId, session["history"], session["intel"], True)

    await manager.broadcast(
        {
            "type": "session_update",
            "sessionId": body.sessionId,
            "overview": build_overview(),
            "session": {
                "sessionId": body.sessionId,
                "riskScore": session.get("riskScore", 0),
                "scamProbability": session.get("scamProbability", 0.0),
                "riskLevel": session.get("riskLevel", "LOW"),
                "riskReasons": session.get("riskReasons", []),
                "latestMessage": body.message.text,
                "latestReports": reports,
                "updatedAt": session.get("updatedAt", int(time.time())),
            },
        }
    )

    return {
        "status": "success",
        "reply": reply,
        "riskScore": score,
        "scam_probability": scoring_result["scam_probability"],
        "risk_level": scoring_result["risk_level"],
        "reasons": scoring_result.get("reasons", []),
    }


@app.post("/analyze")
async def analyze_scam_probability(body: AnalyzeBody) -> dict[str, Any]:
    # Validate required message input for scoring.
    message = (body.message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    try:
        # Load historical context from SQLite in a worker thread.
        context = await asyncio.to_thread(load_scoring_context, body.phone, body.upi, message)

        # Calculate weighted scam probability and risk reasons.
        result = calculate_scam_probability(
            message=message,
            phone=body.phone,
            upi=body.upi,
            links=body.links,
            context=context,
        )

        # Persist analysis outcome for repeat-detection and clustering features.
        await asyncio.to_thread(
            save_analysis_event,
            message,
            body.phone,
            body.upi,
            result.get("links", []),
            float(result["scam_probability"]),
            str(result["risk_level"]),
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to analyze scam probability")

    return {
        "scam_probability": result["scam_probability"],
        "risk_level": result["risk_level"],
        "reasons": result["reasons"],
    }


# ==========================================================
# DASHBOARD ROUTES
# ==========================================================


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request, error: str | None = None) -> HTMLResponse:
    if current_user_from_request(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(
        "auth.html",
        {
            "request": request,
            "mode": "signup",
            "error": error,
            "google_enabled": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        },
    )


@app.post("/signup")
async def signup_submit(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse:
    normalized_email = email.strip().lower()
    if len(password) < 8:
        return RedirectResponse(url="/signup?error=Password+must+be+at+least+8+characters", status_code=303)
    if get_user_by_email(normalized_email):
        return RedirectResponse(url="/signup?error=Email+already+exists", status_code=303)

    user = create_local_user(normalized_email, password, name.strip() or "User")
    response = RedirectResponse(url="/dashboard", status_code=303)
    issue_auth_cookie(response, user)
    return response


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str | None = None) -> HTMLResponse:
    if current_user_from_request(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(
        "auth.html",
        {
            "request": request,
            "mode": "login",
            "error": error,
            "google_enabled": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        },
    )


@app.post("/login")
async def login_submit(email: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    user = get_user_by_email(email)
    if not user or not user["password_salt"] or not user["password_hash"]:
        return RedirectResponse(url="/login?error=Invalid+email+or+password", status_code=303)
    if not verify_password(password, user["password_salt"], user["password_hash"]):
        return RedirectResponse(url="/login?error=Invalid+email+or+password", status_code=303)

    response = RedirectResponse(url="/dashboard", status_code=303)
    issue_auth_cookie(response, user)
    return response


@app.get("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse(url="/login", status_code=303)
    clear_auth_cookie(response)
    return response


@app.get("/auth/google/login")
async def google_login(request: Request) -> RedirectResponse:
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return RedirectResponse(url="/login?error=Google+OAuth+is+not+configured", status_code=303)
    redirect_uri = get_google_redirect_uri(request)
    params = urlencode(
        {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "prompt": "select_account",
        }
    )
    return RedirectResponse(url=f"https://accounts.google.com/o/oauth2/v2/auth?{params}", status_code=303)


@app.get("/auth/google/callback")
async def google_callback(request: Request, code: str | None = None) -> RedirectResponse:
    if not code:
        return RedirectResponse(url="/login?error=Google+authorization+failed", status_code=303)
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return RedirectResponse(url="/login?error=Google+OAuth+is+not+configured", status_code=303)
    redirect_uri = get_google_redirect_uri(request)

    try:
        async with httpx.AsyncClient(timeout=10) as http:
            token_res = await http.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                },
                auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
            )
            if token_res.status_code >= 400:
                token_error = token_res.text[:300]
                msg = quote_plus(f"Google token error {token_res.status_code}: {token_error}")
                return RedirectResponse(url=f"/login?error={msg}", status_code=303)
            access_token = token_res.json().get("access_token")
            if not access_token:
                raise ValueError("missing access token")

            profile_res = await http.get(
                "https://openidconnect.googleapis.com/v1/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            profile_res.raise_for_status()
            profile = profile_res.json()

        email = (profile.get("email") or "").strip().lower()
        sub = (profile.get("sub") or "").strip()
        name = (profile.get("name") or "Google User").strip()
        if not email or not sub:
            raise ValueError("missing google profile fields")
    except Exception as exc:
        msg = quote_plus(f"Google sign-in failed: {str(exc)[:140]}")
        return RedirectResponse(url=f"/login?error={msg}", status_code=303)

    user = upsert_google_user(email=email, display_name=name, google_sub=sub)
    response = RedirectResponse(url="/dashboard", status_code=303)
    issue_auth_cookie(response, user)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request) -> HTMLResponse:
    user = current_user_from_request(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request) -> HTMLResponse:
    user = current_user_from_request(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("chat.html", {"request": request, "user": user})


@app.get("/api/overview")
async def api_overview(request: Request) -> dict[str, Any]:
    if not current_user_from_request(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return build_overview()


@app.get("/api/sessions")
async def api_sessions(request: Request) -> dict[str, Any]:
    if not current_user_from_request(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"sessions": list_sessions_summary()}


@app.get("/api/sessions/{session_id}")
async def api_session_detail(session_id: str, request: Request) -> dict[str, Any]:
    if not current_user_from_request(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.post("/api/test-telegram")
async def api_test_telegram(body: TelegramTestBody, request: Request) -> dict[str, Any]:
    if not current_user_from_request(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not (TELEGRAM_ALERTS_ENABLED and TELEGRAM_BOT_TOKEN):
        raise HTTPException(status_code=400, detail="Telegram alerts are not configured")
    users = await asyncio.to_thread(load_users)
    if not users:
        raise HTTPException(status_code=400, detail="No Telegram users registered yet. Start the bot first.")

    now = int(time.time())
    sid = (body.sessionId or "").strip() or f"session-test-{now}"
    default_intel = {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": [],
        "linkReports": [],
    }

    session = sessions.get(sid)
    if session:
        history = session.get("history", [])
        intel = session.get("intel", default_intel)
    else:
        history = [{"sender": "scammer", "text": (body.message or "Test alert"), "timestamp": now}]
        intel = default_intel

    sent = await send_telegram_alert(sid, history, intel, scam_detected=True)
    if not sent:
        raise HTTPException(status_code=502, detail="Failed to send Telegram alert")
    return {"status": "success", "sessionId": sid}


@app.post("/telegram-webhook")
async def telegram_webhook(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    message = data.get("message") or data.get("edited_message") or {}
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    if chat_id is None:
        return {"status": "ignored", "reason": "no chat id"}

    try:
        added = await asyncio.to_thread(save_user, int(chat_id))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to save chat id")

    text = (message.get("text") or "").strip().lower()
    if TELEGRAM_ALERTS_ENABLED and TELEGRAM_BOT_TOKEN and text.startswith("/start"):
        welcome = (
            "✅ You are subscribed to Honeypot alerts.\n"
            "You will receive scam detection alerts automatically."
        )
        await _send_telegram_message_to_chat(int(chat_id), welcome)

    return {"status": "ok", "chatId": int(chat_id), "registered": added}


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket) -> None:
    if not current_user_from_ws(ws):
        await ws.close(code=4401)
        return
    await manager.connect(ws)
    try:
        await ws.send_text(json.dumps({"type": "init", "overview": build_overview(), "sessions": list_sessions_summary()}))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception:
        await manager.disconnect(ws)


# ==========================================================
# HEALTH
# ==========================================================


@app.get("/")
def home(request: Request) -> RedirectResponse:
    if current_user_from_request(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/login", status_code=303)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/debug/google")
def debug_google(request: Request) -> dict[str, Any]:
    cid = GOOGLE_CLIENT_ID or ""
    masked_cid = f"{cid[:12]}...{cid[-20:]}" if len(cid) > 36 else ("set" if cid else "missing")
    secret_set = bool(GOOGLE_CLIENT_SECRET)
    redirect_uri = get_google_redirect_uri(request)
    return {
        "googleClientId": masked_cid,
        "googleClientSecretSet": secret_set,
        "googleRedirectUri": redirect_uri,
        "host": request.headers.get("host"),
    }
