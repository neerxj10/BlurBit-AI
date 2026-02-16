from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

# Dedicated SQLite database for scam analysis history.
SCAM_DB_PATH = Path(os.getenv("SCAM_DB_PATH", "scam_history.db"))
_db_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    """Create a SQLite connection with row access enabled."""
    conn = sqlite3.connect(SCAM_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_scam_db() -> None:
    """Initialize scam-analysis tables and indexes for fast lookups."""
    with _db_lock:
        with _connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scam_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    normalized_message TEXT NOT NULL,
                    phone TEXT,
                    upi TEXT,
                    upi_handle TEXT,
                    phone_prefix TEXT,
                    links_json TEXT NOT NULL,
                    scam_probability REAL NOT NULL,
                    risk_level TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_phone ON scam_events(phone)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_phone_prefix ON scam_events(phone_prefix)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_upi ON scam_events(upi)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_upi_handle ON scam_events(upi_handle)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_created ON scam_events(created_at DESC)")
            conn.commit()


def _normalize_text(text: str) -> str:
    """Normalize message text for fast similarity checks and storage."""
    lowered = (text or "").lower().strip()
    return " ".join(lowered.split())


def _extract_upi_handle(upi: str | None) -> str:
    """Extract UPI handle part after @ for clustering (e.g. ybl, okicici)."""
    if not upi or "@" not in upi:
        return ""
    return upi.split("@", 1)[1].strip().lower()


def _phone_prefix(phone: str | None) -> str:
    """Extract stable phone prefix for batch analysis across number ranges."""
    if not phone:
        return ""
    digits = "".join(ch for ch in phone if ch.isdigit())
    return digits[:6] if len(digits) >= 6 else digits


def save_analysis_event(
    message: str,
    phone: str | None,
    upi: str | None,
    links: list[str],
    scam_probability: float,
    risk_level: str,
) -> None:
    """Persist one analysis event for historical scoring and repeat detection."""
    now = int(time.time())
    normalized = _normalize_text(message)
    with _db_lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO scam_events(
                    created_at,
                    message,
                    normalized_message,
                    phone,
                    upi,
                    upi_handle,
                    phone_prefix,
                    links_json,
                    scam_probability,
                    risk_level
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    message,
                    normalized,
                    (phone or "").strip() or None,
                    (upi or "").strip().lower() or None,
                    _extract_upi_handle(upi),
                    _phone_prefix(phone),
                    json.dumps(links or []),
                    float(scam_probability),
                    risk_level,
                ),
            )
            conn.commit()


def load_scoring_context(phone: str | None, upi: str | None, message: str) -> dict[str, Any]:
    """Fetch compact historical context used by the scoring engine."""
    cleaned_phone = (phone or "").strip()
    cleaned_upi = (upi or "").strip().lower()
    upi_handle = _extract_upi_handle(cleaned_upi)
    prefix = _phone_prefix(cleaned_phone)

    with _db_lock:
        with _connect() as conn:
            phone_attempts = 0
            if cleaned_phone:
                row = conn.execute(
                    "SELECT COUNT(1) AS c FROM scam_events WHERE phone = ?",
                    (cleaned_phone,),
                ).fetchone()
                phone_attempts = int(row["c"] or 0)

            upi_attempts = 0
            if cleaned_upi:
                row = conn.execute(
                    "SELECT COUNT(1) AS c FROM scam_events WHERE upi = ?",
                    (cleaned_upi,),
                ).fetchone()
                upi_attempts = int(row["c"] or 0)

            upi_cluster_count = 0
            if upi_handle:
                row = conn.execute(
                    "SELECT COUNT(1) AS c FROM scam_events WHERE upi_handle = ?",
                    (upi_handle,),
                ).fetchone()
                upi_cluster_count = int(row["c"] or 0)

            phone_batch_count = 0
            if prefix:
                row = conn.execute(
                    "SELECT COUNT(1) AS c FROM scam_events WHERE phone_prefix = ?",
                    (prefix,),
                ).fetchone()
                phone_batch_count = int(row["c"] or 0)

            # Pull only recent normalized messages to keep scoring real-time.
            rows = conn.execute(
                "SELECT normalized_message FROM scam_events ORDER BY created_at DESC LIMIT 250"
            ).fetchall()
            recent_messages = [str(r["normalized_message"] or "") for r in rows]

            # Pull recent infrastructure fields for correlation checks.
            infra_rows = conn.execute(
                """
                SELECT phone, upi, links_json
                FROM scam_events
                ORDER BY created_at DESC
                LIMIT 350
                """
            ).fetchall()

            recent_phones: list[str] = []
            recent_upis: list[str] = []
            recent_domains: list[str] = []
            for row in infra_rows:
                phone_value = str(row["phone"] or "").strip()
                upi_value = str(row["upi"] or "").strip().lower()
                if phone_value:
                    recent_phones.append(phone_value)
                if upi_value:
                    recent_upis.append(upi_value)

                links_json = str(row["links_json"] or "[]")
                try:
                    links = json.loads(links_json)
                    if isinstance(links, list):
                        for item in links:
                            domain = str(item or "").strip().lower()
                            if domain:
                                recent_domains.append(domain)
                except Exception:
                    continue

    return {
        "phone_attempts": phone_attempts,
        "upi_attempts": upi_attempts,
        "upi_cluster_count": upi_cluster_count,
        "phone_batch_count": phone_batch_count,
        "recent_messages": recent_messages,
        "recent_phones": recent_phones,
        "recent_upis": recent_upis,
        "recent_domains": recent_domains,
        "current_normalized_message": _normalize_text(message),
    }
