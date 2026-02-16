from __future__ import annotations

import math
import re
from dataclasses import dataclass
from urllib.parse import urlparse

# Precompiled regex patterns for fast text risk analysis.
KEYWORD_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\botp\b",
        r"\bverify\b",
        r"\bk?yc\b",
        r"\bblocked\b",
        r"\baccount\b",
        r"\blogin\b",
        r"\bpassword\b",
        r"\bpin\b",
        r"\brefund\b",
        r"\bupdate now\b",
    ]
]

URGENCY_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"urgent",
        r"immediately",
        r"within\s*\d+\s*(minutes|min|hrs|hours)",
        r"act now",
        r"last warning",
    ]
]

PAYMENT_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"send\s+money",
        r"transfer\s+now",
        r"pay\s+now",
        r"upi",
        r"bank\s+account",
        r"deposit",
    ]
]

THREAT_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"account\s+will\s+be\s+blocked",
        r"legal\s+action",
        r"police\s+case",
        r"penalty",
        r"service\s+suspended",
    ]
]

LINK_REGEX = re.compile(r"http[s]?://\S+|www\.\S+", re.IGNORECASE)

# High-risk domains commonly abused in phishing campaigns.
SUSPICIOUS_DOMAIN_MARKERS = {
    "bit.ly",
    "tinyurl.com",
    "rb.gy",
    "t.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl",
    "grabify",
    "ngrok-free.app",
    "web.app",
}

# UPI handles frequently used for throwaway scam collection IDs.
SUSPICIOUS_UPI_HANDLES = {
    "ybl",
    "ibl",
    "axl",
    "okaxis",
    "okicici",
    "oksbi",
    "paytm",
    "airtel",
}


@dataclass(slots=True)
class ScoreBreakdown:
    """Container for per-signal risk scores and explanation reasons."""

    message_score: float
    link_score: float
    upi_score: float
    phone_score: float
    behavior_score: float
    reasons: list[str]


def _clamp(value: float, min_value: float = 0.0, max_value: float = 100.0) -> float:
    """Clamp score to the 0-100 probability range."""
    return max(min_value, min(max_value, value))


def extract_links(message: str) -> list[str]:
    """Extract URL-like tokens from message text."""
    if not message:
        return []
    return LINK_REGEX.findall(message)


def _message_score(message: str) -> tuple[float, list[str]]:
    """Score message text based on scam language, urgency, payment asks and threats."""
    if not message:
        return 0.0, []

    score = 0.0
    reasons: list[str] = []

    keyword_hits = sum(1 for p in KEYWORD_PATTERNS if p.search(message))
    if keyword_hits:
        score += min(22.0, keyword_hits * 4.5)
        reasons.append(f"Scam keywords detected ({keyword_hits})")

    urgency_hits = sum(1 for p in URGENCY_PATTERNS if p.search(message))
    if urgency_hits:
        score += min(18.0, urgency_hits * 6.0)
        reasons.append(f"Urgency language detected ({urgency_hits})")

    payment_hits = sum(1 for p in PAYMENT_PATTERNS if p.search(message))
    if payment_hits:
        score += min(20.0, payment_hits * 6.5)
        reasons.append(f"Payment request patterns detected ({payment_hits})")

    threat_hits = sum(1 for p in THREAT_PATTERNS if p.search(message))
    if threat_hits:
        score += min(20.0, threat_hits * 7.0)
        reasons.append(f"Threat/coercion patterns detected ({threat_hits})")

    return score, reasons


def _link_score(all_links: list[str]) -> tuple[float, list[str]]:
    """Score links using volume and suspicious-domain heuristics."""
    if not all_links:
        return 0.0, []

    score = min(10.0, len(all_links) * 3.0)
    reasons = [f"Message contains links ({len(all_links)})"]

    suspicious_count = 0
    for link in all_links:
        raw = link if link.lower().startswith("http") else f"https://{link}"
        try:
            domain = (urlparse(raw).netloc or "").lower()
        except Exception:
            domain = ""

        if any(marker in domain for marker in SUSPICIOUS_DOMAIN_MARKERS):
            suspicious_count += 1

        # Hyphen-heavy domains and long random hostnames are common in phishing.
        if domain.count("-") >= 2 or len(domain) > 32:
            suspicious_count += 1

    if suspicious_count:
        score += min(18.0, suspicious_count * 6.0)
        reasons.append(f"Suspicious link/domain signals detected ({suspicious_count})")

    return score, reasons


def _upi_score(upi: str | None, upi_attempts: int, upi_cluster_count: int) -> tuple[float, list[str]]:
    """Score UPI risk based on handle reputation and historical repetition."""
    if not upi:
        return 0.0, []

    score = 4.0
    reasons = ["UPI ID provided in conversation"]

    handle = ""
    if "@" in upi:
        handle = upi.split("@", 1)[1].strip().lower()

    if handle and handle in SUSPICIOUS_UPI_HANDLES:
        score += 10.0
        reasons.append(f"UPI handle is high-risk ({handle})")

    if upi_attempts > 0:
        repeat_bonus = min(16.0, 4.0 + math.log1p(upi_attempts) * 5.0)
        score += repeat_bonus
        reasons.append(f"UPI ID seen in previous attempts ({upi_attempts})")

    if upi_cluster_count >= 3:
        cluster_bonus = min(10.0, upi_cluster_count * 1.2)
        score += cluster_bonus
        reasons.append(f"UPI handle cluster activity detected ({upi_cluster_count})")

    return score, reasons


def _phone_score(phone: str | None, phone_attempts: int) -> tuple[float, list[str]]:
    """Score phone risk using repeat-attempt history."""
    if not phone:
        return 0.0, []

    score = 3.0
    reasons = ["Phone number provided in conversation"]

    if phone_attempts > 0:
        repeat_bonus = min(20.0, 5.0 + math.log1p(phone_attempts) * 6.0)
        score += repeat_bonus
        reasons.append(f"Phone number seen in previous attempts ({phone_attempts})")

    return score, reasons


def _extract_domain(url_or_host: str) -> str:
    """Normalize URL/host strings into a lowercase domain value."""
    if not url_or_host:
        return ""
    raw = url_or_host.strip().lower()
    if not raw:
        return ""
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"https://{raw}"
    try:
        return (urlparse(raw).netloc or "").lower()
    except Exception:
        return ""


def _extract_numeric_suffix(value: str) -> int | None:
    """Extract numeric suffix from usernames/domains for sequence detection."""
    m = re.search(r"(\d{1,6})$", value or "")
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _infrastructure_score(
    phone: str | None,
    upi: str | None,
    links: list[str],
    recent_upis: list[str],
    recent_phones: list[str],
    recent_domains: list[str],
    upi_cluster_count: int,
    phone_batch_count: int,
) -> tuple[float, list[str]]:
    """Score infrastructure correlation (payment, phone and domain clusters)."""
    score = 0.0
    reasons: list[str] = []

    if upi_cluster_count >= 5:
        score += min(10.0, 4.0 + upi_cluster_count * 0.9)
        reasons.append(f"UPI clustering pattern matched ({upi_cluster_count})")

    if phone_batch_count >= 4:
        score += min(10.0, 3.0 + phone_batch_count * 0.8)
        reasons.append(f"Phone batch pattern matched ({phone_batch_count})")

    # UPI infrastructure: same provider + sequential usernames.
    if upi and "@" in upi:
        current_user, current_handle = upi.lower().split("@", 1)
        same_handle_users = []
        for historic_upi in recent_upis:
            if "@" not in historic_upi:
                continue
            h_user, h_handle = historic_upi.lower().split("@", 1)
            if h_handle == current_handle:
                same_handle_users.append(h_user)

        if len(same_handle_users) >= 2:
            score += min(14.0, 4.0 + len(same_handle_users) * 1.8)
            reasons.append(f"Shared UPI provider infrastructure detected (@{current_handle})")

        current_suffix = _extract_numeric_suffix(current_user)
        if current_suffix is not None:
            seq_hits = 0
            for h_user in same_handle_users[:80]:
                h_suffix = _extract_numeric_suffix(h_user)
                if h_suffix is None:
                    continue
                if abs(h_suffix - current_suffix) <= 500:
                    seq_hits += 1
            if seq_hits >= 2:
                score += min(10.0, 3.0 + seq_hits * 1.5)
                reasons.append(f"Sequential UPI account pattern detected ({seq_hits})")

    # Phone infrastructure: nearby numbers suggest batch-issued SIM blocks.
    if phone:
        cur_digits = "".join(ch for ch in phone if ch.isdigit())
        if len(cur_digits) >= 10:
            current = int(cur_digits[-10:])
            near = 0
            for hist_phone in recent_phones[:200]:
                h_digits = "".join(ch for ch in str(hist_phone) if ch.isdigit())
                if len(h_digits) < 10:
                    continue
                candidate = int(h_digits[-10:])
                if abs(candidate - current) <= 5000:
                    near += 1
            if near >= 2:
                score += min(12.0, 4.0 + near * 1.6)
                reasons.append(f"Phone number range cluster detected ({near} nearby numbers)")

    # Domain infrastructure: suspicious TLD + shared base keyword + sequence.
    current_domains = [_extract_domain(link) for link in links]
    current_domains = [d for d in current_domains if d]
    hist_domains = [_extract_domain(d) for d in recent_domains[:260]]
    hist_domains = [d for d in hist_domains if d]
    if current_domains and hist_domains:
        suspicious_tld_hits = 0
        shared_base_hits = 0
        for dom in current_domains:
            if dom.endswith((".xyz", ".top", ".click", ".shop", ".info")):
                suspicious_tld_hits += 1
            base = re.sub(r"\d+", "", dom.split(".")[0])
            if not base:
                continue
            for hd in hist_domains:
                if base and base in hd:
                    shared_base_hits += 1
                    break

        if suspicious_tld_hits:
            score += min(8.0, suspicious_tld_hits * 4.0)
            reasons.append(f"Suspicious phishing TLD infrastructure detected ({suspicious_tld_hits})")
        if shared_base_hits:
            score += min(10.0, 3.0 + shared_base_hits * 2.0)
            reasons.append(f"Shared phishing domain family detected ({shared_base_hits})")

    return score, reasons


def _risk_level(score: float) -> str:
    """Map numeric scam probability to human-readable risk level."""
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def calculate_scam_probability(
    message: str,
    phone: str | None,
    upi: str | None,
    links: list[str] | None,
    context: dict,
) -> dict:
    """Calculate final scam probability score from all weighted feature groups."""
    explicit_links = links or []
    extracted_links = extract_links(message)

    # De-duplicate links while preserving order.
    merged_links: list[str] = []
    seen = set()
    for item in [*explicit_links, *extracted_links]:
        key = item.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        merged_links.append(key)

    msg_score, msg_reasons = _message_score(message)
    l_score, l_reasons = _link_score(merged_links)
    u_score, u_reasons = _upi_score(
        upi=upi,
        upi_attempts=int(context.get("upi_attempts", 0)),
        upi_cluster_count=int(context.get("upi_cluster_count", 0)),
    )
    p_score, p_reasons = _phone_score(
        phone=phone,
        phone_attempts=int(context.get("phone_attempts", 0)),
    )
    b_score, b_reasons = _infrastructure_score(
        phone=phone,
        upi=upi,
        links=merged_links,
        recent_upis=list(context.get("recent_upis", [])),
        recent_phones=list(context.get("recent_phones", [])),
        recent_domains=list(context.get("recent_domains", [])),
        upi_cluster_count=int(context.get("upi_cluster_count", 0)),
        phone_batch_count=int(context.get("phone_batch_count", 0)),
    )

    breakdown = ScoreBreakdown(
        message_score=msg_score,
        link_score=l_score,
        upi_score=u_score,
        phone_score=p_score,
        behavior_score=b_score,
        reasons=[*msg_reasons, *l_reasons, *u_reasons, *p_reasons, *b_reasons],
    )

    total = breakdown.message_score + breakdown.link_score + breakdown.upi_score + breakdown.phone_score + breakdown.behavior_score
    normalized = round(_clamp(total, 0.0, 100.0), 2)

    return {
        "scam_probability": normalized,
        "risk_level": _risk_level(normalized),
        "reasons": breakdown.reasons,
        "links": merged_links,
        "score_breakdown": {
            "message_score": round(breakdown.message_score, 2),
            "link_score": round(breakdown.link_score, 2),
            "upi_score": round(breakdown.upi_score, 2),
            "phone_score": round(breakdown.phone_score, 2),
            "behavior_score": round(breakdown.behavior_score, 2),
        },
    }
