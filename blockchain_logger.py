from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


# Append-only local file used to simulate immutable blockchain storage.
# In production, this can be replaced by on-chain transaction writes.
BLOCKCHAIN_STORAGE_FILE = Path("blockchain_storage.txt")


def _canonical_log_json(log: dict[str, Any]) -> str:
    """
    Convert log to deterministic JSON string.
    Deterministic encoding ensures the same log always produces the same hash.
    """
    return json.dumps(log, sort_keys=True, separators=(",", ":"))


def _sha256_hex(payload: str) -> str:
    """
    Generate SHA-256 digest for given text.
    SHA-256 creates a fixed-size fingerprint; any tiny data change yields a different hash.
    """
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_security_log(user: str, action: str, ip: str) -> tuple[dict[str, Any], str]:
    """
    Create a security log record and store its hash in append-only blockchain_storage.txt.

    The file simulates blockchain immutability:
    - each new hash is appended as a new line
    - existing history is never edited
    """
    try:
        log: dict[str, Any] = {
            "user": user,
            "action": action,
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        payload = _canonical_log_json(log)
        log_hash = _sha256_hex(payload)

        BLOCKCHAIN_STORAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with BLOCKCHAIN_STORAGE_FILE.open("a", encoding="utf-8") as f:
            # Append-only write simulates immutable blockchain ledger behavior.
            f.write(f"{log_hash}\n")

        return log, log_hash
    except OSError as exc:
        raise RuntimeError(f"Failed to store hash in blockchain storage: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Failed to create security log: {exc}") from exc


def verify_security_log(log: dict[str, Any], original_hash: str) -> bool:
    """
    Recompute log hash and compare with provided hash.
    Returns True if authentic (untampered), otherwise False.
    """
    try:
        recomputed = _sha256_hex(_canonical_log_json(log))
        return recomputed == original_hash.strip()
    except Exception:
        return False


class SecurityLogRequest(BaseModel):
    user: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    ip: str = Field(..., min_length=1)


class VerifyLogRequest(BaseModel):
    log: dict[str, Any]
    hash: str = Field(..., min_length=1)


router = APIRouter(tags=["Blockchain Logger"])


@router.post("/log-event")
def log_event(body: SecurityLogRequest) -> dict[str, Any]:
    """Create tamper-proof log and store hash in blockchain-style storage."""
    try:
        log, log_hash = create_security_log(body.user, body.action, body.ip)
        return {"log": log, "hash": log_hash, "message": "Stored in blockchain"}
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/verify-log")
def verify_log(body: VerifyLogRequest) -> dict[str, Any]:
    """Verify log integrity against provided SHA-256 hash."""
    is_valid = verify_security_log(body.log, body.hash)
    return {"verified": is_valid}
