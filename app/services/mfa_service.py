"""
TRAPWIRE — Multi-Factor Authentication (MFA) Service
Implements TOTP-based authentication compatible with Google Authenticator,
Microsoft Authenticator, and standard RFC 6238 apps.
Features:
- Cryptographic Base32 secret generation
- Inline vector SVG QR-code generation
- SHA-256 hashed single-use recovery codes
- Server-side rate-limiting and brute-force lockout protection
- Session validation gates
"""

import time
import secrets
import hashlib
import json
import io
from typing import Tuple, List, Dict, Any, Optional
import pyotp
import qrcode
import qrcode.image.svg

from app import database

# Security thresholds
MAX_MFA_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 60

# In-memory rate limiting tracker: { key: { "failures": int, "locked_until": float } }
MFA_RATE_LIMITS: Dict[str, Dict[str, Any]] = {}


def generate_secret() -> str:
    """Generates a secure random 32-character base32 secret."""
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, username: str = "admin", issuer: str = "TrapWire SOC") -> str:
    """Builds standard otpauth:// URI for authenticator app enrollment."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=f"{username}@trapwire.corp", issuer_name=issuer)


def generate_qr_svg(uri: str) -> str:
    """Renders crisp vector SVG QR code without external C/Pillow dependencies."""
    buf = io.BytesIO()
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage)
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def generate_recovery_codes(count: int = 8) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Generates single-use recovery codes (e.g. 'A7X9-K2M4')
    Returns:
      plain_codes: list of strings shown to the user ONCE upon enrollment
      stored_hashes: list of dicts with SHA-256 hashes stored in the DB
    """
    plain_codes = []
    stored_hashes = []
    for _ in range(count):
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        code = f"{part1}-{part2}"
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        plain_codes.append(code)
        stored_hashes.append({
            "hash": code_hash,
            "used": False,
            "used_at": None
        })
    return plain_codes, stored_hashes


def hash_code(code: str) -> str:
    """Normalizes and hashes recovery code."""
    clean = code.strip().upper().replace(" ", "")
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


def check_rate_limit(key: str) -> Tuple[bool, int, int]:
    """
    Checks rate limit for user/IP.
    Returns: (is_allowed, seconds_remaining, attempts_left)
    """
    now = time.time()
    record = MFA_RATE_LIMITS.get(key)
    if not record:
        return True, 0, MAX_MFA_ATTEMPTS

    # Check lockout
    locked_until = record.get("locked_until", 0)
    if now < locked_until:
        return False, int(locked_until - now) + 1, 0

    failures = record.get("failures", 0)
    attempts_left = max(0, MAX_MFA_ATTEMPTS - failures)
    return True, 0, attempts_left


def record_failure(key: str) -> Tuple[bool, int, int]:
    """
    Increments failure count and locks out if threshold reached.
    Returns: (is_locked, lockout_seconds, attempts_left)
    """
    now = time.time()
    record = MFA_RATE_LIMITS.setdefault(key, {"failures": 0, "locked_until": 0})
    record["failures"] = record.get("failures", 0) + 1

    if record["failures"] >= MAX_MFA_ATTEMPTS:
        record["locked_until"] = now + LOCKOUT_DURATION_SECONDS
        record["failures"] = 0  # reset for next cycle after lockout
        return True, LOCKOUT_DURATION_SECONDS, 0

    attempts_left = MAX_MFA_ATTEMPTS - record["failures"]
    return False, 0, attempts_left


def reset_rate_limit(key: str) -> None:
    """Clears rate-limit tracker upon successful verification."""
    if key in MFA_RATE_LIMITS:
        del MFA_RATE_LIMITS[key]


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verifies 6-digit TOTP code with standard drift allowance (+-30s)."""
    if not secret or not code:
        return False
    clean_code = code.strip().replace(" ", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(clean_code, valid_window=valid_window)
    except Exception:
        return False


def verify_recovery_code(username: str, code: str) -> bool:
    """Verifies and burns a single-use recovery code from database storage."""
    clean_code = code.strip().upper().replace(" ", "")
    if not clean_code:
        return False
    target_hash = hash_code(clean_code)
    return database.db_verify_and_use_recovery_code(username, target_hash)
