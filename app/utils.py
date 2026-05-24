"""Security primitives and small shared helpers.

This module contains:

* Password hashing (bcrypt + sha256 pre-hash to cover bcrypt's 72-byte limit)
* JWT access / refresh token helpers (no ADMIN_KEY backdoor)
* Phone normalisation and masking
* Brute-force throttling helpers operating on the ``login_attempts`` table
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets as _secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
from jose import JWTError, jwt

from .config import get_settings
from .database import database, login_attempts


# ---------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------
def _prehash(password: str) -> bytes:
    """Pre-hash with HMAC-SHA256(pepper, password) to remove bcrypt's 72-byte limit.

    The output is base64-encoded (no padding) which keeps it inside
    bcrypt's tolerated input range (60 bytes) regardless of password
    length, while also mixing in the static pepper.
    """
    s = get_settings()
    pepper = (s.PASSWORD_PEPPER or "").encode("utf-8")
    mac = hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(mac).rstrip(b"=")


def hash_password(password: str) -> str:
    s = get_settings()
    salt = bcrypt.gensalt(rounds=s.BCRYPT_ROUNDS)
    return bcrypt.hashpw(_prehash(password), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------
def create_access_token(user_id: int, is_admin: bool = False) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "is_admin": bool(is_admin),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=s.ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, s.JWT_SECRET, algorithm=s.JWT_ALGORITHM)


def create_refresh_token(user_id: int) -> tuple[str, datetime]:
    """Return ``(token, expires_at)``.

    The token is a 256-bit URL-safe random string. The caller persists its
    SHA-256 hash in ``refresh_tokens`` and returns the raw value to the
    client only once.
    """
    s = get_settings()
    raw = _secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + timedelta(days=s.REFRESH_TOKEN_EXPIRE_DAYS)
    return raw, expires_at


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def decode_token(token: str) -> Dict[str, Any]:
    s = get_settings()
    try:
        return jwt.decode(token, s.JWT_SECRET, algorithms=[s.JWT_ALGORITHM])
    except JWTError as exc:
        raise ValueError(str(exc)) from exc


# ---------------------------------------------------------------------
# Phones
# ---------------------------------------------------------------------
_PHONE_DIGITS = re.compile(r"\D+")


def normalize_phone(phone: str) -> str:
    """Strip everything except digits and a leading '+'."""
    if not phone:
        return ""
    p = phone.strip()
    plus = p.startswith("+")
    digits = _PHONE_DIGITS.sub("", p)
    return ("+" + digits) if plus else digits


def mask_phone(phone: str) -> str:
    """Mask all but the last 3 digits of a phone number for public display."""
    p = normalize_phone(phone)
    if len(p) <= 4:
        return "*" * len(p)
    return p[:2] + "*" * (len(p) - 5) + p[-3:]


# ---------------------------------------------------------------------
# Rate / lockout helpers
# ---------------------------------------------------------------------
async def record_login_attempt(phone: str, ip: Optional[str], success: bool) -> None:
    await database.execute(
        login_attempts.insert().values(
            phone=normalize_phone(phone), ip=ip, success=success
        )
    )


async def is_account_locked(phone: str) -> bool:
    """Return True if too many failed attempts within the lock window."""
    s = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=s.LOGIN_LOCK_SECONDS)
    row = await database.fetch_one(
        """
        SELECT COUNT(*) AS c
          FROM login_attempts
         WHERE phone = :phone
           AND success = false
           AND attempted_at >= :cutoff
        """,
        values={"phone": normalize_phone(phone), "cutoff": cutoff},
    )
    return bool(row and row["c"] >= s.LOGIN_MAX_ATTEMPTS)


def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
