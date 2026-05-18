# FILE: utils.py
# -*- coding: utf-8 -*-

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import HTTPException, Request

from config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ADMIN_KEY,
    ADMIN_PHONES_ENV,
    BCRYPT_ROUNDS,
    JWT_SECRET,
    PASSWORD_PEPPER,
    REFRESH_TOKEN_EXPIRE_DAYS,
    ROLE_ADMIN,
    ROLE_USER,
    STATUS_ASSIGNED,
    STATUS_CANCELED,
    STATUS_FINISH,
    STATUS_IN_PROGRESS,
    STATUS_NEW,
    STATUS_WAITING,
)


# -------------------- Phone --------------------

def normalize_phone(p: str) -> str:
    raw = str(p or "").strip()
    if not raw:
        return ""
    cleaned = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
    if not cleaned:
        return ""
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]
    if cleaned.startswith("00"):
        cleaned = cleaned[2:]
    digits = "".join(ch for ch in cleaned if ch.isdigit())
    if not digits:
        return ""
    if digits.startswith("98") and len(digits) >= 12:
        tail10 = digits[-10:]
        if tail10.startswith("9"):
            return "0" + tail10
    if digits.startswith("9") and len(digits) == 10:
        return "0" + digits
    return digits


def parse_admin_phones(s: str) -> set[str]:
    out: set[str] = set()
    for part in (s or "").split(","):
        v = normalize_phone(part.strip())
        if v:
            out.add(v)
    return out


ADMIN_PHONES_SET: set[str] = parse_admin_phones(ADMIN_PHONES_ENV)


# -------------------- Time --------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso_utc(ts: str) -> datetime:
    try:
        raw = str(ts or "").strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            raise ValueError("timezone required")
        return dt.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail=f"invalid UTC datetime: {ts}")


def iso_utc(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


# -------------------- Status --------------------

def canon_status(raw: str) -> str:
    s = str(raw or "").strip().upper()
    mapping = {
        "NEW": STATUS_NEW,
        "WAITING": STATUS_WAITING,
        "PENDING": STATUS_WAITING,
        "ASSIGNED": STATUS_ASSIGNED,
        "IN_PROGRESS": STATUS_IN_PROGRESS,
        "STARTED": STATUS_IN_PROGRESS,
        "FINISH": STATUS_FINISH,
        "DONE": STATUS_FINISH,
        "COMPLETED": STATUS_FINISH,
        "FINISHED": STATUS_FINISH,
        "CANCELED": STATUS_CANCELED,
        "CANCELLED": STATUS_CANCELED,
    }
    return mapping.get(s, STATUS_NEW)


# -------------------- Security --------------------

def bcrypt_hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    mixed = (str(password) + PASSWORD_PEPPER).encode("utf-8")
    return bcrypt.hashpw(mixed, salt).decode("utf-8")


def verify_password_secure(password: str, stored_hash: str) -> bool:
    try:
        mixed = (str(password) + PASSWORD_PEPPER).encode("utf-8")
        return bcrypt.checkpw(mixed, str(stored_hash or "").encode("utf-8"))
    except Exception:
        return False


def create_access_token(subject_phone: str, role: str) -> str:
    now = utc_now()
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(subject_phone),
        "role": str(role),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def create_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256((str(token) + PASSWORD_PEPPER).encode("utf-8")).hexdigest()


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "access":
            return None
        return payload
    except Exception:
        return None


def extract_bearer_token(request: Request) -> Optional[str]:
    auth = (
        request.headers.get("authorization")
        or request.headers.get("Authorization")
        or ""
    )
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip()


def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return (request.client.host if request.client else None) or "unknown"


# -------------------- Auth guards --------------------

def require_user_phone(request: Request, expected_phone: str) -> str:
    token = extract_bearer_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="missing bearer token")
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="invalid token")
    if str(payload.get("role") or "") != ROLE_USER:
        raise HTTPException(status_code=403, detail="forbidden")
    sub = normalize_phone(str(payload.get("sub") or ""))
    exp = normalize_phone(expected_phone)
    if sub != exp:
        raise HTTPException(status_code=403, detail="forbidden")
    return sub


def require_admin(request: Request) -> str:
    token = extract_bearer_token(request)
    if token:
        payload = decode_access_token(token)
        sub = normalize_phone(str((payload or {}).get("sub") or ""))
        role = str((payload or {}).get("role") or "")
        if role == ROLE_ADMIN and sub and sub in ADMIN_PHONES_SET:
            return sub
    key = (
        request.headers.get("x-admin-key")
        or request.headers.get("X-Admin-Key")
        or ""
    ).strip()
    if key and key == ADMIN_KEY:
        if ADMIN_PHONES_SET:
            return sorted(ADMIN_PHONES_SET)[0]
        return ""
    raise HTTPException(status_code=401, detail="admin auth required")


def get_admin_provider_phone(request: Request) -> str:
    phone = require_admin(request)
    if phone:
        return phone
    if ADMIN_PHONES_SET:
        return sorted(ADMIN_PHONES_SET)[0]
    raise HTTPException(status_code=400, detail="admin provider phone not available")


# -------------------- Response --------------------

def unified_response(
    status: str, code: str, message: str, data: Optional[dict] = None
) -> dict:
    return {"status": status, "code": code, "message": message, "data": data or {}}


# -------------------- i18n --------------------

def pick_i18n(d: dict, lang: str) -> str:
    lang = (lang or "en").strip().lower()
    if not isinstance(d, dict):
        return ""
    if d.get(lang):
        return str(d[lang])
    if d.get("en"):
        return str(d["en"])
    for v in d.values():
        if v:
            return str(v)
    return ""
