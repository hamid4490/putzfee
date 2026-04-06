# FILE: server/main.py
# -*- coding: utf-8 -*-

import os
import re
import io
import json
import time
import base64
import hashlib
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Tuple, Any

import bcrypt
import jwt
import httpx

from dotenv import load_dotenv
from PIL import Image, ImageOps, UnidentifiedImageError

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import sqlalchemy
from databases import Database
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    ForeignKey, Index, select, func, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base

# -------------------- Config --------------------
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret").strip()
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper").strip()

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*").strip()

FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "").strip()
FCM_PROJECT_ID = os.getenv("FCM_PROJECT_ID", "").strip()

GOOGLE_APPLICATION_CREDENTIALS_JSON = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "").strip()
GOOGLE_APPLICATION_CREDENTIALS_JSON_B64 = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON_B64", "").strip()

ADMIN_KEY = os.getenv("ADMIN_KEY", "CHANGE_ME_ADMIN").strip()
ADMIN_PHONES_ENV = os.getenv("ADMIN_PHONES", "").strip()

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "600"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "1800"))

PUSH_BACKEND = os.getenv("PUSH_BACKEND", "fcm").strip().lower()
NTFY_BASE_URL = os.getenv("NTFY_BASE_URL", "https://ntfy.sh").strip()
NTFY_AUTH = os.getenv("NTFY_AUTH", "").strip()

MEDIA_DIR = os.getenv("MEDIA_DIR", "media").strip() or "media"
MEDIA_URL_PREFIX = os.getenv("MEDIA_URL_PREFIX", "/media").strip() or "/media"
MAX_IMAGE_BYTES = int(os.getenv("MAX_IMAGE_BYTES", "5000000"))
MEDIA_TARGET_WIDTH = int(os.getenv("MEDIA_TARGET_WIDTH", "1200"))
MEDIA_TARGET_HEIGHT = int(os.getenv("MEDIA_TARGET_HEIGHT", "1200"))
MEDIA_SAVE_FORMAT = os.getenv("MEDIA_SAVE_FORMAT", "JPEG").strip().upper()
MEDIA_JPEG_QUALITY = int(os.getenv("MEDIA_JPEG_QUALITY", "82"))
MEDIA_WEBP_QUALITY = int(os.getenv("MEDIA_WEBP_QUALITY", "82"))

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip()

ENABLE_SCHEMA_CREATE = os.getenv("ENABLE_SCHEMA_CREATE", "true").strip().lower() in ("1", "true", "yes", "on")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is empty")

os.makedirs(MEDIA_DIR, exist_ok=True)
os.makedirs(os.path.join(MEDIA_DIR, "users"), exist_ok=True)
os.makedirs(os.path.join(MEDIA_DIR, "promotions"), exist_ok=True)
os.makedirs(os.path.join(MEDIA_DIR, "services"), exist_ok=True)

# -------------------- Logger --------------------
logger = logging.getLogger("putz.push")
if not logger.handlers:
    h = logging.StreamHandler()
    fmt = logging.Formatter("[PUSH] %(levelname)s: %(message)s")
    h.setFormatter(fmt)
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# -------------------- Database --------------------
database = Database(DATABASE_URL)
Base = declarative_base()

# -------------------- Status constants --------------------
STATUS_NEW = "NEW"
STATUS_WAITING = "WAITING"
STATUS_ASSIGNED = "ASSIGNED"
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_FINISH = "FINISH"
STATUS_CANCELED = "CANCELED"

ACTIVE_ORDER_STATUSES = [
    STATUS_NEW,
    STATUS_WAITING,
    STATUS_ASSIGNED,
    STATUS_IN_PROGRESS,
]

FINAL_ORDER_STATUSES = [
    STATUS_FINISH,
    STATUS_CANCELED,
]

ROLE_USER = "user"
ROLE_ADMIN = "admin"

# -------------------- Helpers: phone --------------------
def _normalize_phone(p: str) -> str:
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

def _parse_admin_phones(s: str) -> set[str]:
    out: set[str] = set()
    for part in (s or "").split(","):
        vv = _normalize_phone(part.strip())
        if vv:
            out.add(vv)
    return out

ADMIN_PHONES_SET = _parse_admin_phones(ADMIN_PHONES_ENV)

# -------------------- Helpers: time --------------------
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

# -------------------- Helpers: status --------------------
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
        "PRICE_REJECTED": STATUS_CANCELED,
    }
    return mapping.get(s, STATUS_NEW)

# -------------------- Security helpers --------------------
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

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):
    return {"status": status, "code": code, "message": message, "data": (data or {})}

def extract_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip()

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "access":
            return None
        return payload
    except Exception:
        return None

def require_user_phone(request: Request, expected_phone: str) -> str:
    token = extract_bearer_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="missing bearer token")

    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="invalid token")

    if str(payload.get("role") or "") != ROLE_USER:
        raise HTTPException(status_code=403, detail="forbidden")

    sub = _normalize_phone(str(payload.get("sub") or ""))
    exp = _normalize_phone(expected_phone)
    if sub != exp:
        raise HTTPException(status_code=403, detail="forbidden")
    return sub

def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host or "unknown"

def require_admin(request: Request) -> str:
    token = extract_bearer_token(request)
    if token:
        payload = decode_access_token(token)
        sub = _normalize_phone(str((payload or {}).get("sub") or ""))
        role = str((payload or {}).get("role") or "")
        if role == ROLE_ADMIN and sub and sub in ADMIN_PHONES_SET:
            return sub

    key = (request.headers.get("x-admin-key") or request.headers.get("X-Admin-Key") or "").strip()
    if key and key == ADMIN_KEY:
        if ADMIN_PHONES_SET:
            return sorted(list(ADMIN_PHONES_SET))[0]
        return ""

    raise HTTPException(status_code=401, detail="admin auth required")

def get_admin_provider_phone(request: Request) -> str:
    phone = require_admin(request)
    if phone:
        return phone
    if ADMIN_PHONES_SET:
        return sorted(list(ADMIN_PHONES_SET))[0]
    raise HTTPException(status_code=400, detail="admin provider phone not available")

# -------------------- Media helpers --------------------
_ALLOWED_IMAGE_MIMES = {
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
    "image/heic",
    "image/heif",
}

def _safe_relpath(rel: str) -> str:
    rel = (rel or "").replace("\\", "/").strip()
    rel = re.sub(r"^\/*", "", rel)
    rel = re.sub(r"\.\.+", ".", rel)
    rel = rel.replace("../", "").replace("..\\", "")
    return rel

def _media_url(rel_path: str) -> Optional[str]:
    rel = _safe_relpath(rel_path)
    if not rel:
        return None
    path = f"{MEDIA_URL_PREFIX}/{rel}"
    if PUBLIC_BASE_URL:
        return f"{PUBLIC_BASE_URL.rstrip('/')}{path}"
    return path

def _target_ext_and_mime() -> Tuple[str, str]:
    fmt = MEDIA_SAVE_FORMAT.upper()
    if fmt == "PNG":
        return ".png", "image/png"
    if fmt == "WEBP":
        return ".webp", "image/webp"
    return ".jpg", "image/jpeg"

def _normalize_and_encode_image(data: bytes) -> Tuple[bytes, str]:
    try:
        with Image.open(io.BytesIO(data)) as im:
            im = ImageOps.exif_transpose(im)
            target_fmt = MEDIA_SAVE_FORMAT.upper()

            if target_fmt in ("JPEG", "JPG", "WEBP"):
                if im.mode != "RGB":
                    bg = Image.new("RGB", im.size, (255, 255, 255))
                    if "A" in im.getbands():
                        bg.paste(im, mask=im.getchannel("A"))
                    else:
                        bg.paste(im)
                    im = bg
            else:
                if im.mode not in ("RGBA", "RGB"):
                    im = im.convert("RGBA")

            im.thumbnail((MEDIA_TARGET_WIDTH, MEDIA_TARGET_HEIGHT), Image.Resampling.LANCZOS)

            out = io.BytesIO()
            if target_fmt == "PNG":
                im.save(out, format="PNG", optimize=True)
            elif target_fmt == "WEBP":
                im.save(out, format="WEBP", quality=MEDIA_WEBP_QUALITY, method=6)
            else:
                im.save(out, format="JPEG", quality=MEDIA_JPEG_QUALITY, optimize=True, progressive=True)

            encoded = out.getvalue()
            _, mime = _target_ext_and_mime()
            return encoded, mime
    except UnidentifiedImageError:
        raise HTTPException(status_code=400, detail="invalid image file")
    except Exception as e:
        logger.error(f"image processing failed: {e}")
        raise HTTPException(status_code=400, detail="image processing failed")

async def _save_image_upload(file: UploadFile, *, subdir: str) -> tuple[str, str, int]:
    if not file:
        raise HTTPException(status_code=400, detail="file required")

    raw = await file.read()
    if not raw or len(raw) < 16:
        raise HTTPException(status_code=400, detail="empty file")

    if len(raw) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail=f"image too large (max {MAX_IMAGE_BYTES} bytes)")

    ct = (file.content_type or "").strip().lower()
    if ct and ct not in _ALLOWED_IMAGE_MIMES:
        raise HTTPException(status_code=400, detail="unsupported image type")

    encoded, mime = _normalize_and_encode_image(raw)
    ext, _ = _target_ext_and_mime()

    name = f"{secrets.token_hex(16)}{ext}"
    subdir = _safe_relpath(subdir)
    abs_dir = os.path.join(MEDIA_DIR, subdir)
    os.makedirs(abs_dir, exist_ok=True)

    abs_path = os.path.join(abs_dir, name)
    with open(abs_path, "wb") as f:
        f.write(encoded)

    rel_path = _safe_relpath(f"{subdir}/{name}")
    return rel_path, mime, len(encoded)

def _delete_media_file(rel_path: str) -> None:
    try:
        rel = _safe_relpath(rel_path)
        if not rel:
            return
        abs_path = os.path.join(MEDIA_DIR, rel)
        if os.path.isfile(abs_path):
            os.remove(abs_path)
    except Exception:
        return

# -------------------- ORM models --------------------
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    address = Column(String, default="", nullable=False)
    name = Column(String, default="", nullable=False)
    car_list = Column(JSONB, default=list, nullable=False)
    photo_path = Column(String, default="", nullable=False)
    photo_mime = Column(String, default="", nullable=False)
    photo_updated_at = Column(DateTime(timezone=True), nullable=True)

class RequestTable(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String, index=True, nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    car_list = Column(JSONB, default=list, nullable=False)
    address = Column(String, default="", nullable=False)
    home_number = Column(String, default="", nullable=False)
    service_type = Column(String, index=True, nullable=False)
    service_types = Column(JSONB, default=list, nullable=False)
    preferred_slots = Column(JSONB, default=list, nullable=False)
    price = Column(Integer, default=0, nullable=False)
    request_datetime = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    finish_datetime = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, default=STATUS_NEW, index=True, nullable=False)
    driver_name = Column(String, default="", nullable=False)
    driver_phone = Column(String, default="", nullable=False)
    payment_type = Column(String, default="", nullable=False)
    service_place = Column(String, default="client", nullable=False)
    scheduled_start = Column(DateTime(timezone=True), nullable=True)
    execution_start = Column(DateTime(timezone=True), nullable=True)

class ReviewTable(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), unique=True, index=True, nullable=False)
    user_phone = Column(String, index=True, nullable=False)
    rating = Column(Integer, nullable=False)
    comment = Column(String, default="", nullable=False)
    status = Column(String, default="PENDING", index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    decided_by = Column(String, nullable=True)

class RefreshTokenTable(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), index=True, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)

class LoginAttemptTable(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, index=True, nullable=False)
    ip = Column(String, index=True, nullable=False)
    attempt_count = Column(Integer, default=0, nullable=False)
    window_start = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_attempt_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)

class ScheduleSlotTable(Base):
    __tablename__ = "schedule_slots"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True, nullable=False)
    provider_phone = Column(String, index=True, nullable=False)
    slot_start = Column(DateTime(timezone=True), index=True, nullable=False)
    status = Column(String, default="PROPOSED", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (
        Index("ix_schedule_slots_req_status", "request_id", "status"),
        Index("ix_schedule_slots_provider_slot", "provider_phone", "slot_start"),
    )

class AppointmentTable(Base):
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    provider_phone = Column(String, index=True, nullable=False)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True, nullable=False)
    start_time = Column(DateTime(timezone=True), index=True, nullable=False)
    end_time = Column(DateTime(timezone=True), index=True, nullable=False)
    status = Column(String, default="BOOKED", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),
    )

class NotificationTable(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String, index=True, nullable=False)
    title = Column(String, default="", nullable=False)
    body = Column(String, default="", nullable=False)
    data = Column(JSONB, default=dict, nullable=False)
    read = Column(Boolean, default=False, index=True, nullable=False)
    read_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    __table_args__ = (
        Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),
    )

class DeviceTokenTable(Base):
    __tablename__ = "device_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    role = Column(String, index=True, nullable=False)
    platform = Column(String, default="android", index=True, nullable=False)
    user_phone = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (Index("ix_tokens_role_platform", "role", "platform"),)

class PromotionTable(Base):
    __tablename__ = "promotions"
    id = Column(Integer, primary_key=True, index=True)
    active = Column(Boolean, default=True, index=True, nullable=False)
    sort_order = Column(Integer, default=0, index=True, nullable=False)
    title_i18n = Column(JSONB, default=dict, nullable=False)
    subtitle_i18n = Column(JSONB, default=dict, nullable=False)
    service_types = Column(JSONB, default=list, nullable=False)
    discount_amount = Column(Integer, default=0, nullable=False)
    image_path = Column(String, default="", nullable=False)
    image_mime = Column(String, default="", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

class ServicePriceTable(Base):
    __tablename__ = "service_prices"
    id = Column(Integer, primary_key=True, index=True)
    service_type = Column(String, unique=True, index=True, nullable=False)
    base_price = Column(Integer, default=0, nullable=False)
    active = Column(Boolean, default=True, index=True, nullable=False)
    sort_order = Column(Integer, default=0, index=True, nullable=False)
    name_i18n = Column(JSONB, default=dict, nullable=False)
    icon_path = Column(String, default="", nullable=False)
    icon_mime = Column(String, default="", nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

# -------------------- Pydantic models --------------------
class CarInfo(BaseModel):
    brand: str
    model: str
    plate: str

class Location(BaseModel):
    latitude: float
    longitude: float

class CarOrderItem(BaseModel):
    brand: str
    model: str
    plate: str
    wash_outside: bool = False
    wash_inside: bool = False
    polish: bool = False

class OrderRequest(BaseModel):
    user_phone: str
    location: Location
    car_list: List[CarOrderItem]
    address: str
    home_number: Optional[str] = ""
    service_type: str
    price: int = 0
    request_datetime: Optional[str] = None
    payment_type: str = "cash"
    service_place: str = "client"
    service_types: Optional[List[str]] = None
    preferred_slots: Optional[List[str]] = None

class CarListUpdateRequest(BaseModel):
    user_phone: str
    car_list: List[CarInfo]

class CancelRequest(BaseModel):
    user_phone: str
    service_type: str

class UserRegisterRequest(BaseModel):
    phone: str
    password: str
    address: Optional[str] = None

class UserLoginRequest(BaseModel):
    phone: str
    password: str

class UserProfileUpdate(BaseModel):
    phone: str
    name: str = ""
    address: str = ""

class ProposedSlotsRequest(BaseModel):
    slots: List[str]

class ConfirmSlotRequest(BaseModel):
    slot: str

class PriceBody(BaseModel):
    price: int
    agree: bool
    exec_time: Optional[str] = None

class PushRegister(BaseModel):
    role: str
    token: str
    platform: str = "android"
    user_phone: Optional[str] = None

class PushUnregister(BaseModel):
    token: str

class LogoutRequest(BaseModel):
    refresh_token: str
    device_token: Optional[str] = None

class RefreshAccessRequest(BaseModel):
    refresh_token: str

class ReviewSubmitBody(BaseModel):
    rating: int
    comment: Optional[str] = ""

class ReviewDecisionBody(BaseModel):
    approve: bool

class AdminLoginRequest(BaseModel):
    phone: str
    password: str

class NotificationReadBody(BaseModel):
    notification_id: Optional[int] = None
    order_id: Optional[int] = None

# -------------------- Push helpers --------------------
_FCM_OAUTH_TOKEN = ""
_FCM_OAUTH_EXP = 0.0

def _load_service_account() -> Optional[dict]:
    b64_val = GOOGLE_APPLICATION_CREDENTIALS_JSON_B64
    if b64_val:
        try:
            decoded_bytes = base64.b64decode(b64_val)
            decoded_str = decoded_bytes.decode("utf-8")
            data = json.loads(decoded_str)
            if "client_email" in data and "private_key" in data:
                pk = str(data.get("private_key", ""))
                if "\\n" in pk:
                    data["private_key"] = pk.replace("\\n", "\n")
                return data
        except Exception as e:
            logger.error(f"Failed to load SA from Base64: {e}")

    raw_val = GOOGLE_APPLICATION_CREDENTIALS_JSON
    if raw_val:
        try:
            data = json.loads(raw_val)
            if "client_email" in data and "private_key" in data:
                pk = str(data.get("private_key", ""))
                if "\\n" in pk:
                    data["private_key"] = pk.replace("\\n", "\n")
                return data
        except Exception as e:
            logger.error(f"Failed to load SA from JSON: {e}")
    return None

def _get_oauth2_token_for_fcm() -> Optional[str]:
    global _FCM_OAUTH_TOKEN, _FCM_OAUTH_EXP
    now = time.time()
    if _FCM_OAUTH_TOKEN and (_FCM_OAUTH_EXP - 60) > now:
        return _FCM_OAUTH_TOKEN

    sa = _load_service_account()
    if not sa:
        return None

    issued = int(now)
    expires = issued + 3600
    payload = {
        "iss": sa["client_email"],
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": issued,
        "exp": expires,
    }

    try:
        assertion = jwt.encode(payload, sa["private_key"], algorithm="RS256")
        resp = httpx.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
            timeout=10.0
        )
        if resp.status_code != 200:
            logger.error(f"OAuth token fetch failed: {resp.text}")
            return None

        data = resp.json()
        token = str(data.get("access_token", "")).strip()
        if token:
            _FCM_OAUTH_TOKEN = token
            _FCM_OAUTH_EXP = now + int(data.get("expires_in", 3600))
            return token
    except Exception as e:
        logger.error(f"OAuth exception: {e}")
    return None

def _to_fcm_data(data: dict) -> dict:
    out: Dict[str, str] = {}
    for k, v in (data or {}).items():
        if v is None:
            continue
        out[str(k)] = str(v)
    return out

def push_event_data(
    event: str,
    order_id: int,
    *,
    status: str = "",
    service_type: str = "",
    user_phone: str = "",
    order_ids: Optional[List[int]] = None,
    scheduled_start: Optional[datetime] = None,
    execution_start: Optional[datetime] = None,
    price: Optional[int] = None,
) -> dict:
    data = {
        "event": str(event or "").strip(),
        "order_id": str(int(order_id)),
    }
    if order_ids:
        data["order_ids"] = ",".join(str(int(x)) for x in order_ids if x is not None)
    if status:
        data["status"] = canon_status(status)
    if service_type:
        data["service_type"] = str(service_type or "").strip().lower()
    if user_phone:
        data["user_phone"] = _normalize_phone(user_phone)
    if scheduled_start is not None:
        data["scheduled_start"] = iso_utc(scheduled_start)
    if execution_start is not None:
        data["execution_start"] = iso_utc(execution_start)
    if price is not None:
        data["price"] = str(int(price))
    return data

async def _send_fcm_legacy(tokens: List[str], title: str, body: str, data: dict) -> None:
    if not tokens or not FCM_SERVER_KEY:
        return

    headers = {
        "Authorization": f"key={FCM_SERVER_KEY}",
        "Content-Type": "application/json",
    }
    merged = dict(data or {})
    merged["title"] = str(title or "")
    merged["body"] = str(body or "")
    payload = {
        "registration_ids": tokens,
        "priority": "high",
        "data": _to_fcm_data(merged),
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post("https://fcm.googleapis.com/fcm/send", headers=headers, json=payload)

    if resp.status_code != 200:
        logger.error(f"FCM legacy send failed HTTP_{resp.status_code} body={resp.text}")

async def _send_fcm_v1_single(token: str, title: str, body: str, data: dict) -> None:
    access = _get_oauth2_token_for_fcm()
    if not access or not FCM_PROJECT_ID:
        return

    headers = {
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json",
    }

    merged = dict(data or {})
    merged["title"] = str(title or "")
    merged["body"] = str(body or "")

    msg = {
        "message": {
            "token": str(token or "").strip(),
            "android": {"priority": "HIGH"},
            "data": _to_fcm_data(merged),
        }
    }

    url = f"https://fcm.googleapis.com/v1/projects/{FCM_PROJECT_ID}/messages:send"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(url, headers=headers, json=msg)

    if resp.status_code not in (200, 201):
        logger.error(f"FCM v1 send failed HTTP_{resp.status_code} body={resp.text}")

async def push_notify_tokens(tokens: List[str], title: str, body: str, data: dict) -> None:
    if not tokens:
        return

    if PUSH_BACKEND == "fcm":
        sa = _load_service_account()
        if FCM_PROJECT_ID and sa is not None:
            for t in tokens:
                await _send_fcm_v1_single(t, title, body, data)
            return
        if FCM_SERVER_KEY:
            await _send_fcm_legacy(tokens, title, body, data)
            return
        return

    if PUSH_BACKEND == "ntfy":
        base = (NTFY_BASE_URL or "https://ntfy.sh").strip()
        headers = {}
        if NTFY_AUTH:
            headers["Authorization"] = NTFY_AUTH
        async with httpx.AsyncClient(timeout=10.0) as client:
            for topic in tokens:
                await client.post(f"{base}/{topic}", headers=headers, data=body.encode("utf-8"))
        return

async def get_manager_tokens(target_phone: Optional[str] = None) -> List[str]:
    q = DeviceTokenTable.__table__.select().where(
        (DeviceTokenTable.role == "manager") &
        (DeviceTokenTable.platform == "android")
    )
    if target_phone:
        q = q.where(DeviceTokenTable.user_phone == _normalize_phone(target_phone))

    rows = await database.fetch_all(q)
    seen: set[str] = set()
    out: List[str] = []
    for r in rows:
        t = str(r["token"] or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out

async def get_user_tokens(phone: str) -> List[str]:
    norm = _normalize_phone(phone)
    q = DeviceTokenTable.__table__.select().where(
        (DeviceTokenTable.role.in_(["client", "user"])) &
        (DeviceTokenTable.platform == "android") &
        (DeviceTokenTable.user_phone == norm)
    )
    rows = await database.fetch_all(q)
    seen: set[str] = set()
    out: List[str] = []
    for r in rows:
        t = str(r["token"] or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out

async def notify_user(phone: str, title: str, body: str, data: Optional[dict] = None) -> None:
    norm = _normalize_phone(phone)
    await database.execute(
        NotificationTable.__table__.insert().values(
            user_phone=norm,
            title=str(title or ""),
            body=str(body or ""),
            data=(data or {}),
            read=False,
            created_at=utc_now(),
        )
    )

    tokens = await get_user_tokens(norm)
    if tokens:
        await push_notify_tokens(tokens, str(title or ""), str(body or ""), data or {})

async def notify_managers(title: str, body: str, data: Optional[dict] = None, target_phone: Optional[str] = None) -> None:
    tokens = await get_manager_tokens(target_phone=target_phone)
    if not tokens and target_phone:
        tokens = await get_manager_tokens(target_phone=None)
    if tokens:
        await push_notify_tokens(tokens, str(title or ""), str(body or ""), data or {})

# -------------------- App & CORS --------------------
app = FastAPI()
app.mount(MEDIA_URL_PREFIX, StaticFiles(directory=MEDIA_DIR), name="media")

allow_origins = ["*"] if ALLOW_ORIGINS_ENV == "*" else [
    o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Startup / Shutdown --------------------
@app.on_event("startup")
async def startup() -> None:
    if ENABLE_SCHEMA_CREATE:
        engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))
        Base.metadata.create_all(engine)
    await database.connect()

@app.on_event("shutdown")
async def shutdown() -> None:
    await database.disconnect()

# -------------------- Health --------------------
@app.get("/")
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}

@app.get("/verify_token")
def verify_token(request: Request):
    token = extract_bearer_token(request)
    if not token:
        return {"status": "ok", "valid": False, "role": None, "phone": None}

    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        return {"status": "ok", "valid": False, "role": None, "phone": None}

    return {
        "status": "ok",
        "valid": True,
        "role": str(payload.get("role") or ""),
        "phone": _normalize_phone(str(payload.get("sub") or "")),
    }

# -------------------- Auth --------------------
@app.post("/auth/refresh")
async def refresh_access(body: RefreshAccessRequest):
    raw = str(body.refresh_token or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="refresh_token required")

    token_hash = hash_refresh_token(raw)
    row = await database.fetch_one(
        RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash)
    )

    if not row or bool(row["revoked"]):
        raise HTTPException(status_code=401, detail="invalid/revoked refresh token")

    if row["expires_at"] <= utc_now():
        raise HTTPException(status_code=401, detail="refresh token expired")

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.id == int(row["user_id"]))
    )
    if not user:
        raise HTTPException(status_code=401, detail="user not found")

    phone = _normalize_phone(user["phone"])
    role = ROLE_ADMIN if phone in ADMIN_PHONES_SET else ROLE_USER
    access = create_access_token(phone, role)
    return unified_response("ok", "ACCESS_REFRESHED", "access token refreshed", {
        "access_token": access,
        "role": role,
        "phone": phone,
    })

@app.post("/logout")
async def logout_user(body: LogoutRequest):
    refresh_raw = str(body.refresh_token or "").strip()
    if not refresh_raw:
        raise HTTPException(status_code=400, detail="refresh_token required")

    token_hash = hash_refresh_token(refresh_raw)

    rt_row = await database.fetch_one(
        RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash)
    )

    await database.execute(
        RefreshTokenTable.__table__.update().where(
            RefreshTokenTable.token_hash == token_hash
        ).values(revoked=True)
    )

    device_token = str(body.device_token or "").strip()
    if device_token:
        await database.execute(
            DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == device_token)
        )
    elif rt_row:
        user = await database.fetch_one(
            UserTable.__table__.select().where(UserTable.id == int(rt_row["user_id"]))
        )
        if user:
            phone = _normalize_phone(user["phone"])
            await database.execute(
                DeviceTokenTable.__table__.delete().where(DeviceTokenTable.user_phone == phone)
            )

    return unified_response("ok", "LOGOUT", "logged out", {})

@app.post("/push/register")
async def register_push_token(body: PushRegister):
    now = utc_now()
    role = str(body.role or "").strip().lower()
    platform = str(body.platform or "android").strip().lower()
    token = str(body.token or "").strip()
    norm_phone = _normalize_phone(body.user_phone) if body.user_phone else None

    if not token:
        raise HTTPException(status_code=400, detail="token required")

    row = await database.fetch_one(
        DeviceTokenTable.__table__.select().where(DeviceTokenTable.token == token)
    )

    if row is None:
        await database.execute(
            DeviceTokenTable.__table__.insert().values(
                token=token,
                role=role,
                platform=platform,
                user_phone=norm_phone,
                created_at=now,
                updated_at=now,
            )
        )
    else:
        await database.execute(
            DeviceTokenTable.__table__.update().where(DeviceTokenTable.id == int(row["id"])).values(
                role=role,
                platform=platform,
                user_phone=norm_phone if norm_phone else row["user_phone"],
                updated_at=now,
            )
        )

    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": role})

@app.post("/push/unregister")
async def unregister_push_token(body: PushUnregister):
    token = str(body.token or "").strip()
    if token:
        await database.execute(
            DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == token)
        )
    return unified_response("ok", "TOKEN_UNREGISTERED", "unregistered", {})

@app.get("/users/exists")
async def user_exists(phone: str):
    norm = _normalize_phone(phone)
    if not norm:
        return unified_response("ok", "USER_NOT_FOUND", "check", {"exists": False})

    count = await database.fetch_val(
        select(func.count()).select_from(UserTable).where(UserTable.phone == norm)
    )
    exists = bool(count and int(count) > 0)
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "check", {
        "exists": exists
    })

@app.post("/register_user")
async def register_user(user: UserRegisterRequest):
    norm = _normalize_phone(user.phone)
    if not norm:
        raise HTTPException(status_code=400, detail="phone required")

    count = await database.fetch_val(
        select(func.count()).select_from(UserTable).where(UserTable.phone == norm)
    )
    if count and int(count) > 0:
        raise HTTPException(status_code=400, detail="User already exists")

    password_hash = bcrypt_hash_password(user.password)
    await database.execute(
        UserTable.__table__.insert().values(
            phone=norm,
            password_hash=password_hash,
            address=str(user.address or "").strip(),
            name="",
            car_list=[],
            photo_path="",
            photo_mime="",
            photo_updated_at=None,
        )
    )

    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": norm})

@app.post("/login")
async def login_user(user: UserLoginRequest, request: Request):
    now = utc_now()
    client_ip = get_client_ip(request)

    phone_norm = _normalize_phone(user.phone)
    if not phone_norm:
        raise HTTPException(status_code=400, detail="invalid phone")

    sel_att = LoginAttemptTable.__table__.select().where(
        (LoginAttemptTable.phone == phone_norm) &
        (LoginAttemptTable.ip == client_ip)
    )
    att = await database.fetch_one(sel_att)

    if not att:
        await database.execute(
            LoginAttemptTable.__table__.insert().values(
                phone=phone_norm,
                ip=client_ip,
                attempt_count=0,
                window_start=now,
                locked_until=None,
                last_attempt_at=now,
                created_at=now,
            )
        )
        att = await database.fetch_one(sel_att)

    locked_until = att["locked_until"]
    if locked_until and locked_until > now:
        remain = int((locked_until - now).total_seconds())
        raise HTTPException(
            status_code=429,
            detail={"code": "RATE_LIMITED", "lock_remaining": remain},
            headers={"Retry-After": str(remain)},
        )

    if (now - att["window_start"]).total_seconds() > LOGIN_WINDOW_SECONDS:
        await database.execute(
            LoginAttemptTable.__table__.update().where(
                LoginAttemptTable.id == int(att["id"])
            ).values(
                attempt_count=0,
                window_start=now,
                locked_until=None,
                last_attempt_at=now,
            )
        )
        att = await database.fetch_one(sel_att)

    db_user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == phone_norm)
    )
    if not db_user:
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})

    if not verify_password_secure(user.password, db_user["password_hash"]):
        cur = int(att["attempt_count"] or 0) + 1
        rem = max(0, LOGIN_MAX_ATTEMPTS - cur)

        if cur >= LOGIN_MAX_ATTEMPTS:
            lock_time = now + timedelta(seconds=LOGIN_LOCK_SECONDS)
            await database.execute(
                LoginAttemptTable.__table__.update().where(
                    LoginAttemptTable.id == int(att["id"])
                ).values(
                    attempt_count=cur,
                    locked_until=lock_time,
                    last_attempt_at=now,
                )
            )
            raise HTTPException(
                status_code=429,
                detail={"code": "RATE_LIMITED", "lock_remaining": LOGIN_LOCK_SECONDS},
                headers={"Retry-After": str(LOGIN_LOCK_SECONDS)},
            )

        await database.execute(
            LoginAttemptTable.__table__.update().where(
                LoginAttemptTable.id == int(att["id"])
            ).values(
                attempt_count=cur,
                last_attempt_at=now,
            )
        )
        raise HTTPException(
            status_code=401,
            detail={"code": "WRONG_PASSWORD", "remaining_attempts": int(rem)},
            headers={"X-Remaining-Attempts": str(int(rem))},
        )

    await database.execute(
        LoginAttemptTable.__table__.update().where(
            LoginAttemptTable.id == int(att["id"])
        ).values(
            attempt_count=0,
            window_start=now,
            locked_until=None,
            last_attempt_at=now,
        )
    )

    access = create_access_token(phone_norm, ROLE_USER)
    refresh = create_refresh_token()

    await database.execute(
        RefreshTokenTable.__table__.insert().values(
            user_id=int(db_user["id"]),
            token_hash=hash_refresh_token(refresh),
            expires_at=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            revoked=False,
            created_at=now,
        )
    )

    return {
        "status": "ok",
        "access_token": access,
        "refresh_token": refresh,
        "user": {
            "phone": phone_norm,
            "address": str(db_user["address"] or ""),
            "name": str(db_user["name"] or ""),
            "role": ROLE_USER,
        }
    }

@app.post("/admin/login")
async def admin_login(body: AdminLoginRequest, request: Request):
    now = utc_now()
    client_ip = get_client_ip(request)

    phone_norm = _normalize_phone(body.phone)
    if not phone_norm:
        raise HTTPException(status_code=400, detail="invalid phone")

    if phone_norm not in ADMIN_PHONES_SET:
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": 0})

    password_raw = str(body.password or "").strip()
    if not password_raw:
        raise HTTPException(status_code=400, detail="password required")

    sel_att = LoginAttemptTable.__table__.select().where(
        (LoginAttemptTable.phone == phone_norm) &
        (LoginAttemptTable.ip == client_ip)
    )
    att = await database.fetch_one(sel_att)

    if not att:
        await database.execute(
            LoginAttemptTable.__table__.insert().values(
                phone=phone_norm,
                ip=client_ip,
                attempt_count=0,
                window_start=now,
                locked_until=None,
                last_attempt_at=now,
                created_at=now,
            )
        )
        att = await database.fetch_one(sel_att)

    locked_until = att["locked_until"]
    if locked_until and locked_until > now:
        remain = int((locked_until - now).total_seconds())
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": remain})

    if (now - att["window_start"]).total_seconds() > LOGIN_WINDOW_SECONDS:
        await database.execute(
            LoginAttemptTable.__table__.update().where(
                LoginAttemptTable.id == int(att["id"])
            ).values(
                attempt_count=0,
                window_start=now,
                locked_until=None,
                last_attempt_at=now,
            )
        )
        att = await database.fetch_one(sel_att)

    db_user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == phone_norm)
    )

    if not db_user:
        password_hash = bcrypt_hash_password(password_raw)
        await database.execute(
            UserTable.__table__.insert().values(
                phone=phone_norm,
                password_hash=password_hash,
                address="",
                name="Manager",
                car_list=[],
                photo_path="",
                photo_mime="",
                photo_updated_at=None,
            )
        )
        db_user = await database.fetch_one(
            UserTable.__table__.select().where(UserTable.phone == phone_norm)
        )
    else:
        if not verify_password_secure(password_raw, db_user["password_hash"]):
            cur = int(att["attempt_count"] or 0) + 1
            rem = max(0, LOGIN_MAX_ATTEMPTS - cur)

            if cur >= LOGIN_MAX_ATTEMPTS:
                lock = now + timedelta(seconds=LOGIN_LOCK_SECONDS)
                await database.execute(
                    LoginAttemptTable.__table__.update().where(
                        LoginAttemptTable.id == int(att["id"])
                    ).values(
                        attempt_count=cur,
                        locked_until=lock,
                        last_attempt_at=now,
                    )
                )
                raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": LOGIN_LOCK_SECONDS})

            await database.execute(
                LoginAttemptTable.__table__.update().where(
                    LoginAttemptTable.id == int(att["id"])
                ).values(
                    attempt_count=cur,
                    last_attempt_at=now,
                )
            )
            raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": rem})

    await database.execute(
        LoginAttemptTable.__table__.update().where(
            LoginAttemptTable.id == int(att["id"])
        ).values(
            attempt_count=0,
            window_start=now,
            locked_until=None,
            last_attempt_at=now,
        )
    )

    access = create_access_token(phone_norm, ROLE_ADMIN)
    refresh = create_refresh_token()

    await database.execute(
        RefreshTokenTable.__table__.insert().values(
            user_id=int(db_user["id"]),
            token_hash=hash_refresh_token(refresh),
            expires_at=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            revoked=False,
            created_at=now,
        )
    )

    return {
        "status": "ok",
        "access_token": access,
        "refresh_token": refresh,
        "user": {
            "phone": phone_norm,
            "address": str(db_user["address"] or ""),
            "name": str(db_user["name"] or "Manager"),
            "role": ROLE_ADMIN,
        }
    }

# -------------------- User profile --------------------
@app.post("/user/{phone}/photo")
async def upload_user_photo(phone: str, request: Request, file: UploadFile = File(...)):
    norm = require_user_phone(request, phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    rel_path, mime, size = await _save_image_upload(file, subdir=f"users/{norm}")

    if str(user["photo_path"] or "").strip():
        _delete_media_file(str(user["photo_path"]))

    await database.execute(
        UserTable.__table__.update().where(UserTable.phone == norm).values(
            photo_path=rel_path,
            photo_mime=mime,
            photo_updated_at=utc_now(),
        )
    )

    return unified_response("ok", "PHOTO_SAVED", "saved", {
        "phone": norm,
        "photo_url": _media_url(rel_path),
        "bytes": int(size),
    })

@app.post("/user/profile")
async def update_profile(body: UserProfileUpdate, request: Request):
    norm = require_user_phone(request, body.phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await database.execute(
        UserTable.__table__.update().where(UserTable.phone == norm).values(
            name=str(body.name or "").strip(),
            address=str(body.address or "").strip(),
        )
    )

    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": norm})

@app.get("/user/profile/{phone}")
async def get_user_profile(phone: str, request: Request):
    norm = require_user_phone(request, phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return unified_response("ok", "PROFILE_FETCHED", "profile data", {
        "phone": norm,
        "name": str(user["name"] or ""),
        "address": str(user["address"] or ""),
        "photo_url": _media_url(str(user["photo_path"] or "")),
    })

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str, request: Request):
    norm = require_user_phone(request, user_phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return unified_response("ok", "USER_CARS", "cars list", {"items": user["car_list"] or []})

@app.post("/user_cars")
async def update_user_cars(body: CarListUpdateRequest, request: Request):
    norm = require_user_phone(request, body.user_phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    cars_payload = [c.model_dump() for c in (body.car_list or [])]
    await database.execute(
        UserTable.__table__.update().where(UserTable.phone == norm).values(car_list=cars_payload)
    )

    return unified_response("ok", "USER_CARS_UPDATED", "cars updated", {"count": len(cars_payload)})

# -------------------- Public helper --------------------
def _pick_i18n(d: dict, lang: str) -> str:
    lang = (lang or "en").strip().lower()
    if not isinstance(d, dict):
        return ""
    if d.get(lang):
        return str(d.get(lang) or "")
    if lang == "fa" and d.get("en"):
        return str(d.get("en") or "")
    if d.get("en"):
        return str(d.get("en") or "")
    for _, v in d.items():
        if v:
            return str(v)
    return ""

# -------------------- Orders --------------------
@app.post("/order")
async def create_order(order: OrderRequest, request: Request):
    norm = require_user_phone(request, order.user_phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    svc = str(order.service_type or "").strip().lower()
    if not svc:
        raise HTTPException(status_code=400, detail="service_type required")

    existing_active = await database.fetch_val(
        select(func.count()).select_from(RequestTable).where(
            (RequestTable.user_phone == norm) &
            (RequestTable.service_type == svc) &
            (RequestTable.status.in_(ACTIVE_ORDER_STATUSES))
        )
    )
    if int(existing_active or 0) > 0:
        raise HTTPException(
            status_code=409,
            detail={"code": "ACTIVE_ORDER_EXISTS", "message": "active order already exists for this service"}
        )

    svc_types = []
    if order.service_types:
        svc_types = [str(x or "").strip().lower() for x in order.service_types if str(x or "").strip()]
    if not svc_types:
        svc_types = [svc]

    pref = []
    if order.preferred_slots:
        uniq = []
        for x in order.preferred_slots:
            s = str(x or "").strip()
            if not s:
                continue
            if s not in uniq:
                uniq.append(s)
        pref = uniq[:3]

    req_dt = utc_now()
    if str(order.request_datetime or "").strip():
        req_dt = parse_iso_utc(str(order.request_datetime).strip())

    ins = RequestTable.__table__.insert().values(
        user_phone=norm,
        latitude=float(order.location.latitude),
        longitude=float(order.location.longitude),
        car_list=[car.model_dump() for car in (order.car_list or [])],
        address=str(order.address or "").strip(),
        home_number=str(order.home_number or "").strip(),
        service_type=svc,
        service_types=svc_types,
        preferred_slots=pref,
        price=int(order.price or 0),
        request_datetime=req_dt,
        status=STATUS_NEW,
        driver_name="",
        driver_phone="",
        finish_datetime=None,
        payment_type=str(order.payment_type or "").strip().lower(),
        service_place=str(order.service_place or "client").strip().lower(),
        scheduled_start=None,
        execution_start=None,
    ).returning(RequestTable.id)

    row = await database.fetch_one(ins)
    new_id = int(row["id"]) if row and row["id"] else 0

    try:
        await notify_managers(
            title="",
            body="",
            data=push_event_data(
                event="new_order",
                order_id=new_id,
                status=STATUS_NEW,
                service_type=svc,
                user_phone=norm,
            ),
        )
    except Exception as e:
        logger.error(f"notify_managers(create_order) failed: {e}")

    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})

@app.get("/user_orders/{phone}")
async def get_user_orders(phone: str, request: Request):
    norm = require_user_phone(request, phone)

    rows = await database.fetch_all(
        RequestTable.__table__
        .select()
        .where(RequestTable.user_phone == norm)
        .order_by(RequestTable.request_datetime.desc(), RequestTable.id.desc())
    )

    items = []
    for r in rows:
        items.append({
            "id": int(r["id"]),
            "user_phone": str(r["user_phone"] or ""),
            "address": str(r["address"] or ""),
            "home_number": str(r["home_number"] or ""),
            "service_type": str(r["service_type"] or ""),
            "service_types": r["service_types"] or [],
            "preferred_slots": r["preferred_slots"] or [],
            "price": int(r["price"] or 0),
            "status": canon_status(str(r["status"] or "")),
            "latitude": float(r["latitude"]) if r["latitude"] is not None else None,
            "longitude": float(r["longitude"]) if r["longitude"] is not None else None,
            "scheduled_start": iso_utc(r["scheduled_start"]),
            "execution_start": iso_utc(r["execution_start"]),
            "finish_datetime": iso_utc(r["finish_datetime"]),
            "driver_name": str(r["driver_name"] or ""),
            "driver_phone": str(r["driver_phone"] or ""),
            "request_datetime": iso_utc(r["request_datetime"]),
            "service_place": str(r["service_place"] or "client"),
            "payment_type": str(r["payment_type"] or ""),
        })

    return unified_response("ok", "USER_ORDERS", "orders", {"items": items})

@app.post("/cancel_order")
async def cancel_order(cancel: CancelRequest, request: Request):
    norm = require_user_phone(request, cancel.user_phone)
    service = str(cancel.service_type or "").strip().lower()
    if not service:
        raise HTTPException(status_code=400, detail="service_type required")

    upd = RequestTable.__table__.update().where(
        (RequestTable.user_phone == norm) &
        (RequestTable.service_type == service) &
        (RequestTable.status.in_([STATUS_NEW, STATUS_WAITING, STATUS_ASSIGNED])) &
        (RequestTable.execution_start.is_(None))
    ).values(
        status=STATUS_CANCELED,
        scheduled_start=None,
        execution_start=None,
        finish_datetime=None,
    ).returning(RequestTable.id, RequestTable.driver_phone)

    rows = await database.fetch_all(upd)
    if not rows:
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CANCEL", "message": "cannot cancel"})

    ids = [int(r["id"]) for r in rows]
    drivers = list({str(r["driver_phone"] or "").strip() for r in rows if str(r["driver_phone"] or "").strip()})

    await database.execute(
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id.in_(ids)) &
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
        ).values(status="REJECTED")
    )

    await database.execute(
        AppointmentTable.__table__.update().where(
            (AppointmentTable.request_id.in_(ids)) &
            (AppointmentTable.status == "BOOKED")
        ).values(status="CANCELED")
    )

    try:
        first_id = ids[0]
        payload = push_event_data(
            event="canceled_by_user",
            order_id=first_id,
            order_ids=ids,
            status=STATUS_CANCELED,
            service_type=service,
            user_phone=norm,
        )

        await notify_managers(title="", body="", data=payload)
        for dp in drivers:
            await notify_managers(title="", body="", data=payload, target_phone=_normalize_phone(dp))
    except Exception as e:
        logger.error(f"notify_managers(cancel_order) failed: {e}")

    return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(ids)})

@app.get("/admin/requests/active")
async def admin_active_requests(request: Request):
    require_admin(request)

    rows = await database.fetch_all(
        RequestTable.__table__
        .select()
        .where(RequestTable.status.in_(ACTIVE_ORDER_STATUSES))
        .order_by(RequestTable.request_datetime.desc(), RequestTable.id.desc())
    )

    items = []
    for r in rows:
        items.append({
            "id": int(r["id"]),
            "user_phone": str(r["user_phone"] or ""),
            "latitude": float(r["latitude"]) if r["latitude"] is not None else None,
            "longitude": float(r["longitude"]) if r["longitude"] is not None else None,
            "car_list": r["car_list"] or [],
            "address": str(r["address"] or ""),
            "home_number": str(r["home_number"] or ""),
            "service_type": str(r["service_type"] or ""),
            "price": int(r["price"] or 0),
            "request_datetime": iso_utc(r["request_datetime"]),
            "status": canon_status(str(r["status"] or "")),
            "driver_name": str(r["driver_name"] or ""),
            "driver_phone": str(r["driver_phone"] or ""),
            "finish_datetime": iso_utc(r["finish_datetime"]),
            "payment_type": str(r["payment_type"] or ""),
            "scheduled_start": iso_utc(r["scheduled_start"]),
            "service_place": str(r["service_place"] or "client"),
            "execution_start": iso_utc(r["execution_start"]),
            "service_types": r["service_types"] or [],
            "preferred_slots": r["preferred_slots"] or [],
        })

    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": items})

# -------------------- Scheduling --------------------
async def provider_is_free(
    provider_phone: str,
    start: datetime,
    end: datetime,
    exclude_order_id: Optional[int] = None
) -> bool:
    provider = _normalize_phone(provider_phone)
    if not provider:
        return False

    q_app = select(func.count()).select_from(AppointmentTable).where(
        (AppointmentTable.provider_phone == provider) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.end_time > start)
    )
    if exclude_order_id:
        q_app = q_app.where(AppointmentTable.request_id != int(exclude_order_id))
    if int(await database.fetch_val(q_app) or 0) != 0:
        return False

    q_slot = select(func.count()).select_from(ScheduleSlotTable).where(
        (ScheduleSlotTable.provider_phone == provider) &
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &
        (ScheduleSlotTable.slot_start < end) &
        (ScheduleSlotTable.slot_start > (start - timedelta(hours=1)))
    )
    if exclude_order_id:
        q_slot = q_slot.where(ScheduleSlotTable.request_id != int(exclude_order_id))
    if int(await database.fetch_val(q_slot) or 0) != 0:
        return False

    q_visit = select(func.count()).select_from(RequestTable).where(
        (RequestTable.driver_phone == provider) &
        (RequestTable.scheduled_start.is_not(None)) &
        (RequestTable.status.in_([STATUS_WAITING, STATUS_ASSIGNED, STATUS_IN_PROGRESS])) &
        (RequestTable.scheduled_start < end) &
        (RequestTable.scheduled_start > (start - timedelta(hours=1)))
    )
    if exclude_order_id:
        q_visit = q_visit.where(RequestTable.id != int(exclude_order_id))
    if int(await database.fetch_val(q_visit) or 0) != 0:
        return False

    q_exec = select(func.count()).select_from(RequestTable).where(
        (RequestTable.driver_phone == provider) &
        (RequestTable.execution_start.is_not(None)) &
        (RequestTable.status == STATUS_IN_PROGRESS) &
        (RequestTable.execution_start < end) &
        (RequestTable.execution_start > (start - timedelta(hours=1)))
    )
    if exclude_order_id:
        q_exec = q_exec.where(RequestTable.id != int(exclude_order_id))
    if int(await database.fetch_val(q_exec) or 0) != 0:
        return False

    return True

@app.get("/busy_slots")
async def get_busy_slots(request: Request, date: str, exclude_order_id: Optional[int] = None):
    require_admin(request)

    try:
        d = datetime.fromisoformat(str(date).strip()).date()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid date")

    provider = get_admin_provider_phone(request)
    start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=1)

    q_sched = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.slot_start >= start) &
        (ScheduleSlotTable.slot_start < end) &
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &
        (ScheduleSlotTable.provider_phone == provider)
    )
    if exclude_order_id:
        q_sched = q_sched.where(ScheduleSlotTable.request_id != int(exclude_order_id))

    q_app = AppointmentTable.__table__.select().where(
        (AppointmentTable.start_time >= start) &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.provider_phone == provider)
    )
    if exclude_order_id:
        q_app = q_app.where(AppointmentTable.request_id != int(exclude_order_id))

    q_visit = RequestTable.__table__.select().where(
        (RequestTable.scheduled_start >= start) &
        (RequestTable.scheduled_start < end) &
        (RequestTable.scheduled_start.is_not(None)) &
        (RequestTable.status.in_([STATUS_WAITING, STATUS_ASSIGNED, STATUS_IN_PROGRESS])) &
        (RequestTable.driver_phone == provider)
    )
    if exclude_order_id:
        q_visit = q_visit.where(RequestTable.id != int(exclude_order_id))

    q_exec = RequestTable.__table__.select().where(
        (RequestTable.execution_start >= start) &
        (RequestTable.execution_start < end) &
        (RequestTable.execution_start.is_not(None)) &
        (RequestTable.status == STATUS_IN_PROGRESS) &
        (RequestTable.driver_phone == provider)
    )
    if exclude_order_id:
        q_exec = q_exec.where(RequestTable.id != int(exclude_order_id))

    busy = set()
    for r in await database.fetch_all(q_sched):
        busy.add(r["slot_start"].astimezone(timezone.utc).isoformat())
    for r in await database.fetch_all(q_app):
        busy.add(r["start_time"].astimezone(timezone.utc).isoformat())
    for r in await database.fetch_all(q_visit):
        busy.add(r["scheduled_start"].astimezone(timezone.utc).isoformat())
    for r in await database.fetch_all(q_exec):
        busy.add(r["execution_start"].astimezone(timezone.utc).isoformat())

    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": sorted(list(busy))})

@app.post("/order/{order_id}/propose_slots")
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):
    require_admin(request)
    provider = get_admin_provider_phone(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    st = canon_status(str(req["status"] or ""))
    if st in FINAL_ORDER_STATUSES or req["execution_start"]:
        raise HTTPException(status_code=409, detail="cannot propose slots")

    slots = sorted(list(set(body.slots)))[:3]
    if not slots:
        raise HTTPException(status_code=400, detail="slots required")

    slot_dts = [parse_iso_utc(x) for x in slots]

    async with database.transaction():
        await database.execute(
            ScheduleSlotTable.__table__.update().where(
                (ScheduleSlotTable.request_id == int(order_id)) &
                (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
            ).values(status="REJECTED")
        )

        await database.execute(
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &
                (AppointmentTable.status == "BOOKED")
            ).values(status="CANCELED")
        )

        await database.execute(
            RequestTable.__table__.update().where(
                RequestTable.id == int(order_id)
            ).values(
                driver_phone=provider,
                status=STATUS_WAITING,
                scheduled_start=None,
            )
        )

        for dt in slot_dts:
            if not await provider_is_free(provider, dt, dt + timedelta(hours=1), exclude_order_id=int(order_id)):
                raise HTTPException(status_code=409, detail="slot overlap")

            await database.execute(
                ScheduleSlotTable.__table__.insert().values(
                    request_id=int(order_id),
                    provider_phone=provider,
                    slot_start=dt,
                    status="PROPOSED",
                    created_at=utc_now(),
                )
            )

    try:
        await notify_user(
            phone=str(req["user_phone"]),
            title="",
            body="",
            data=push_event_data(
                event="visit_slots_proposed",
                order_id=int(order_id),
                status=STATUS_WAITING,
                service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify_user(propose_slots) failed: {e}")

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {
        "accepted": [dt.isoformat() for dt in slot_dts]
    })

@app.get("/order/{order_id}/proposed_slots")
async def get_proposed_slots(order_id: int, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    require_user_phone(request, str(req["user_phone"]))

    rows = await database.fetch_all(
        ScheduleSlotTable.__table__.select().where(
            (ScheduleSlotTable.request_id == int(order_id)) &
            (ScheduleSlotTable.status == "PROPOSED")
        ).order_by(ScheduleSlotTable.slot_start.asc())
    )

    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {
        "items": [r["slot_start"].astimezone(timezone.utc).isoformat() for r in rows]
    })

@app.post("/order/{order_id}/confirm_slot")
async def confirm_slot(order_id: int, body: ConfirmSlotRequest, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    require_user_phone(request, str(req["user_phone"]))

    st = canon_status(str(req["status"] or ""))
    if req["execution_start"] or st not in [STATUS_WAITING, STATUS_ASSIGNED, STATUS_NEW]:
        raise HTTPException(status_code=409, detail="cannot confirm")

    slot_dt = parse_iso_utc(body.slot)
    end_dt = slot_dt + timedelta(hours=1)

    async with database.transaction():
        slot_row = await database.fetch_one(
            ScheduleSlotTable.__table__.select().where(
                (ScheduleSlotTable.request_id == int(order_id)) &
                (ScheduleSlotTable.slot_start == slot_dt) &
                (ScheduleSlotTable.status == "PROPOSED")
            )
        )
        if not slot_row:
            raise HTTPException(status_code=404, detail="slot not found")

        provider = _normalize_phone(str(slot_row["provider_phone"]))
        if not await provider_is_free(provider, slot_dt, end_dt, int(order_id)):
            raise HTTPException(status_code=409, detail="overlap")

        await database.execute(
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &
                (AppointmentTable.status == "BOOKED") &
                ((AppointmentTable.start_time != slot_dt) | (AppointmentTable.end_time != end_dt))
            ).values(status="CANCELED")
        )

        await database.execute(
            ScheduleSlotTable.__table__.update().where(
                (ScheduleSlotTable.request_id == int(order_id)) &
                (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &
                (ScheduleSlotTable.slot_start != slot_dt)
            ).values(status="REJECTED")
        )

        await database.execute(
            ScheduleSlotTable.__table__.update().where(
                (ScheduleSlotTable.request_id == int(order_id)) &
                (ScheduleSlotTable.slot_start == slot_dt)
            ).values(status="ACCEPTED")
        )

        exist = await database.fetch_one(
            AppointmentTable.__table__.select().where(
                (AppointmentTable.provider_phone == provider) &
                (AppointmentTable.start_time == slot_dt)
            ).limit(1)
        )

        if exist:
            if str(exist["status"]) == "BOOKED" and int(exist["request_id"]) != int(order_id):
                raise HTTPException(status_code=409, detail="conflict")

            await database.execute(
                AppointmentTable.__table__.update().where(
                    AppointmentTable.id == int(exist["id"])
                ).values(
                    request_id=int(order_id),
                    status="BOOKED"
                )
            )
        else:
            await database.execute(
                AppointmentTable.__table__.insert().values(
                    provider_phone=provider,
                    request_id=int(order_id),
                    start_time=slot_dt,
                    end_time=end_dt,
                    status="BOOKED",
                    created_at=utc_now(),
                )
            )

        await database.execute(
            RequestTable.__table__.update().where(
                RequestTable.id == int(order_id)
            ).values(
                scheduled_start=slot_dt,
                status=STATUS_ASSIGNED,
                driver_phone=provider,
            )
        )

    try:
        await notify_managers(
            title="",
            body="",
            data=push_event_data(
                event="visit_time_confirmed",
                order_id=int(order_id),
                status=STATUS_ASSIGNED,
                service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
                scheduled_start=slot_dt,
            ),
            target_phone=provider,
        )
    except Exception as e:
        logger.error(f"notify(confirm_slot) failed: {e}")

    return unified_response("ok", "SLOT_CONFIRMED", "confirmed", {
        "start": slot_dt.isoformat(),
        "end": end_dt.isoformat(),
    })

@app.post("/order/{order_id}/reject_all_and_cancel")
async def reject_all_and_cancel(order_id: int, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    require_user_phone(request, str(req["user_phone"]))

    st = canon_status(str(req["status"] or ""))
    if req["execution_start"] or st not in [STATUS_NEW, STATUS_WAITING, STATUS_ASSIGNED]:
        raise HTTPException(status_code=409, detail="cannot cancel")

    await database.execute(
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == int(order_id)) &
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
        ).values(status="REJECTED")
    )

    await database.execute(
        AppointmentTable.__table__.update().where(
            (AppointmentTable.request_id == int(order_id)) &
            (AppointmentTable.status == "BOOKED")
        ).values(status="CANCELED")
    )

    await database.execute(
        RequestTable.__table__.update().where(
            RequestTable.id == int(order_id)
        ).values(
            status=STATUS_CANCELED,
            scheduled_start=None,
            execution_start=None,
            finish_datetime=None,
        )
    )

    try:
        await notify_managers(
            title="",
            body="",
            data=push_event_data(
                event="canceled_by_user",
                order_id=int(order_id),
                status=STATUS_CANCELED,
                service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify_managers(reject_all) failed: {e}")

    return unified_response("ok", "ORDER_CANCELED", "canceled", {"order_id": int(order_id)})

@app.post("/admin/order/{order_id}/price")
async def admin_set_price(order_id: int, body: PriceBody, request: Request):
    require_admin(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    st = canon_status(str(req["status"] or ""))
    if st in FINAL_ORDER_STATUSES:
        raise HTTPException(status_code=409, detail="order already final")

    provider = _normalize_phone(str(req["driver_phone"] or "")) or get_admin_provider_phone(request)
    exec_dt = None
    new_status = STATUS_CANCELED if not body.agree else STATUS_IN_PROGRESS

    async with database.transaction():
        if body.agree:
            if st != STATUS_ASSIGNED:
                raise HTTPException(status_code=409, detail="price can be set only after time confirmation")

            if not body.exec_time:
                raise HTTPException(status_code=400, detail="exec_time required")

            exec_dt = parse_iso_utc(str(body.exec_time))
            end_dt = exec_dt + timedelta(hours=1)

            if not await provider_is_free(provider, exec_dt, end_dt, int(order_id)):
                raise HTTPException(status_code=409, detail="overlap")

            exist = await database.fetch_one(
                AppointmentTable.__table__.select().where(
                    (AppointmentTable.provider_phone == provider) &
                    (AppointmentTable.start_time == exec_dt)
                ).limit(1)
            )
            if exist:
                if str(exist["status"]) == "BOOKED" and int(exist["request_id"]) != int(order_id):
                    raise HTTPException(status_code=409, detail="conflict")
                await database.execute(
                    AppointmentTable.__table__.update().where(
                        AppointmentTable.id == int(exist["id"])
                    ).values(
                        request_id=int(order_id),
                        status="BOOKED"
                    )
                )
            else:
                await database.execute(
                    AppointmentTable.__table__.insert().values(
                        provider_phone=provider,
                        request_id=int(order_id),
                        start_time=exec_dt,
                        end_time=end_dt,
                        status="BOOKED",
                        created_at=utc_now(),
                    )
                )
        else:
            await database.execute(
                ScheduleSlotTable.__table__.update().where(
                    (ScheduleSlotTable.request_id == int(order_id)) &
                    (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
                ).values(status="REJECTED")
            )
            await database.execute(
                AppointmentTable.__table__.update().where(
                    (AppointmentTable.request_id == int(order_id)) &
                    (AppointmentTable.status == "BOOKED")
                ).values(status="CANCELED")
            )

        saved = await database.fetch_one(
            RequestTable.__table__.update().where(
                RequestTable.id == int(order_id)
            ).values(
                price=int(body.price),
                status=new_status,
                execution_start=exec_dt,
                driver_phone=provider,
            ).returning(
                RequestTable.id,
                RequestTable.price,
                RequestTable.status,
                RequestTable.execution_start
            )
        )

    try:
        if body.agree:
            await notify_user(
                phone=str(req["user_phone"]),
                title="",
                body="",
                data=push_event_data(
                    event="execution_set",
                    order_id=int(order_id),
                    status=STATUS_IN_PROGRESS,
                    service_type=str(req["service_type"] or ""),
                    user_phone=str(req["user_phone"] or ""),
                    scheduled_start=req["scheduled_start"],
                    execution_start=exec_dt,
                    price=int(body.price),
                ),
            )
        else:
            await notify_user(
                phone=str(req["user_phone"]),
                title="",
                body="",
                data=push_event_data(
                    event="canceled_by_manager",
                    order_id=int(order_id),
                    status=STATUS_CANCELED,
                    service_type=str(req["service_type"] or ""),
                    user_phone=str(req["user_phone"] or ""),
                    scheduled_start=req["scheduled_start"],
                    price=int(body.price),
                ),
            )
    except Exception as e:
        logger.error(f"notify_user(set_price) failed: {e}")

    return unified_response("ok", "PRICE_SET", "updated", {
        "order_id": int(saved["id"]),
        "price": int(saved["price"]),
        "status": canon_status(str(saved["status"] or "")),
        "execution_start": iso_utc(saved["execution_start"]),
    })

@app.post("/order/{order_id}/finish")
async def finish_order(order_id: int, request: Request):
    require_admin(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    if canon_status(str(req["status"] or "")) != STATUS_IN_PROGRESS:
        raise HTTPException(status_code=409, detail="only in-progress order can be finished")

    async with database.transaction():
        await database.execute(
            RequestTable.__table__.update().where(
                RequestTable.id == int(order_id)
            ).values(
                status=STATUS_FINISH,
                finish_datetime=utc_now(),
            )
        )

        await database.execute(
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &
                (AppointmentTable.status == "BOOKED")
            ).values(status="DONE")
        )

    try:
        await notify_user(
            phone=str(req["user_phone"]),
            title="",
            body="",
            data=push_event_data(
                event="finished",
                order_id=int(order_id),
                status=STATUS_FINISH,
                service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify(finish) failed: {e}")

    return unified_response("ok", "ORDER_FINISHED", "finished", {
        "order_id": int(order_id),
        "status": STATUS_FINISH,
    })

@app.post("/admin/order/{order_id}/cancel")
async def admin_cancel_order(order_id: int, request: Request):
    require_admin(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    if canon_status(str(req["status"] or "")) in FINAL_ORDER_STATUSES:
        raise HTTPException(status_code=409, detail="order already final")

    await database.execute(
        RequestTable.__table__.update().where(
            RequestTable.id == int(order_id)
        ).values(
            status=STATUS_CANCELED,
            scheduled_start=None,
            execution_start=None,
            finish_datetime=None,
        )
    )

    await database.execute(
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == int(order_id)) &
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
        ).values(status="REJECTED")
    )

    await database.execute(
        AppointmentTable.__table__.update().where(
            (AppointmentTable.request_id == int(order_id)) &
            (AppointmentTable.status == "BOOKED")
        ).values(status="CANCELED")
    )

    try:
        await notify_user(
            phone=str(req["user_phone"]),
            title="",
            body="",
            data=push_event_data(
                event="canceled_by_manager",
                order_id=int(order_id),
                status=STATUS_CANCELED,
                service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify(admin_cancel) failed: {e}")

    return unified_response("ok", "ORDER_CANCELED", "canceled by admin", {
        "order_id": int(order_id),
        "status": STATUS_CANCELED,
    })

# -------------------- Reviews --------------------
@app.get("/reviews")
async def public_reviews(limit: int = 50, offset: int = 0):
    reviews = ReviewTable.__table__
    users = UserTable.__table__

    q = (
        select(
            reviews.c.id,
            reviews.c.request_id,
            reviews.c.user_phone,
            reviews.c.rating,
            reviews.c.comment,
            reviews.c.created_at,
            users.c.name.label("user_name"),
        )
        .select_from(reviews.outerjoin(users, users.c.phone == reviews.c.user_phone))
        .where(reviews.c.status == "APPROVED")
        .order_by(func.random())
        .limit(limit)
        .offset(offset)
    )

    rows = await database.fetch_all(q)
    items = []
    for r in rows:
        items.append({
            "id": int(r["id"]),
            "request_id": int(r["request_id"]),
            "user_phone": str(r["user_phone"] or ""),
            "user_name": str(r["user_name"] or ""),
            "rating": int(r["rating"] or 0),
            "comment": str(r["comment"] or ""),
            "created_at": iso_utc(r["created_at"]),
        })

    avg_val = await database.fetch_val(
        select(func.avg(ReviewTable.__table__.c.rating)).where(ReviewTable.__table__.c.status == "APPROVED")
    )
    count_val = await database.fetch_val(
        select(func.count()).select_from(ReviewTable.__table__).where(ReviewTable.__table__.c.status == "APPROVED")
    )

    return unified_response("ok", "PUBLIC_REVIEWS", "reviews", {
        "items": items,
        "avg_rating": float(avg_val) if avg_val is not None else None,
        "count": int(count_val or 0),
    })

@app.post("/order/{order_id}/review/submit")
async def submit_review(order_id: int, body: ReviewSubmitBody, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    norm = require_user_phone(request, str(req["user_phone"]))
    if canon_status(str(req["status"] or "")) != STATUS_FINISH:
        raise HTTPException(status_code=409, detail="order is not finished")

    rating = int(body.rating or 0)
    if rating < 1 or rating > 5:
        raise HTTPException(status_code=400, detail="rating must be 1..5")

    comment = str(body.comment or "").strip()

    existing = await database.fetch_one(
        ReviewTable.__table__.select().where(ReviewTable.request_id == int(order_id))
    )

    if existing:
        await database.execute(
            ReviewTable.__table__.update().where(
                ReviewTable.request_id == int(order_id)
            ).values(
                rating=rating,
                comment=comment,
                status="PENDING",
                created_at=utc_now(),
                decided_at=None,
                decided_by=None,
            )
        )
    else:
        await database.execute(
            ReviewTable.__table__.insert().values(
                request_id=int(order_id),
                user_phone=norm,
                rating=rating,
                comment=comment,
                status="PENDING",
                created_at=utc_now(),
            )
        )

    return unified_response("ok", "REVIEW_SUBMITTED", "review submitted", {"order_id": int(order_id)})

@app.get("/admin/reviews")
async def admin_list_reviews(request: Request, status: str = "APPROVED", limit: int = 50, offset: int = 0):
    require_admin(request)

    st = str(status or "APPROVED").strip().upper()
    if st not in ["PENDING", "APPROVED", "REJECTED"]:
        st = "APPROVED"

    reviews = ReviewTable.__table__
    users = UserTable.__table__

    q = (
        select(
            reviews.c.id,
            reviews.c.request_id,
            reviews.c.user_phone,
            reviews.c.rating,
            reviews.c.comment,
            reviews.c.status,
            reviews.c.created_at,
            users.c.name.label("user_name"),
        )
        .select_from(reviews.outerjoin(users, users.c.phone == reviews.c.user_phone))
        .where(reviews.c.status == st)
        .order_by(reviews.c.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    rows = await database.fetch_all(q)
    items = []
    for r in rows:
        items.append({
            "id": int(r["id"]),
            "request_id": int(r["request_id"]),
            "user_phone": str(r["user_phone"] or ""),
            "user_name": str(r["user_name"] or ""),
            "rating": int(r["rating"] or 0),
            "comment": str(r["comment"] or ""),
            "status": str(r["status"] or ""),
            "created_at": iso_utc(r["created_at"]),
        })

    avg = None
    count = 0
    if st == "APPROVED":
        avg_val = await database.fetch_val(
            select(func.avg(ReviewTable.__table__.c.rating)).where(ReviewTable.__table__.c.status == "APPROVED")
        )
        count_val = await database.fetch_val(
            select(func.count()).select_from(ReviewTable.__table__).where(ReviewTable.__table__.c.status == "APPROVED")
        )
        avg = float(avg_val) if avg_val is not None else None
        count = int(count_val or 0)

    return unified_response("ok", "REVIEWS", "reviews", {
        "items": items,
        "avg_rating": avg,
        "count": count,
        "status": st,
    })

@app.post("/admin/reviews/{review_id}/decide")
async def admin_decide_review(review_id: int, body: ReviewDecisionBody, request: Request):
    require_admin(request)

    row = await database.fetch_one(
        ReviewTable.__table__.select().where(ReviewTable.id == int(review_id))
    )
    if not row:
        raise HTTPException(status_code=404, detail="review not found")

    new_status = "APPROVED" if body.approve else "REJECTED"
    decided_by = get_admin_provider_phone(request)

    await database.execute(
        ReviewTable.__table__.update().where(
            ReviewTable.id == int(review_id)
        ).values(
            status=new_status,
            decided_at=utc_now(),
            decided_by=decided_by,
        )
    )

    return unified_response("ok", "REVIEW_DECIDED", "decided", {
        "id": int(review_id),
        "status": new_status,
    })

# -------------------- Admin: services --------------------
@app.get("/admin/services")
async def admin_list_services(request: Request):
    require_admin(request)

    reviews = ReviewTable.__table__
    reqs = RequestTable.__table__

    q_rating = (
        select(
            reqs.c.service_type.label("service_type"),
            func.avg(reviews.c.rating).label("avg_rating"),
            func.count().label("review_count"),
        )
        .select_from(reviews.join(reqs, reqs.c.id == reviews.c.request_id))
        .where(reviews.c.status == "APPROVED")
        .group_by(reqs.c.service_type)
    )
    rr = await database.fetch_all(q_rating)
    rating_map = {
        str(x["service_type"] or "").strip().lower(): {
            "avg": float(x["avg_rating"]) if x["avg_rating"] is not None else None,
            "count": int(x["review_count"] or 0),
        }
        for x in rr
    }

    rows = await database.fetch_all(
        ServicePriceTable.__table__
        .select()
        .order_by(ServicePriceTable.sort_order.asc(), ServicePriceTable.service_type.asc())
    )

    items = []
    for r in rows:
        svc = str(r["service_type"] or "").strip().lower()
        rm = rating_map.get(svc, {"avg": None, "count": 0})
        items.append({
            "service_type": svc,
            "base_price": int(r["base_price"] or 0),
            "active": bool(r["active"]),
            "sort_order": int(r["sort_order"] or 0),
            "name_i18n": r["name_i18n"] or {},
            "icon_url": _media_url(str(r["icon_path"] or "")),
            "avg_rating": rm["avg"],
            "review_count": rm["count"],
            "updated_at": iso_utc(r["updated_at"]),
        })

    return unified_response("ok", "ADMIN_SERVICES", "services", {"items": items})

@app.post("/admin/services")
async def admin_upsert_service(
    request: Request,
    service_type: str = Form(...),
    base_price: int = Form(0),
    active: bool = Form(True),
    sort_order: int = Form(0),
    name_i18n: str = Form("{}"),
    icon: Optional[UploadFile] = File(None),
):
    require_admin(request)

    svc = str(service_type or "").strip().lower()
    if not svc:
        raise HTTPException(status_code=400, detail="service_type required")

    bp = int(base_price or 0)
    if bp < 0:
        raise HTTPException(status_code=400, detail="base_price must be >= 0")

    try:
        nm = json.loads(name_i18n or "{}")
        if not isinstance(nm, dict):
            raise ValueError()
    except Exception:
        raise HTTPException(status_code=400, detail="name_i18n must be JSON object string")

    existing = await database.fetch_one(
        ServicePriceTable.__table__.select().where(ServicePriceTable.service_type == svc)
    )

    patch = {
        "base_price": bp,
        "active": bool(active),
        "sort_order": int(sort_order),
        "name_i18n": nm,
        "updated_at": utc_now(),
    }

    if icon is not None:
        rel_path, mime, _ = await _save_image_upload(icon, subdir="services")
        if existing and str(existing["icon_path"] or "").strip():
            _delete_media_file(str(existing["icon_path"]))
        patch["icon_path"] = rel_path
        patch["icon_mime"] = mime

    if existing:
        await database.execute(
            ServicePriceTable.__table__.update().where(
                ServicePriceTable.service_type == svc
            ).values(**patch)
        )
    else:
        vals = dict(patch)
        vals["service_type"] = svc
        vals.setdefault("icon_path", "")
        vals.setdefault("icon_mime", "")
        await database.execute(ServicePriceTable.__table__.insert().values(**vals))

    return unified_response("ok", "SERVICE_UPSERTED", "saved", {"service_type": svc})

# -------------------- Admin: promotions --------------------
@app.get("/admin/promotions")
async def admin_list_promotions(request: Request):
    require_admin(request)

    rows = await database.fetch_all(
        PromotionTable.__table__.select().order_by(
            PromotionTable.sort_order.asc(),
            PromotionTable.id.asc()
        )
    )

    items = []
    for r in rows:
        items.append({
            "id": int(r["id"]),
            "active": bool(r["active"]),
            "sort_order": int(r["sort_order"] or 0),
            "title_i18n": r["title_i18n"] or {},
            "subtitle_i18n": r["subtitle_i18n"] or {},
            "service_types": r["service_types"] or [],
            "discount_amount": int(r["discount_amount"] or 0),
            "image_url": _media_url(str(r["image_path"] or "")),
            "created_at": iso_utc(r["created_at"]),
            "updated_at": iso_utc(r["updated_at"]),
        })

    return unified_response("ok", "PROMOTIONS", "promotions", {"items": items})

@app.post("/admin/promotions")
async def admin_create_promotion(
    request: Request,
    active: bool = Form(True),
    sort_order: int = Form(0),
    title_i18n: str = Form("{}"),
    subtitle_i18n: str = Form("{}"),
    service_types: str = Form(""),
    discount_amount: int = Form(0),
    image: Optional[UploadFile] = File(None),
):
    require_admin(request)

    try:
        title_map = json.loads(title_i18n or "{}")
        subtitle_map = json.loads(subtitle_i18n or "{}")
        if not isinstance(title_map, dict) or not isinstance(subtitle_map, dict):
            raise ValueError()
    except Exception:
        raise HTTPException(status_code=400, detail="title_i18n/subtitle_i18n must be JSON object strings")

    svc_list = [s.strip().lower() for s in service_types.split(",") if s.strip()]
    if int(discount_amount or 0) < 0:
        raise HTTPException(status_code=400, detail="discount_amount must be >= 0")

    rel_path = ""
    mime = ""
    if image is not None:
        rel_path, mime, _ = await _save_image_upload(image, subdir="promotions")

    now = utc_now()
    row = await database.fetch_one(
        PromotionTable.__table__.insert().values(
            active=bool(active),
            sort_order=int(sort_order),
            title_i18n=title_map,
            subtitle_i18n=subtitle_map,
            service_types=svc_list,
            discount_amount=int(discount_amount or 0),
            image_path=rel_path,
            image_mime=mime,
            created_at=now,
            updated_at=now,
        ).returning(PromotionTable.id)
    )

    return unified_response("ok", "PROMOTION_CREATED", "created", {
        "id": int(row["id"]) if row else 0
    })

@app.put("/admin/promotions/{promo_id}")
async def admin_update_promotion(
    promo_id: int,
    request: Request,
    active: Optional[bool] = Form(None),
    sort_order: Optional[int] = Form(None),
    title_i18n: Optional[str] = Form(None),
    subtitle_i18n: Optional[str] = Form(None),
    service_types: Optional[str] = Form(None),
    discount_amount: Optional[int] = Form(None),
    image: Optional[UploadFile] = File(None),
):
    require_admin(request)

    old = await database.fetch_one(
        PromotionTable.__table__.select().where(PromotionTable.id == int(promo_id))
    )
    if not old:
        raise HTTPException(status_code=404, detail="promotion not found")

    patch: dict = {"updated_at": utc_now()}

    if active is not None:
        patch["active"] = bool(active)
    if sort_order is not None:
        patch["sort_order"] = int(sort_order)
    if discount_amount is not None:
        da = int(discount_amount or 0)
        if da < 0:
            raise HTTPException(status_code=400, detail="discount_amount must be >= 0")
        patch["discount_amount"] = da

    if title_i18n is not None:
        try:
            v = json.loads(title_i18n or "{}")
            if not isinstance(v, dict):
                raise ValueError()
            patch["title_i18n"] = v
        except Exception:
            raise HTTPException(status_code=400, detail="title_i18n must be JSON object string")

    if subtitle_i18n is not None:
        try:
            v = json.loads(subtitle_i18n or "{}")
            if not isinstance(v, dict):
                raise ValueError()
            patch["subtitle_i18n"] = v
        except Exception:
            raise HTTPException(status_code=400, detail="subtitle_i18n must be JSON object string")

    if service_types is not None:
        patch["service_types"] = [s.strip().lower() for s in service_types.split(",") if s.strip()]

    if image is not None:
        rel_path, mime, _ = await _save_image_upload(image, subdir="promotions")
        if str(old["image_path"] or "").strip():
            _delete_media_file(str(old["image_path"]))
        patch["image_path"] = rel_path
        patch["image_mime"] = mime

    await database.execute(
        PromotionTable.__table__.update().where(
            PromotionTable.id == int(promo_id)
        ).values(**patch)
    )

    return unified_response("ok", "PROMOTION_UPDATED", "updated", {"id": int(promo_id)})

@app.delete("/admin/promotions/{promo_id}")
async def admin_delete_promotion(promo_id: int, request: Request):
    require_admin(request)

    old = await database.fetch_one(
        PromotionTable.__table__.select().where(PromotionTable.id == int(promo_id))
    )
    if not old:
        raise HTTPException(status_code=404, detail="promotion not found")

    if str(old["image_path"] or "").strip():
        _delete_media_file(str(old["image_path"]))

    await database.execute(
        PromotionTable.__table__.delete().where(PromotionTable.id == int(promo_id))
    )

    return unified_response("ok", "PROMOTION_DELETED", "deleted", {"id": int(promo_id)})

# -------------------- Notifications API --------------------
@app.get("/notifications/{phone}")
async def list_notifications(phone: str, request: Request, limit: int = Query(50, ge=1, le=200)):
    norm = require_user_phone(request, phone)

    rows = await database.fetch_all(
        NotificationTable.__table__.select().where(
            NotificationTable.user_phone == norm
        ).order_by(NotificationTable.created_at.desc()).limit(limit)
    )

    items: List[Dict[str, Any]] = []
    for r in rows:
        items.append({
            "id": int(r["id"]),
            "title": str(r["title"] or ""),
            "body": str(r["body"] or ""),
            "data": r["data"] or {},
            "read": bool(r["read"]),
            "read_at": iso_utc(r["read_at"]),
            "created_at": iso_utc(r["created_at"]),
        })

    return unified_response("ok", "NOTIFICATIONS", "notifications", {"items": items})

@app.post("/notifications/{phone}/read")
async def mark_notifications_read(phone: str, body: NotificationReadBody, request: Request):
    norm = require_user_phone(request, phone)

    cond = (NotificationTable.user_phone == norm) & (NotificationTable.read == False)

    if body.notification_id:
        cond = cond & (NotificationTable.id == int(body.notification_id))
    elif body.order_id:
        order_id_str = str(int(body.order_id))
        rows = await database.fetch_all(
            NotificationTable.__table__.select().where(
                (NotificationTable.user_phone == norm) &
                (NotificationTable.read == False)
            )
        )
        ids = []
        for r in rows:
            data = r["data"] or {}
            oid = str(data.get("order_id") or "").strip()
            if oid == order_id_str:
                ids.append(int(r["id"]))
        if ids:
            await database.execute(
                NotificationTable.__table__.update().where(
                    NotificationTable.id.in_(ids)
                ).values(read=True, read_at=utc_now())
            )
            return unified_response("ok", "NOTIFICATIONS_READ", "marked read", {"count": len(ids)})
        return unified_response("ok", "NOTIFICATIONS_READ", "marked read", {"count": 0})

    await database.execute(
        NotificationTable.__table__.update().where(cond).values(read=True, read_at=utc_now())
    )
    return unified_response("ok", "NOTIFICATIONS_READ", "marked read", {"count": 1 if body.notification_id else -1})

# -------------------- Public home --------------------
@app.get("/public/home")
async def public_home(lang: str = "en"):
    promo_rows = await database.fetch_all(
        PromotionTable.__table__.select().where(
            PromotionTable.active == True
        ).order_by(
            PromotionTable.sort_order.asc(),
            PromotionTable.id.asc()
        )
    )

    promo_items = []
    for r in promo_rows:
        promo_items.append({
            "id": int(r["id"]),
            "active": bool(r["active"]),
            "sort_order": int(r["sort_order"] or 0),
            "title_i18n": r["title_i18n"] or {},
            "subtitle_i18n": r["subtitle_i18n"] or {},
            "service_types": r["service_types"] or [],
            "discount_amount": int(r["discount_amount"] or 0),
            "image_url": _media_url(str(r["image_path"] or "")),
        })

    reviews = ReviewTable.__table__
    reqs = RequestTable.__table__
    q_rating = (
        select(
            reqs.c.service_type.label("service_type"),
            func.avg(reviews.c.rating).label("avg_rating"),
            func.count().label("count"),
        )
        .select_from(reviews.join(reqs, reqs.c.id == reviews.c.request_id))
        .where(reviews.c.status == "APPROVED")
        .group_by(reqs.c.service_type)
    )
    rr = await database.fetch_all(q_rating)

    rating_map = {
        str(x["service_type"] or "").strip().lower(): {
            "avg": float(x["avg_rating"]) if x["avg_rating"] is not None else None,
            "count": int(x["count"] or 0),
        }
        for x in rr
    }

    svc_rows = await database.fetch_all(
        ServicePriceTable.__table__.select().where(
            ServicePriceTable.active == True
        ).order_by(
            ServicePriceTable.sort_order.asc(),
            ServicePriceTable.service_type.asc()
        )
    )

    services = []
    service_map = {}
    for r in svc_rows:
        k = str(r["service_type"] or "").strip().lower()
        rm = rating_map.get(k, {"avg": None, "count": 0})

        item = {
            "service_type": k,
            "name": _pick_i18n(r["name_i18n"] or {}, lang),
            "icon_url": _media_url(str(r["icon_path"] or "")),
            "base_price": int(r["base_price"] or 0),
            "avg_rating": rm["avg"],
            "review_count": rm["count"],
            "sort_order": int(r["sort_order"] or 0),
        }
        services.append(item)
        service_map[k] = item

    promotion_details = []
    for p in promo_rows:
        svc_types = [str(x).strip().lower() for x in (p["service_types"] or []) if str(x).strip()]
        details = []
        discount_amount = int(p["discount_amount"] or 0)

        for svc in svc_types:
            if svc not in service_map:
                continue
            base_price = int(service_map[svc]["base_price"] or 0)
            final_price = max(0, base_price - discount_amount)
            details.append({
                "service_type": svc,
                "name": service_map[svc]["name"],
                "icon_url": service_map[svc]["icon_url"],
                "base_price": base_price,
                "discount_amount": discount_amount,
                "discounted_price": final_price,
                "avg_rating": service_map[svc]["avg_rating"],
            })

        promotion_details.append({
            "id": int(p["id"]),
            "title": _pick_i18n(p["title_i18n"] or {}, lang),
            "subtitle": _pick_i18n(p["subtitle_i18n"] or {}, lang),
            "discount_amount": discount_amount,
            "image_url": _media_url(str(p["image_path"] or "")),
            "services": details,
        })

    return unified_response("ok", "PUBLIC_HOME", "home", {
        "promotions": promo_items,
        "promotion_details": promotion_details,
        "services": services,
    })
