# FILE: server/main.py  # فایل=فایل اصلی سرور
# -*- coding: utf-8 -*-  # تنظیم=کدینگ UTF-8

import os  # ایمپورت=خواندن متغیرهای محیطی
import re  # ایمپورت=Regex
import json  # ایمپورت=JSON
import time  # ایمپورت=زمان یونیکس
import base64  # ایمپورت=Base64
import hashlib  # ایمپورت=هش
import secrets  # ایمپورت=تولید توکن امن
import logging  # ایمپورت=لاگ‌گیری
from datetime import datetime, timedelta, timezone  # ایمپورت=زمان/UTC
from typing import Optional, List, Dict  # ایمپورت=نوع‌ها

import bcrypt  # ایمپورت=هش امن رمز
import jwt  # ایمپورت=JWT

import httpx  # ایمپورت=HTTP Client

from dotenv import load_dotenv  # ایمپورت=خواندن env از فایل
from fastapi import FastAPI, HTTPException, Request  # ایمپورت=FastAPI
from fastapi.middleware.cors import CORSMiddleware  # ایمپورت=CORS
from pydantic import BaseModel  # ایمپورت=Pydantic

import sqlalchemy  # ایمپورت=SQLAlchemy Engine
from databases import Database  # ایمپورت=DB Async
from sqlalchemy import (  # ایمپورت=ستون‌ها و ابزارهای SQLAlchemy
    Column, Integer, String, Float, Boolean, DateTime,  # ستون‌ها=انواع
    ForeignKey, Index, select, func, text, UniqueConstraint  # ابزارها=کوئری/ایندکس
)  # پایان import sqlalchemy
from sqlalchemy.dialects.postgresql import JSONB  # ایمپورت=JSONB برای Postgres
from sqlalchemy.ext.declarative import declarative_base  # ایمپورت=Base ORM

# -------------------- Config --------------------  # بخش=پیکربندی
load_dotenv()  # اجرا=بارگذاری env از .env

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()  # مقدار=آدرس دیتابیس
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret").strip()  # مقدار=کلید JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper").strip()  # مقدار=pepper رمز
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # مقدار=انقضای access
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # مقدار=انقضای refresh
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # مقدار=دور bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*").strip()  # مقدار=CORS origins

# کلیدهای FCM
FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "").strip()  # مقدار=کلید Legacy (منسوخ)
FCM_PROJECT_ID = os.getenv("FCM_PROJECT_ID", "").strip()  # مقدار=ProjectId FCM v1

# متغیر JSON یا Base64 فایل فایربیس
GOOGLE_APPLICATION_CREDENTIALS_JSON = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "").strip()
GOOGLE_APPLICATION_CREDENTIALS_JSON_B64 = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON_B64", "").strip()

ADMIN_KEY = os.getenv("ADMIN_KEY", "CHANGE_ME_ADMIN").strip()  # مقدار=کلید ادمین (fallback)
ADMIN_PHONES_ENV = os.getenv("ADMIN_PHONES", "").strip()  # مقدار=شماره‌های مدیر

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "600"))  # مقدار=پنجره ورود
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # مقدار=حداکثر تلاش
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "1800"))  # مقدار=قفل موقت

PUSH_BACKEND = os.getenv("PUSH_BACKEND", "fcm").strip().lower()  # مقدار=نوع پوش (fcm/ntfy)
NTFY_BASE_URL = os.getenv("NTFY_BASE_URL", "https://ntfy.sh").strip()  # مقدار=آدرس ntfy
NTFY_AUTH = os.getenv("NTFY_AUTH", "").strip()  # مقدار=auth ntfy

# -------------------- Logger --------------------  # بخش=لاگر
logger = logging.getLogger("putz.push")  # logger=لاگر پوش
if not logger.handlers:  # شرط=نداشتن handler
    h = logging.StreamHandler()  # handler=خروجی کنسول
    fmt = logging.Formatter("[PUSH] %(levelname)s: %(message)s")  # fmt=فرمت لاگ
    h.setFormatter(fmt)  # set=فرمت
    logger.addHandler(h)  # add=handler
logger.setLevel(logging.INFO)  # level=سطح لاگ

# -------------------- Database --------------------  # بخش=دیتابیس
database = Database(DATABASE_URL)  # database=اتصال async
Base = declarative_base()  # Base=ریشه ORM

# -------------------- Helpers: phone --------------------  # بخش=نرمال‌سازی شماره
def _normalize_phone(p: str) -> str:  # تابع=نرمال‌سازی شماره به فرم یکتا
    raw = str(p or "").strip()  # raw=ورودی trim
    if not raw: return ""  # خالی

    cleaned = "".join(ch for ch in raw if ch.isdigit() or ch == "+")  # فقط رقم و +
    if not cleaned: return ""

    if cleaned.startswith("+"): cleaned = cleaned[1:]
    if cleaned.startswith("00"): cleaned = cleaned[2:]

    digits = "".join(ch for ch in cleaned if ch.isdigit())
    if not digits: return ""

    if digits.startswith("98") and len(digits) >= 12:
        tail10 = digits[-10:]
        if tail10.startswith("9"): return "0" + tail10

    if digits.startswith("9") and len(digits) == 10:
        return "0" + digits

    return digits

def _parse_admin_phones(s: str) -> set[str]:  # تابع=تبدیل env مدیران به set
    out: set[str] = set()
    for part in (s or "").split(","):
        vv = _normalize_phone(part.strip())
        if vv: out.add(vv)
    return out

ADMIN_PHONES_SET = _parse_admin_phones(ADMIN_PHONES_ENV)  # مقدار=set مدیران

# -------------------- Helpers: time (UTC only) --------------------  # بخش=زمان UTC
def parse_iso(ts: str) -> datetime:  # تابع=پارس ISO با timezone
    try:
        raw = str(ts or "").strip()
        if raw.endswith("Z"): raw = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None: raise ValueError("timezone required")
        return dt.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail=f"invalid UTC datetime: {ts}")

# -------------------- Security helpers --------------------  # بخش=امنیت
def bcrypt_hash_password(password: str) -> str:  # تابع=هش رمز
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    mixed = (str(password) + PASSWORD_PEPPER).encode("utf-8")
    return bcrypt.hashpw(mixed, salt).decode("utf-8")

def verify_password_secure(password: str, stored_hash: str) -> bool:  # تابع=بررسی رمز
    try:
        mixed = (str(password) + PASSWORD_PEPPER).encode("utf-8")
        return bcrypt.checkpw(mixed, str(stored_hash or "").encode("utf-8"))
    except Exception:
        return False

def create_access_token(subject_phone: str) -> str:  # تابع=ساخت access token
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(subject_phone), "type": "access", "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def create_refresh_token() -> str:  # تابع=ساخت refresh token خام
    return secrets.token_urlsafe(48)

def hash_refresh_token(token: str) -> str:  # تابع=هش رفرش توکن
    return hashlib.sha256((str(token) + PASSWORD_PEPPER).encode("utf-8")).hexdigest()

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # تابع=پاسخ واحد
    return {"status": status, "code": code, "message": message, "data": (data or {})}

def extract_bearer_token(request: Request) -> Optional[str]:  # تابع=استخراج Bearer
    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "): return None
    return auth.split(" ", 1)[1].strip()

def decode_access_token(token: str) -> Optional[dict]:  # تابع=دیکود JWT
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "access": return None
        return payload
    except Exception:
        return None

def require_user_phone(request: Request, expected_phone: str) -> str:  # تابع=احراز مالکیت شماره
    token = extract_bearer_token(request)
    if not token: raise HTTPException(status_code=401, detail="missing bearer token")
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"): raise HTTPException(status_code=401, detail="invalid token")
    sub = _normalize_phone(str(payload.get("sub") or ""))
    exp = _normalize_phone(expected_phone)
    if sub != exp: raise HTTPException(status_code=403, detail="forbidden")
    return sub

def get_client_ip(request: Request) -> str:  # تابع=آی‌پی کلاینت
    xff = request.headers.get("x-forwarded-for", "")
    if xff: return xff.split(",")[0].strip()
    return request.client.host or "unknown"

def require_admin(request: Request) -> None:  # تابع=احراز مدیر
    token = extract_bearer_token(request)
    if token:
        payload = decode_access_token(token)
        sub = _normalize_phone(str((payload or {}).get("sub") or ""))
        if sub and sub in ADMIN_PHONES_SET: return
    key = (request.headers.get("x-admin-key") or request.headers.get("X-Admin-Key") or "").strip()
    if key and key == ADMIN_KEY: return
    raise HTTPException(status_code=401, detail="admin auth required")

def get_admin_provider_phone(request: Request) -> str:  # تابع=شماره مدیر
    token = extract_bearer_token(request)
    if token:
        payload = decode_access_token(token)
        sub = _normalize_phone(str((payload or {}).get("sub") or ""))
        if sub and sub in ADMIN_PHONES_SET: return sub
    if ADMIN_PHONES_SET: return sorted(list(ADMIN_PHONES_SET))[0]
    raise HTTPException(status_code=400, detail="admin provider phone not available")

# -------------------- ORM models --------------------  # بخش=مدل‌های دیتابیس
class UserTable(Base):  # کلاس=جدول کاربران
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True)
    password_hash = Column(String)
    address = Column(String)
    name = Column(String, default="")
    car_list = Column(JSONB, default=list)

class DriverTable(Base):  # کلاس=جدول راننده (رزرو شده)
    __tablename__ = "drivers"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    photo_url = Column(String)
    id_card_number = Column(String)
    phone = Column(String, unique=True, index=True)
    phone_verified = Column(Boolean, default=False)
    is_online = Column(Boolean, default=False)
    status = Column(String, default="فعال")

class RequestTable(Base):  # کلاس=جدول سفارش‌ها
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String, index=True)
    latitude = Column(Float)
    longitude = Column(Float)
    car_list = Column(JSONB)
    address = Column(String)
    home_number = Column(String, default="")
    service_type = Column(String, index=True)
    price = Column(Integer)
    request_datetime = Column(String)
    status = Column(String)
    driver_name = Column(String)
    driver_phone = Column(String)
    finish_datetime = Column(String)
    payment_type = Column(String)
    scheduled_start = Column(DateTime(timezone=True), nullable=True)
    service_place = Column(String, default="client")
    execution_start = Column(DateTime(timezone=True), nullable=True)

class RefreshTokenTable(Base):  # کلاس=جدول رفرش توکن
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    token_hash = Column(String, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), index=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)

class LoginAttemptTable(Base):  # کلاس=جدول تلاش ورود
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, index=True)
    ip = Column(String, index=True)
    attempt_count = Column(Integer, default=0)
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)

class ScheduleSlotTable(Base):  # کلاس=جدول زمان‌های پیشنهادی
    __tablename__ = "schedule_slots"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)
    provider_phone = Column(String, index=True)
    slot_start = Column(DateTime(timezone=True), index=True)
    status = Column(String, default="PROPOSED")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)

class AppointmentTable(Base):  # کلاس=جدول رزرو قطعی
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    provider_phone = Column(String, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)
    start_time = Column(DateTime(timezone=True), index=True)
    end_time = Column(DateTime(timezone=True), index=True)
    status = Column(String, default="BOOKED")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),
        Index("ix_provider_time", "provider_phone", "start_time", "end_time")
    )

class NotificationTable(Base):  # کلاس=جدول اعلان‌ها
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String, index=True)
    title = Column(String)
    body = Column(String)
    data = Column(JSONB, default=dict)
    read = Column(Boolean, default=False, index=True)
    read_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    __table_args__ = (Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),)

class DeviceTokenTable(Base):  # کلاس=توکن دستگاه
    __tablename__ = "device_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    role = Column(String, index=True)
    platform = Column(String, default="android", index=True)
    user_phone = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_tokens_role_platform", "role", "platform"),)

# -------------------- Pydantic models --------------------  # بخش=مدل‌های ورودی API
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
    price: int
    request_datetime: str
    payment_type: str
    service_place: str

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

# -------------------- Push helpers (Modified) --------------------  # بخش=توابع ارسال پوش (اصلاح شده)

_FCM_OAUTH_TOKEN = ""  # کش توکن OAuth
_FCM_OAUTH_EXP = 0.0  # انقضای توکن OAuth

def _load_service_account() -> Optional[dict]:  # تابع=لود فایل کردینشال (اولویت با Base64)
    # 1. تلاش اول: Base64 (مطمئن‌ترین روش در Render)
    b64_val = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON_B64", "").strip()
    if b64_val:
        try:
            # دیکود کردن Base64 به رشته
            decoded_bytes = base64.b64decode(b64_val)
            decoded_str = decoded_bytes.decode("utf-8")
            data = json.loads(decoded_str)
            # چک کردن فیلدها و اصلاح کاراکتر خط جدید
            if "client_email" in data and "private_key" in data:
                pk = str(data.get("private_key", ""))
                if "\\n" in pk:
                    data["private_key"] = pk.replace("\\n", "\n")
                logger.info("Service Account loaded successfully from Base64")
                return data
            else:
                logger.error("Service Account loaded from Base64 but missing keys")
        except Exception as e:
            logger.error(f"Failed to load Service Account from Base64: {e}")

    # 2. تلاش دوم: متغیر متنی JSON (اگر Base64 نبود)
    raw_val = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "").strip()
    if not raw_val:
        raw_val = os.getenv("GOOGLE_APPLICATIONS_CREDENTIALS_JSON", "").strip() # نام قدیمی

    if raw_val:
        try:
            data = json.loads(raw_val)
            if "client_email" in data and "private_key" in data:
                pk = str(data.get("private_key", ""))
                if "\\n" in pk:
                    data["private_key"] = pk.replace("\\n", "\n")
                logger.info("Service Account loaded successfully from JSON Raw")
                return data
            else:
                logger.error("Service Account loaded from JSON Raw but missing keys")
        except Exception as e:
            logger.error(f"Failed to load Service Account from JSON Raw: {e}")

    logger.error("No valid Service Account found. Check env vars.")
    return None

def _get_oauth2_token_for_fcm() -> Optional[str]:  # تابع=گرفتن OAuth Token
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
        "exp": expires
    }
    
    try:
        assertion = jwt.encode(payload, sa["private_key"], algorithm="RS256")
        resp = httpx.post(
            "https://oauth2.googleapis.com/token",
            data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion},
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

def _to_fcm_data(data: dict) -> dict:  # تابع=تبدیل دیتا به رشته
    out: Dict[str, str] = {}
    for k, v in (data or {}).items():
        if v is None: continue
        out[str(k)] = str(v)
    return out

def order_push_data(msg_type: str, order_id: int, status: str, service_type: str = "", scheduled_start: Optional[datetime] = None, execution_start: Optional[datetime] = None, price: Optional[int] = None) -> dict:  # تابع=ساخت payload
    data = {"type": str(msg_type or "").strip(), "order_id": str(int(order_id)), "status": str(status or "").strip()}
    if service_type: data["service_type"] = str(service_type).strip()
    if scheduled_start is not None: data["scheduled_start"] = scheduled_start.astimezone(timezone.utc).isoformat()
    if execution_start is not None: data["execution_start"] = execution_start.astimezone(timezone.utc).isoformat()
    if price is not None: data["price"] = str(int(price))
    return data

async def _send_fcm_legacy(tokens: List[str], title: str, body: str, data: dict) -> None:  # تابع=ارسال Legacy
    if not tokens: return
    if not FCM_SERVER_KEY:
        logger.error("FCM_SERVER_KEY is empty")
        return

    headers = {"Authorization": f"key={FCM_SERVER_KEY}", "Content-Type": "application/json"}
    merged = dict(data or {})
    merged["title"] = str(title or "")
    merged["body"] = str(body or "")
    payload = {"registration_ids": tokens, "priority": "high", "data": _to_fcm_data(merged)}

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post("https://fcm.googleapis.com/fcm/send", headers=headers, json=payload)
    if resp.status_code != 200:
        logger.error(f"FCM legacy send failed HTTP_{resp.status_code} body={resp.text}")

async def _send_fcm_v1_single(token: str, title: str, body: str, data: dict) -> None:  # تابع=ارسال v1
    access = _get_oauth2_token_for_fcm()
    if not access:
        logger.error("FCM v1 oauth token not available")
        return
    if not FCM_PROJECT_ID:
        logger.error("FCM_PROJECT_ID is empty")
        return

    headers = {"Authorization": f"Bearer {access}", "Content-Type": "application/json"}
    merged = dict(data or {})
    merged["title"] = str(title or "")
    merged["body"] = str(body or "")
    msg = {
        "message": {
            "token": str(token or "").strip(),
            "android": {"priority": "HIGH"},
            "data": _to_fcm_data(merged)
        }
    }
    url = f"https://fcm.googleapis.com/v1/projects/{FCM_PROJECT_ID}/messages:send"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(url, headers=headers, json=msg)
    if resp.status_code not in (200, 201):
        logger.error(f"FCM v1 send failed HTTP_{resp.status_code} body={resp.text}")

async def push_notify_tokens(tokens: List[str], title: str, body: str, data: dict) -> None:  # تابع=مدیریت ارسال پوش
    if not tokens: return
    
    if PUSH_BACKEND == "fcm":
        # بررسی امکان استفاده از v1
        sa = _load_service_account()
        if FCM_PROJECT_ID and (sa is not None):
            logger.info(f"Sending push via FCM v1 to {len(tokens)} tokens")
            for t in tokens:
                await _send_fcm_v1_single(t, title, body, data)
            return
        
        # اگر v1 ممکن نبود، تلاش با Legacy (فقط اگر کلید باشد)
        if FCM_SERVER_KEY:
            logger.warning("Falling back to FCM Legacy")
            await _send_fcm_legacy(tokens, title, body, data)
        else:
            logger.error("Cannot send FCM: ProjectID/ServiceAccount missing AND LegacyKey missing")
        return

    if PUSH_BACKEND == "ntfy":
        base = (NTFY_BASE_URL or "https://ntfy.sh").strip()
        headers = {}
        if NTFY_AUTH: headers["Authorization"] = NTFY_AUTH
        async with httpx.AsyncClient(timeout=10.0) as client:
            for topic in tokens:
                await client.post(f"{base}/{topic}", headers=headers, data=body.encode("utf-8"))
        return
    
    logger.error(f"unknown PUSH_BACKEND={PUSH_BACKEND}")

async def get_manager_tokens(target_phone: Optional[str] = None) -> List[str]:  # تابع=گرفتن توکن‌های مدیر
    q = DeviceTokenTable.__table__.select().where((DeviceTokenTable.role == "manager") & (DeviceTokenTable.platform == "android"))
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

async def get_user_tokens(phone: str) -> List[str]:  # تابع=گرفتن توکن‌های کاربر
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

async def notify_user(phone: str, title: str, body: str, data: Optional[dict] = None) -> None:  # تابع=اعلان به کاربر
    norm = _normalize_phone(phone)
    ins = NotificationTable.__table__.insert().values(
        user_phone=norm, title=str(title or ""), body=str(body or ""), data=(data or {}),
        read=False, created_at=datetime.now(timezone.utc)
    )
    await database.execute(ins)
    tokens = await get_user_tokens(norm)
    if not tokens:
        logger.info(f"no user tokens for phone={norm}")
        return
    await push_notify_tokens(tokens, str(title or ""), str(body or ""), (data or {}))

async def notify_managers(title: str, body: str, data: Optional[dict] = None, target_phone: Optional[str] = None) -> None:  # تابع=اعلان به مدیران
    tokens = await get_manager_tokens(target_phone=target_phone)
    if not tokens and not target_phone:
        logger.info("no manager tokens")
        return
    if not tokens and target_phone:
        tokens = await get_manager_tokens(target_phone=None)
    if not tokens:
        logger.info("no manager tokens")
        return
    await push_notify_tokens(tokens, str(title or ""), str(body or ""), (data or {}))

# -------------------- App & CORS --------------------  # بخش=اپ و CORS
app = FastAPI()
allow_origins = ["*"] if ALLOW_ORIGINS_ENV == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allow_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# -------------------- Startup / Shutdown --------------------  # بخش=شروع/پایان
@app.on_event("startup")
async def startup() -> None:
    if not DATABASE_URL: raise RuntimeError("DATABASE_URL is empty")
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS execution_start TIMESTAMPTZ NULL;"))
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place VARCHAR DEFAULT 'client';"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_schedule_slots_provider_start_active ON schedule_slots (provider_phone, slot_start) WHERE status IN ('PROPOSED','ACCEPTED');"))
    await database.connect()

@app.on_event("shutdown")
async def shutdown() -> None:
    await database.disconnect()

# -------------------- Health --------------------  # بخش=سلامت
@app.get("/")
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}

# -------------------- Auth & Token --------------------  # بخش=احراز هویت
@app.get("/verify_token")
def verify_token(request: Request):
    token = extract_bearer_token(request)
    if not token: return {"status": "ok", "valid": False}
    payload = decode_access_token(token)
    return {"status": "ok", "valid": bool(payload and payload.get("sub"))}

@app.post("/auth/refresh")
async def refresh_access(body: RefreshAccessRequest):
    raw = str(body.refresh_token or "").strip()
    if not raw: raise HTTPException(status_code=400, detail="refresh_token required")
    token_hash = hash_refresh_token(raw)
    row = await database.fetch_one(RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash))
    if not row or bool(row["revoked"]): raise HTTPException(status_code=401, detail="invalid/revoked refresh token")
    if row["expires_at"] <= datetime.now(timezone.utc): raise HTTPException(status_code=401, detail="refresh token expired")
    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.id == int(row["user_id"])))
    if not user: raise HTTPException(status_code=401, detail="user not found")
    access = create_access_token(_normalize_phone(user["phone"]))
    return unified_response("ok", "ACCESS_REFRESHED", "access token refreshed", {"access_token": access})

@app.post("/logout")
async def logout_user(body: LogoutRequest):
    refresh_raw = str(body.refresh_token or "").strip()
    if not refresh_raw: raise HTTPException(status_code=400, detail="refresh_token required")
    token_hash = hash_refresh_token(refresh_raw)
    rt_row = await database.fetch_one(RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash))
    await database.execute(RefreshTokenTable.__table__.update().where(RefreshTokenTable.token_hash == token_hash).values(revoked=True))
    device_token = str(body.device_token or "").strip()
    if device_token:
        await database.execute(DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == device_token))
    elif rt_row:
        user = await database.fetch_one(UserTable.__table__.select().where(UserTable.id == int(rt_row["user_id"])))
        if user:
            phone = _normalize_phone(user["phone"])
            await database.execute(DeviceTokenTable.__table__.delete().where(DeviceTokenTable.user_phone == phone))
    return unified_response("ok", "LOGOUT", "logged out", {})

@app.post("/push/register")
async def register_push_token(body: PushRegister):
    now = datetime.now(timezone.utc)
    norm_phone = _normalize_phone(body.user_phone) if body.user_phone else None
    row = await database.fetch_one(DeviceTokenTable.__table__.select().where(DeviceTokenTable.token == str(body.token).strip()))
    if row is None:
        await database.execute(DeviceTokenTable.__table__.insert().values(token=str(body.token).strip(), role=str(body.role).strip(), platform=str(body.platform or "android").strip(), user_phone=norm_phone, created_at=now, updated_at=now))
    else:
        await database.execute(DeviceTokenTable.__table__.update().where(DeviceTokenTable.id == int(row["id"])).values(role=str(body.role).strip(), platform=str(body.platform or "android").strip(), user_phone=norm_phone if norm_phone else row["user_phone"], updated_at=now))
    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": str(body.role).strip()})

@app.post("/push/unregister")
async def unregister_push_token(body: PushUnregister):
    await database.execute(DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == str(body.token).strip()))
    return unified_response("ok", "TOKEN_UNREGISTERED", "unregistered", {})

@app.get("/users/exists")
async def user_exists(phone: str):
    norm = _normalize_phone(phone)
    if not norm: return unified_response("ok", "USER_NOT_FOUND", "check", {"exists": False})
    count = await database.fetch_val(select(func.count()).select_from(UserTable).where(UserTable.phone == norm))
    exists = bool(count and int(count) > 0)
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "check", {"exists": exists})

@app.post("/register_user")
async def register_user(user: UserRegisterRequest):
    norm = _normalize_phone(user.phone)
    if not norm: raise HTTPException(status_code=400, detail="phone required")
    count = await database.fetch_val(select(func.count()).select_from(UserTable).where(UserTable.phone == norm))
    if count and int(count) > 0: raise HTTPException(status_code=400, detail="User already exists")
    password_hash = bcrypt_hash_password(user.password)
    await database.execute(UserTable.__table__.insert().values(phone=norm, password_hash=password_hash, address=str(user.address or "").strip(), name="", car_list=[]))
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": norm})

@app.post("/login")
async def login_user(user: UserLoginRequest, request: Request):
    now = datetime.now(timezone.utc)
    client_ip = get_client_ip(request)
    phone_norm = _normalize_phone(user.phone)
    if not phone_norm: raise HTTPException(status_code=400, detail="invalid phone")

    sel_att = LoginAttemptTable.__table__.select().where((LoginAttemptTable.phone == phone_norm) & (LoginAttemptTable.ip == client_ip))
    att = await database.fetch_one(sel_att)
    if not att:
        await database.execute(LoginAttemptTable.__table__.insert().values(phone=phone_norm, ip=client_ip, attempt_count=0, window_start=now, last_attempt_at=now, created_at=now))
        att = await database.fetch_one(sel_att)
    else:
        locked_until = att["locked_until"]
        if locked_until and locked_until > now:
            raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": int((locked_until - now).total_seconds())}, headers={"Retry-After": str(int((locked_until - now).total_seconds()))})
        window_age = (now - (att["window_start"] or now)).total_seconds()
        if window_age > LOGIN_WINDOW_SECONDS or (locked_until and locked_until <= now):
            await database.execute(LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(attempt_count=0, window_start=now, locked_until=None, last_attempt_at=now))
            att = await database.fetch_one(sel_att)

    db_user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == phone_norm))
    if not db_user: raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})

    if not verify_password_secure(user.password, db_user["password_hash"]):
        cur = int(att["attempt_count"] or 0) + 1
        rem = max(0, LOGIN_MAX_ATTEMPTS - cur)
        if cur >= LOGIN_MAX_ATTEMPTS:
            lock_time = now + timedelta(seconds=LOGIN_LOCK_SECONDS)
            await database.execute(LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(attempt_count=cur, locked_until=lock_time, last_attempt_at=now))
            raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": LOGIN_LOCK_SECONDS}, headers={"Retry-After": str(LOGIN_LOCK_SECONDS)})
        await database.execute(LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(attempt_count=cur, last_attempt_at=now))
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": int(rem)}, headers={"X-Remaining-Attempts": str(int(rem))})

    await database.execute(LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(attempt_count=0, window_start=now, locked_until=None, last_attempt_at=now))
    
    access = create_access_token(phone_norm)
    refresh = create_refresh_token()
    await database.execute(RefreshTokenTable.__table__.insert().values(user_id=int(db_user["id"]), token_hash=hash_refresh_token(refresh), expires_at=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), revoked=False))
    return {"status": "ok", "access_token": access, "refresh_token": refresh, "user": {"phone": phone_norm, "address": str(db_user["address"] or ""), "name": str(db_user["name"] or "")}}

class AdminLoginRequest(BaseModel):  # کلاس=مدل ورودی ورود مدیر
    phone: str
    password: str

@app.post("/admin/login")  # مسیر=ورود مدیر
async def admin_login(body: AdminLoginRequest, request: Request):
    now = datetime.now(timezone.utc)
    client_ip = get_client_ip(request)
    phone_norm = _normalize_phone(body.phone)
    if not phone_norm: raise HTTPException(status_code=400, detail="invalid phone")

    if phone_norm not in ADMIN_PHONES_SET:
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": 0})

    sel_att = LoginAttemptTable.__table__.select().where((LoginAttemptTable.phone == phone_norm) & (LoginAttemptTable.ip == client_ip))
    att = await database.fetch_one(sel_att)
    if not att:
        await database.execute(LoginAttemptTable.__table__.insert().values(phone=phone_norm, ip=client_ip, attempt_count=0, window_start=now, last_attempt_at=now, created_at=now))
        att = await database.fetch_one(sel_att)
    else:
        locked_until = att["locked_until"]
        if locked_until and locked_until > now:
            raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": int((locked_until - now).total_seconds())})
        if (now - (att["window_start"] or now)).total_seconds() > LOGIN_WINDOW_SECONDS or (locked_until and locked_until <= now):
            await database.execute(LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(attempt_count=0, window_start=now, locked_until=None))
            att = await database.fetch_one(sel_att)

    db_user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == phone_norm))
    password_raw = str(body.password or "").strip()
    if not password_raw: raise HTTPException(status_code=400, detail="password required")

    if not db_user:
        password_hash = bcrypt_hash_password(password_raw)
        await database.execute(UserTable.__table__.insert().values(phone=phone_norm, password_hash=password_hash, address="", name="Manager", car_list=[]))
        db_user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == phone_norm))
    else:
        if not verify_password_secure(password_raw, db_user["password_hash"]):
            cur = int(att["attempt_count"] or 0) + 1
            if cur >= LOGIN_MAX_ATTEMPTS:
                lock = now + timedelta(seconds=LOGIN_LOCK_SECONDS)
                await database.execute(LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(attempt_count=cur, locked_until=lock))
                raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": LOGIN_LOCK_SECONDS})
            await database.execute(LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(attempt_count=cur))
            raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": max(0, LOGIN_MAX_ATTEMPTS - cur)})

    await database.execute(LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(attempt_count=0, window_start=now, locked_until=None))
    
    access = create_access_token(phone_norm)
    refresh = create_refresh_token()
    await database.execute(RefreshTokenTable.__table__.insert().values(user_id=int(db_user["id"]), token_hash=hash_refresh_token(refresh), expires_at=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), revoked=False))
    return {"status": "ok", "access_token": access, "refresh_token": refresh, "user": {"phone": phone_norm, "address": str(db_user["address"] or ""), "name": str(db_user["name"] or "")}}

@app.get("/admin/requests/active")
async def admin_active_requests(request: Request):
    require_admin(request)
    active = ["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]
    rows = await database.fetch_all(RequestTable.__table__.select().where(RequestTable.status.in_(active)).order_by(RequestTable.id.desc()))
    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": [dict(r) for r in rows]})

@app.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str, request: Request):
    norm = require_user_phone(request, user_phone)
    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))
    if not user: raise HTTPException(status_code=404, detail="User not found")
    return unified_response("ok", "USER_CARS", "cars list", {"items": user["car_list"] or []})

@app.post("/user_cars")
async def update_user_cars(body: CarListUpdateRequest, request: Request):
    norm = require_user_phone(request, body.user_phone)
    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))
    if not user: raise HTTPException(status_code=404, detail="User not found")
    cars_payload = [c.dict() for c in (body.car_list or [])]
    await database.execute(UserTable.__table__.update().where(UserTable.phone == norm).values(car_list=cars_payload))
    return unified_response("ok", "USER_CARS_UPDATED", "cars updated", {"count": len(cars_payload)})

@app.post("/user/profile")
async def update_profile(body: UserProfileUpdate, request: Request):
    norm = require_user_phone(request, body.phone)
    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))
    if not user: raise HTTPException(status_code=404, detail="User not found")
    await database.execute(UserTable.__table__.update().where(UserTable.phone == norm).values(name=str(body.name or "").strip(), address=str(body.address or "").strip()))
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": norm})

@app.get("/user/profile/{phone}")
async def get_user_profile(phone: str, request: Request):
    norm = require_user_phone(request, phone)
    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))
    if not user: raise HTTPException(status_code=404, detail="User not found")
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {"phone": norm, "name": str(user["name"] or ""), "address": str(user["address"] or "")})

@app.post("/order")
async def create_order(order: OrderRequest, request: Request):
    norm = require_user_phone(request, order.user_phone)
    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))
    if not user: raise HTTPException(status_code=404, detail="User not found")
    ins = RequestTable.__table__.insert().values(user_phone=norm, latitude=float(order.location.latitude), longitude=float(order.location.longitude), car_list=[car.dict() for car in (order.car_list or [])], address=str(order.address or "").strip(), home_number=str(order.home_number or "").strip(), service_type=str(order.service_type or "").strip().lower(), price=int(order.price), request_datetime=str(order.request_datetime or "").strip(), status="NEW", payment_type=str(order.payment_type or "").strip().lower(), service_place=str(order.service_place or "client").strip().lower(), driver_phone="", driver_name="").returning(RequestTable.id)
    row = await database.fetch_one(ins)
    new_id = int(row["id"]) if row and row["id"] else 0
    try:
        await notify_managers(title="سفارش جدید", body=f"سفارش جدید ثبت شد: {str(order.service_type or '')}", data={"order_id": str(new_id), "user_phone": norm, "service_type": str(order.service_type or ""), "status": "NEW"})
    except Exception as e: logger.error(f"notify_managers(create_order) failed: {e}")
    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})

@app.post("/cancel_order")
async def cancel_order(cancel: CancelRequest, request: Request):
    norm = require_user_phone(request, cancel.user_phone)
    service = str(cancel.service_type or "").strip().lower()
    if not service: raise HTTPException(status_code=400, detail="service_type required")
    upd = RequestTable.__table__.update().where((RequestTable.user_phone == norm) & (RequestTable.service_type == service) & (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED"])) & (RequestTable.execution_start.is_(None))).values(status="CANCELED", scheduled_start=None, execution_start=None).returning(RequestTable.id, RequestTable.driver_phone)
    rows = await database.fetch_all(upd)
    if not rows: raise HTTPException(status_code=409, detail={"code": "CANNOT_CANCEL", "message": "cannot cancel"})
    ids = [int(r["id"]) for r in rows]
    drivers = list({str(r["driver_phone"] or "").strip() for r in rows if str(r["driver_phone"] or "").strip()})
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id.in_(ids)) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))).values(status="REJECTED"))
    await database.execute(AppointmentTable.__table__.update().where((AppointmentTable.request_id.in_(ids)) & (AppointmentTable.status == "BOOKED")).values(status="CANCELED"))
    try:
        await notify_managers(title="لغو سفارش", body=f"سفارش توسط کاربر لغو شد ({service})", data={"order_ids": ",".join(str(x) for x in ids), "user_phone": norm, "service_type": service, "status": "CANCELED"})
        for dp in drivers:
            await notify_managers(title="لغو سفارش", body=f"سفارش شما لغو شد (id={ids[0]})", data={"order_ids": ",".join(str(x) for x in ids), "status": "CANCELED"}, target_phone=_normalize_phone(dp))
    except Exception as e: logger.error(f"notify_managers(cancel_order) failed: {e}")
    return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(ids)})

@app.get("/user_active_services/{user_phone}")
async def get_user_active_services(user_phone: str, request: Request):
    norm = require_user_phone(request, user_phone)
    rows = await database.fetch_all(RequestTable.__table__.select().where((RequestTable.user_phone == norm) & (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))))
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": [dict(r) for r in rows]})

@app.get("/user_orders/{user_phone}")
async def get_user_orders(user_phone: str, request: Request):
    norm = require_user_phone(request, user_phone)
    rows = await database.fetch_all(RequestTable.__table__.select().where(RequestTable.user_phone == norm).order_by(RequestTable.id.desc()))
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": [dict(r) for r in rows]})

@app.get("/user/{phone}/notifications")
async def get_notifications(phone: str, request: Request, only_unread: bool = True, limit: int = 20, offset: int = 0):
    norm = require_user_phone(request, phone)
    q = NotificationTable.__table__.select().where(NotificationTable.user_phone == norm)
    if only_unread: q = q.where(NotificationTable.read == False)
    rows = await database.fetch_all(q.order_by(NotificationTable.created_at.desc()).limit(limit).offset(offset))
    items = [{"id": int(r["id"]), "user_phone": str(r["user_phone"] or ""), "title": str(r["title"] or ""), "body": str(r["body"] or ""), "data": r["data"] or {}, "read": bool(r["read"]), "created_at": (r["created_at"].astimezone(timezone.utc).isoformat() if r["created_at"] else None)} for r in rows]
    return unified_response("ok", "NOTIFICATIONS", "notifications", {"items": items})

@app.post("/user/{phone}/notifications/{notif_id}/read")
async def mark_notification_read(phone: str, notif_id: int, request: Request):
    norm = require_user_phone(request, phone)
    await database.execute(NotificationTable.__table__.update().where((NotificationTable.id == int(notif_id)) & (NotificationTable.user_phone == norm)).values(read=True, read_at=datetime.now(timezone.utc)))
    return unified_response("ok", "NOTIFICATION_READ", "notification marked read", {"id": int(notif_id)})

@app.post("/user/{phone}/notifications/mark_all_read")
async def mark_all_notifications_read(phone: str, request: Request):
    norm = require_user_phone(request, phone)
    await database.execute(NotificationTable.__table__.update().where((NotificationTable.user_phone == norm) & (NotificationTable.read == False)).values(read=True, read_at=datetime.now(timezone.utc)))
    return unified_response("ok", "ALL_NOTIFICATIONS_READ", "all marked read", {})

async def provider_is_free(provider_phone: str, start: datetime, end: datetime, exclude_order_id: Optional[int] = None) -> bool:
    provider = _normalize_phone(provider_phone)
    if not provider: return False
    one_hour = text("interval '1 hour'")
    q_app = select(func.count()).select_from(AppointmentTable).where((AppointmentTable.provider_phone == provider) & (AppointmentTable.status == "BOOKED") & (AppointmentTable.start_time < end) & (AppointmentTable.end_time > start))
    if exclude_order_id: q_app = q_app.where(AppointmentTable.request_id != int(exclude_order_id))
    if int(await database.fetch_val(q_app) or 0) > 0: return False
    
    q_slot = select(func.count()).select_from(ScheduleSlotTable).where((ScheduleSlotTable.provider_phone == provider) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) & (ScheduleSlotTable.slot_start < end) & ((ScheduleSlotTable.slot_start + one_hour) > start))
    if exclude_order_id: q_slot = q_slot.where(ScheduleSlotTable.request_id != int(exclude_order_id))
    if int(await database.fetch_val(q_slot) or 0) > 0: return False

    q_exec = select(func.count()).select_from(RequestTable).where((RequestTable.driver_phone == provider) & (RequestTable.execution_start.is_not(None)) & (RequestTable.status.in_(["IN_PROGRESS", "STARTED"])) & (RequestTable.execution_start < end) & ((RequestTable.execution_start + one_hour) > start))
    if exclude_order_id: q_exec = q_exec.where(RequestTable.id != int(exclude_order_id))
    if int(await database.fetch_val(q_exec) or 0) > 0: return False

    q_visit = select(func.count()).select_from(RequestTable).where((RequestTable.driver_phone == provider) & (RequestTable.scheduled_start.is_not(None)) & (RequestTable.status.in_(["WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"])) & (RequestTable.scheduled_start < end) & ((RequestTable.scheduled_start + one_hour) > start))
    if exclude_order_id: q_visit = q_visit.where(RequestTable.id != int(exclude_order_id))
    if int(await database.fetch_val(q_visit) or 0) > 0: return False
    return True

@app.get("/busy_slots")
async def get_busy_slots(request: Request, date: str, exclude_order_id: Optional[int] = None):
    require_admin(request)
    d = datetime.fromisoformat(str(date).strip()).date()
    provider = get_admin_provider_phone(request)
    start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    
    q_sched = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.slot_start >= start) & (ScheduleSlotTable.slot_start < end) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) & (ScheduleSlotTable.provider_phone == provider))
    if exclude_order_id: q_sched = q_sched.where(ScheduleSlotTable.request_id != int(exclude_order_id))
    
    q_app = AppointmentTable.__table__.select().where((AppointmentTable.start_time >= start) & (AppointmentTable.start_time < end) & (AppointmentTable.status == "BOOKED") & (AppointmentTable.provider_phone == provider))
    if exclude_order_id: q_app = q_app.where(AppointmentTable.request_id != int(exclude_order_id))

    q_exec = RequestTable.__table__.select().where((RequestTable.execution_start >= start) & (RequestTable.execution_start < end) & (RequestTable.execution_start.is_not(None)) & (RequestTable.status.in_(["IN_PROGRESS", "STARTED"])) & (RequestTable.driver_phone == provider))
    if exclude_order_id: q_exec = q_exec.where(RequestTable.id != int(exclude_order_id))

    q_visit = RequestTable.__table__.select().where((RequestTable.scheduled_start >= start) & (RequestTable.scheduled_start < end) & (RequestTable.scheduled_start.is_not(None)) & (RequestTable.status.in_(["ASSIGNED", "IN_PROGRESS", "STARTED", "WAITING"])) & (RequestTable.driver_phone == provider))
    if exclude_order_id: q_visit = q_visit.where(RequestTable.id != int(exclude_order_id))

    busy = set()
    for r in await database.fetch_all(q_sched): busy.add(r["slot_start"].astimezone(timezone.utc).isoformat())
    for r in await database.fetch_all(q_app): busy.add(r["start_time"].astimezone(timezone.utc).isoformat())
    for r in await database.fetch_all(q_exec): busy.add(r["execution_start"].astimezone(timezone.utc).isoformat())
    for r in await database.fetch_all(q_visit): busy.add(r["scheduled_start"].astimezone(timezone.utc).isoformat())
    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": sorted(list(busy))})

@app.post("/order/{order_id}/propose_slots")
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):
    require_admin(request)
    provider = get_admin_provider_phone(request)
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))
    if not req: raise HTTPException(status_code=404, detail="order not found")
    if req["status"] in ["FINISH", "CANCELED"] or req["execution_start"]: raise HTTPException(status_code=409, detail="cannot propose slots")
    
    slots = sorted(list(set(body.slots)))[:3]
    if not slots: raise HTTPException(status_code=400, detail="slots required")
    slot_dts = [parse_iso(x) for x in slots]
    
    async with database.transaction():
        await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == int(order_id)) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))).values(status="REJECTED"))
        await database.execute(AppointmentTable.__table__.update().where((AppointmentTable.request_id == int(order_id)) & (AppointmentTable.status == "BOOKED")).values(status="CANCELED"))
        await database.execute(RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(driver_phone=provider, status="WAITING", scheduled_start=None))
        
        for dt in slot_dts:
            if not await provider_is_free(provider, dt, dt + timedelta(hours=1), exclude_order_id=int(order_id)):
                raise HTTPException(status_code=409, detail="slot overlap")
            try:
                await database.execute(ScheduleSlotTable.__table__.insert().values(request_id=int(order_id), provider_phone=provider, slot_start=dt, status="PROPOSED", created_at=datetime.now(timezone.utc)))
            except: raise HTTPException(status_code=409, detail="slot conflict")
            
    try:
        await notify_user(phone=str(req["user_phone"]), title="پیشنهاد زمان بازدید", body="زمان‌های پیشنهادی برای بازدید ارسال شد.", data={"type": "visit_slots", "order_id": int(order_id), "status": "WAITING", "service_type": str(req["service_type"] or "")})
    except Exception as e: logger.error(f"notify_user(propose_slots) failed: {e}")
    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": [dt.isoformat() for dt in slot_dts]})

@app.get("/order/{order_id}/proposed_slots")
async def get_proposed_slots(order_id: int, request: Request):
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))
    if not req: raise HTTPException(status_code=404, detail="order not found")
    require_user_phone(request, str(req["user_phone"]))
    rows = await database.fetch_all(ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.request_id == int(order_id)) & (ScheduleSlotTable.status == "PROPOSED")).order_by(ScheduleSlotTable.slot_start.asc()))
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": [r["slot_start"].astimezone(timezone.utc).isoformat() for r in rows]})

@app.post("/order/{order_id}/confirm_slot")
async def confirm_slot(order_id: int, body: ConfirmSlotRequest, request: Request):
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))
    if not req: raise HTTPException(status_code=404, detail="order not found")
    require_user_phone(request, str(req["user_phone"]))
    if req["execution_start"] or str(req["status"]).upper() not in ["WAITING", "ASSIGNED", "NEW"]: raise HTTPException(status_code=409, detail="cannot confirm")
    
    slot_dt = parse_iso(body.slot)
    end_dt = slot_dt + timedelta(hours=1)
    
    async with database.transaction():
        slot_row = await database.fetch_one(ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.request_id == int(order_id)) & (ScheduleSlotTable.slot_start == slot_dt) & (ScheduleSlotTable.status == "PROPOSED")))
        if not slot_row: raise HTTPException(status_code=404, detail="slot not found")
        provider = _normalize_phone(str(slot_row["provider_phone"]))
        if not await provider_is_free(provider, slot_dt, end_dt, int(order_id)): raise HTTPException(status_code=409, detail="overlap")
        
        await database.execute(AppointmentTable.__table__.update().where((AppointmentTable.request_id == int(order_id)) & (AppointmentTable.status == "BOOKED") & ((AppointmentTable.start_time != slot_dt) | (AppointmentTable.end_time != end_dt))).values(status="CANCELED"))
        await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == int(order_id)) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) & (ScheduleSlotTable.slot_start != slot_dt)).values(status="REJECTED"))
        await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == int(order_id)) & (ScheduleSlotTable.slot_start == slot_dt)).values(status="ACCEPTED"))
        
        exist = await database.fetch_one(AppointmentTable.__table__.select().where((AppointmentTable.provider_phone == provider) & (AppointmentTable.start_time == slot_dt)).limit(1))
        if exist:
            if str(exist["status"]) == "BOOKED" and int(exist["request_id"]) != int(order_id): raise HTTPException(status_code=409, detail="conflict")
            await database.execute(AppointmentTable.__table__.update().where(AppointmentTable.id == int(exist["id"])).values(request_id=int(order_id), status="BOOKED"))
        else:
            await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider, request_id=int(order_id), start_time=slot_dt, end_time=end_dt, status="BOOKED", created_at=datetime.now(timezone.utc)))
        
        await database.execute(RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(scheduled_start=slot_dt, status="ASSIGNED", driver_phone=provider))
        
    try:
        await notify_managers(title="تأیید زمان بازدید", body=f"کاربر زمان بازدید را تأیید کرد (order_id={int(order_id)}).", data=order_push_data(msg_type="time_confirm", order_id=int(order_id), status="ASSIGNED", service_type=str(req["service_type"] or ""), scheduled_start=slot_dt), target_phone=provider)
    except Exception as e: logger.error(f"notify(confirm_slot) failed: {e}")
    return unified_response("ok", "SLOT_CONFIRMED", "confirmed", {"start": slot_dt.isoformat(), "end": end_dt.isoformat()})

@app.post("/order/{order_id}/reject_all_and_cancel")
async def reject_all_and_cancel(order_id: int, request: Request):
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))
    if not req: raise HTTPException(status_code=404, detail="order not found")
    require_user_phone(request, str(req["user_phone"]))
    if req["execution_start"] or str(req["status"]).upper() not in ["NEW", "WAITING", "ASSIGNED"]: raise HTTPException(status_code=409, detail="cannot cancel")
    
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == int(order_id)) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))).values(status="REJECTED"))
    await database.execute(AppointmentTable.__table__.update().where((AppointmentTable.request_id == int(order_id)) & (AppointmentTable.status == "BOOKED")).values(status="CANCELED"))
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(status="CANCELED", scheduled_start=None, execution_start=None))
    
    try:
        await notify_managers(title="لغو سفارش", body=f"سفارش {int(order_id)} توسط کاربر لغو شد.", data={"order_id": int(order_id), "status": "CANCELED", "user_phone": _normalize_phone(str(req["user_phone"]))})
    except Exception as e: logger.error(f"notify_managers(reject_all) failed: {e}")
    return unified_response("ok", "ORDER_CANCELED", "canceled", {"order_id": int(order_id)})

@app.post("/admin/order/{order_id}/price")
async def admin_set_price(order_id: int, body: PriceBody, request: Request):
    require_admin(request)
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))
    if not req: raise HTTPException(status_code=404, detail="order not found")
    provider = _normalize_phone(str(req["driver_phone"] or ""))
    new_status = "PRICE_REJECTED"
    exec_dt = None
    
    async with database.transaction():
        if body.agree:
            if not body.exec_time or not provider: raise HTTPException(status_code=400, detail="exec_time/provider required")
            exec_dt = parse_iso(str(body.exec_time))
            end_dt = exec_dt + timedelta(hours=1)
            if not await provider_is_free(provider, exec_dt, end_dt, int(order_id)): raise HTTPException(status_code=409, detail="overlap")
            
            exist = await database.fetch_one(AppointmentTable.__table__.select().where((AppointmentTable.provider_phone == provider) & (AppointmentTable.start_time == exec_dt)).limit(1))
            if exist:
                if str(exist["status"]) == "BOOKED" and int(exist["request_id"]) != int(order_id): raise HTTPException(status_code=409, detail="conflict")
                await database.execute(AppointmentTable.__table__.update().where(AppointmentTable.id == int(exist["id"])).values(request_id=int(order_id), status="BOOKED"))
            else:
                await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider, request_id=int(order_id), start_time=exec_dt, end_time=end_dt, status="BOOKED", created_at=datetime.now(timezone.utc)))
            new_status = "IN_PROGRESS"
            
        saved = await database.fetch_one(RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(price=int(body.price), status=new_status, execution_start=exec_dt).returning(RequestTable.id, RequestTable.price, RequestTable.status, RequestTable.execution_start))
        
    try:
        title = "توافق قیمت" if body.agree else "عدم توافق قیمت"
        msg = f"قیمت {int(body.price)} ثبت شد." if body.agree else "قیمت مورد توافق قرار نگرفت."
        m_type = "execution_time" if body.agree else "price_set"
        await notify_user(phone=str(req["user_phone"]), title=title, body=msg, data=order_push_data(msg_type=m_type, order_id=int(order_id), status=str(new_status), service_type=str(req["service_type"] or ""), scheduled_start=req["scheduled_start"], execution_start=exec_dt, price=int(body.price)))
    except Exception as e: logger.error(f"notify_user(set_price) failed: {e}")
    
    return unified_response("ok", "PRICE_SET", "updated", {"order_id": saved["id"], "price": saved["price"], "status": saved["status"], "execution_start": (saved["execution_start"].astimezone(timezone.utc).isoformat() if saved["execution_start"] else None)})

@app.post("/order/{order_id}/finish")
async def finish_order(order_id: int, request: Request):
    require_admin(request)
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))
    if not req: raise HTTPException(status_code=404, detail="order not found")
    
    async with database.transaction():
        await database.execute(RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(status="FINISH", finish_datetime=datetime.now(timezone.utc).isoformat()))
        await database.execute(AppointmentTable.__table__.update().where((AppointmentTable.request_id == int(order_id)) & (AppointmentTable.status == "BOOKED")).values(status="DONE"))
        
    try:
        await notify_user(phone=str(req["user_phone"]), title="اتمام کار", body="سفارش شما انجام شد.", data={"type": "work_finished", "order_id": int(order_id), "status": "FINISH", "service_type": str(req["service_type"] or "")})
    except Exception as e: logger.error(f"notify(finish) failed: {e}")
    return unified_response("ok", "ORDER_FINISHED", "finished", {"order_id": int(order_id), "status": "FINISH"})

@app.post("/admin/order/{order_id}/cancel")
async def admin_cancel_order(order_id: int, request: Request):
    require_admin(request)
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))
    if not req: raise HTTPException(status_code=404, detail="order not found")
    
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(status="CANCELED", scheduled_start=None, execution_start=None))
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == int(order_id)) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))).values(status="REJECTED"))
    await database.execute(AppointmentTable.__table__.update().where((AppointmentTable.request_id == int(order_id)) & (AppointmentTable.status == "BOOKED")).values(status="CANCELED"))
    
    try:
        await notify_user(phone=str(req["user_phone"]), title="لغو سفارش", body="سفارش شما توسط مدیر لغو شد.", data={"type": "order_canceled", "order_id": int(order_id), "status": "CANCELED", "service_type": str(req["service_type"] or ""), "canceled_by": "manager"})
    except Exception as e: logger.error(f"notify(admin_cancel) failed: {e}")
    return unified_response("ok", "ORDER_CANCELED", "canceled by admin", {"order_id": int(order_id), "status": "CANCELED"})

@app.get("/debug/users")
async def debug_users():
    rows = await database.fetch_all(UserTable.__table__.select().order_by(UserTable.id.asc()))
    return {"items": [{"id": r["id"], "phone": r["phone"]} for r in rows]}
