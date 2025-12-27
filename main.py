# FILE: server/main.py
# فایل=سرور FastAPI (بخش ۱: importها، config، ابزارها، بدون حذف هیچ چیز)

# -*- coding: utf-8 -*-

import os  # خواندن Env
import re  # Regex
import hashlib  # هش
import secrets  # تولید توکن
from datetime import datetime, timedelta, timezone  # زمان
from typing import Optional, List, Dict  # تایپ‌ها

import bcrypt  # هش رمز
import jwt  # JWT
from fastapi import FastAPI, HTTPException, Request  # FastAPI
from fastapi.middleware.cors import CORSMiddleware  # CORS
from pydantic import BaseModel  # Pydantic

from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    ForeignKey, Index, select, func, and_, text, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import JSONB  # JSONB
from sqlalchemy.ext.declarative import declarative_base  # Base ORM
import sqlalchemy  # Engine
from databases import Database  # async DB
from dotenv import load_dotenv  # env
import httpx  # HTTP

import json  # JSON
import base64  # Base64
import time  # time
import logging  # logging

# -------------------- Config --------------------
load_dotenv()  # بارگذاری env

DATABASE_URL = os.getenv("DATABASE_URL")  # URL دیتابیس
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # کلید JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # pepper
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # انقضای access
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # انقضای refresh
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # دور bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # CORS

# Legacy FCM
FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "").strip()  # کلید legacy

# FCM HTTP v1
FCM_PROJECT_ID = os.getenv("FCM_PROJECT_ID", "").strip()  # project id
GOOGLE_APPLICATION_CREDENTIALS_JSON = os.getenv(
    "GOOGLE_APPLICATIONS_CREDENTIALS_JSON",
    os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")
).strip()  # service account
GOOGLE_APPLICATION_CREDENTIALS_JSON_B64 = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON_B64", "").strip()  # service account b64

ADMIN_KEY = os.getenv("ADMIN_KEY", "CHANGE_ME_ADMIN")  # کلید ادمین قدیمی

ADMIN_PHONES_ENV = os.getenv("ADMIN_PHONES", "").strip()  # شماره مدیران

def _normalize_phone(p: str) -> str:  # نرمال‌سازی شماره
    return "".join(ch for ch in str(p or "") if ch.isdigit() or ch == "+")

def _parse_admin_phones(s: str) -> set[str]:  # پارس شماره مدیران
    out = set()
    for part in (s or "").split(","):
        vv = _normalize_phone(part.strip())
        if vv:
            out.add(vv)
    return out

ADMIN_PHONES_SET = _parse_admin_phones(ADMIN_PHONES_ENV)  # مجموعه مدیران

AUTH_COMPAT = os.getenv("AUTH_COMPAT", "1").strip()  # سازگاری قدیمی

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "600"))  # پنجره لاگین
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # حداکثر تلاش
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "1800"))  # قفل موقت

PUSH_BACKEND = os.getenv("PUSH_BACKEND", "fcm").strip().lower()  # بک‌اند پوش
NTFY_BASE_URL = os.getenv("NTFY_BASE_URL", "https://ntfy.sh").strip()  # ntfy
NTFY_AUTH = os.getenv("NTFY_AUTH", "").strip()  # auth ntfy

# -------------------- Logger --------------------
logger = logging.getLogger("putz.push")  # لاگر پوش
if not logger.handlers:
    h = logging.StreamHandler()  # handler
    fmt = logging.Formatter("[PUSH] %(levelname)s: %(message)s")  # فرمت
    h.setFormatter(fmt)
    logger.addHandler(h)
logger.setLevel(logging.INFO)  # سطح لاگ

# -------------------- Database --------------------
database = Database(DATABASE_URL)  # اتصال async
Base = declarative_base()  # Base ORM

# -------------------- Time helpers (UTC ONLY) --------------------
def parse_iso(ts: str) -> datetime:  # پارس ISO فقط UTC
    try:
        raw = ts.strip()
        if raw.endswith("Z"):
            raw = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            raise ValueError("timezone required")
        return dt.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail=f"invalid UTC datetime: {ts}")

# -------------------- ORM models --------------------

class UserTable(Base):  # جدول کاربران
    __tablename__ = "users"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    phone = Column(String, unique=True, index=True)  # شماره
    password_hash = Column(String)  # هش رمز
    address = Column(String)  # آدرس
    name = Column(String, default="")  # نام
    car_list = Column(JSONB, default=list)  # لیست خودرو

class DriverTable(Base):  # جدول رانندگان
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

class RequestTable(Base):  # جدول سفارش‌ها
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
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # زمان قطعی (UTC)
    service_place = Column(String, default="client")
    execution_start = Column(DateTime(timezone=True), nullable=True)  # زمان اجرا (UTC)

class RefreshTokenTable(Base):  # جدول رفرش توکن
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    token_hash = Column(String, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), index=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),
    )

class LoginAttemptTable(Base):  # جدول تلاش‌های لاگین
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, index=True)
    ip = Column(String, index=True)
    attempt_count = Column(Integer, default=0)
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        Index("ix_login_attempt_phone_ip", "phone", "ip"),
    )

class ScheduleSlotTable(Base):  # جدول اسلات‌های پیشنهادی
    __tablename__ = "schedule_slots"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)
    provider_phone = Column(String, index=True)
    slot_start = Column(DateTime(timezone=True), index=True)  # UTC
    status = Column(String, default="PROPOSED")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        Index("ix_schedule_slots_req_status", "request_id", "status"),
    )

class AppointmentTable(Base):  # جدول رزرو نهایی
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    provider_phone = Column(String, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)
    start_time = Column(DateTime(timezone=True), index=True)  # UTC
    end_time = Column(DateTime(timezone=True), index=True)  # UTC
    status = Column(String, default="BOOKED")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),
    )

class NotificationTable(Base):  # جدول اعلان‌ها
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String, index=True)
    title = Column(String)
    body = Column(String)
    data = Column(JSONB, default=dict)
    read = Column(Boolean, default=False, index=True)
    read_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    __table_args__ = (
        Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),
    )

class DeviceTokenTable(Base):  # جدول توکن دستگاه
    __tablename__ = "device_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    role = Column(String, index=True)
    platform = Column(String, default="android", index=True)
    user_phone = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        Index("ix_tokens_role_platform", "role", "platform"),
    )

# -------------------- Pydantic models --------------------

class CarInfo(BaseModel):  # مدل خودرو
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک

class Location(BaseModel):  # مدل موقعیت
    latitude: float  # عرض
    longitude: float  # طول

class CarOrderItem(BaseModel):  # آیتم سفارش خودرو
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک
    wash_outside: bool = False  # روشویی
    wash_inside: bool = False  # توشویی
    polish: bool = False  # پولیش

class OrderRequest(BaseModel):  # ثبت سفارش
    user_phone: str  # شماره کاربر
    location: Location  # موقعیت
    car_list: List[CarOrderItem]  # لیست خودرو
    address: str  # آدرس
    home_number: Optional[str] = ""  # پلاک
    service_type: str  # نوع سرویس
    price: int  # قیمت
    request_datetime: str  # زمان ثبت
    payment_type: str  # نوع پرداخت
    service_place: str  # محل سرویس

class CarListUpdateRequest(BaseModel):  # به‌روزرسانی خودروها
    user_phone: str  # شماره
    car_list: List[CarInfo]  # لیست

class CancelRequest(BaseModel):  # لغو سفارش
    user_phone: str  # شماره
    service_type: str  # سرویس

class UserRegisterRequest(BaseModel):  # ثبت‌نام
    phone: str  # شماره
    password: str  # رمز
    address: Optional[str] = None  # آدرس

class UserLoginRequest(BaseModel):  # ورود
    phone: str  # شماره
    password: str  # رمز

class UserProfileUpdate(BaseModel):  # پروفایل
    phone: str  # شماره
    name: str = ""  # نام
    address: str = ""  # آدرس

class ProposedSlotsRequest(BaseModel):  # پیشنهاد زمان
    provider_phone: str  # شماره سرویس‌دهنده
    slots: List[str]  # لیست ISO UTC

class ConfirmSlotRequest(BaseModel):  # تایید زمان
    slot: str  # ISO UTC

class PriceBody(BaseModel):  # تعیین قیمت
    price: int  # قیمت
    agree: bool  # موافقت
    exec_time: Optional[str] = None  # ISO UTC

class PushRegister(BaseModel):  # ثبت توکن پوش
    role: str  # نقش
    token: str  # توکن
    platform: str = "android"  # پلتفرم
    user_phone: Optional[str] = None  # شماره

class PushUnregister(BaseModel):  # لغو توکن پوش
    token: str  # توکن

class LogoutRequest(BaseModel):  # خروج
    refresh_token: str  # رفرش
    device_token: Optional[str] = None  # توکن دستگاه

# -------------------- Security helpers --------------------

def bcrypt_hash_password(password: str) -> str:  # هش رمز
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # نمک
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی

def verify_password_secure(password: str, stored_hash: str) -> bool:  # بررسی رمز
    try:
        if stored_hash.startswith("$2"):  # bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return old == stored_hash
    except Exception:
        return False

def create_access_token(subject_phone: str) -> str:  # ساخت access token
    now = datetime.now(timezone.utc)  # زمان فعلی UTC
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # زمان انقضا
    payload = {  # payload=داده‌های JWT
        "sub": str(subject_phone),  # sub=شماره کاربر/مدیر
        "type": "access",  # type=نوع توکن
        "iat": int(now.timestamp()),  # iat=زمان صدور
        "exp": int(exp.timestamp()),  # exp=زمان انقضا
    }  # پایان payload
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # token=امضای JWT
    return token  # بازگشت توکن

def create_refresh_token() -> str:  # ساخت رفرش
    return secrets.token_urlsafe(48)

def hash_refresh_token(token: str) -> str:  # هش رفرش
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # پاسخ واحد
    return {"status": status, "code": code, "message": message, "data": (data or {})}

def extract_bearer_token(request: Request) -> Optional[str]:  # استخراج Bearer
    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip()

def decode_access_token(token: str) -> Optional[dict]:  # دیکود JWT
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "access":
            return None
        return payload
    except Exception:
        return None

def get_auth_phone(request: Request, fallback_phone: Optional[str] = None, enforce: bool = False) -> str:  # احراز شماره
    token = extract_bearer_token(request)
    if token:
        payload = decode_access_token(token)
        if not payload or not payload.get("sub"):
            raise HTTPException(status_code=401, detail="invalid token")
        sub = str(payload["sub"])
        if fallback_phone and sub != fallback_phone:
            raise HTTPException(status_code=403, detail="forbidden")
        return sub
    if AUTH_COMPAT == "1" and fallback_phone:
        return fallback_phone
    if enforce:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return fallback_phone or ""

def require_admin(request: Request):  # احراز مدیر
    token = extract_bearer_token(request)
    if token:
        payload = decode_access_token(token)
        sub = (payload or {}).get("sub")
        norm = _normalize_phone(sub or "")
        if norm and norm in ADMIN_PHONES_SET:
            return
        raise HTTPException(status_code=401, detail="admin auth required")
    key = request.headers.get("x-admin-key", "")
    if key and key == ADMIN_KEY:
        return
    raise HTTPException(status_code=401, detail="admin auth required")

# -------------------- Utils --------------------

def get_client_ip(request: Request) -> str:  # گرفتن IP کلاینت
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host or "unknown"

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:  # بررسی آزاد بودن
    q = AppointmentTable.__table__.select().where(
        (AppointmentTable.provider_phone == provider_phone) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.end_time > start)
    )
    rows = await database.fetch_all(q)
    return len(rows) == 0

async def notify_user(phone: str, title: str, body: str, data: Optional[dict] = None):  # ثبت اعلان
    ins = NotificationTable.__table__.insert().values(
        user_phone=phone,
        title=title,
        body=body,
        data=(data or {}),
        read=False,
        created_at=datetime.now(timezone.utc)
    )
    await database.execute(ins)

# -------------------- Push helpers --------------------

_FCM_OAUTH_TOKEN = ""
_FCM_OAUTH_EXP = 0.0

def _load_service_account() -> Optional[dict]:
    raw = GOOGLE_APPLICATION_CREDENTIALS_JSON
    if not raw and GOOGLE_APPLICATION_CREDENTIALS_JSON_B64:
        try:
            raw = base64.b64decode(GOOGLE_APPLICATION_CREDENTIALS_JSON_B64).decode("utf-8")
        except Exception:
            raw = ""
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if "client_email" in data and "private_key" in data:
            pk = data.get("private_key", "")
            if "\\n" in pk:
                data["private_key"] = pk.replace("\\n", "\n")
            return data
    except Exception:
        return None
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
        "exp": expires
    }
    assertion = jwt.encode(payload, sa["private_key"], algorithm="RS256")
    resp = httpx.post(
        "https://oauth2.googleapis.com/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion
        },
        timeout=10.0
    )
    if resp.status_code != 200:
        return None
    data = resp.json()
    token = data.get("access_token")
    if not token:
        return None
    _FCM_OAUTH_TOKEN = token
    _FCM_OAUTH_EXP = now + int(data.get("expires_in", 3600))
    return token

async def get_manager_tokens() -> List[str]:
    sel = DeviceTokenTable.__table__.select().where(
        (DeviceTokenTable.role == "manager") &
        (DeviceTokenTable.platform == "android")
    )
    rows = await database.fetch_all(sel)
    seen, tokens = set(), []
    for r in rows:
        t = r["token"]
        if t and t not in seen:
            seen.add(t)
            tokens.append(t)
    return tokens

async def get_user_tokens(phone: str) -> List[str]:
    sel = DeviceTokenTable.__table__.select().where(
        (DeviceTokenTable.role == "client") &
        (DeviceTokenTable.user_phone == phone)
    )
    rows = await database.fetch_all(sel)
    seen, tokens = set(), []
    for r in rows:
        t = r["token"]
        if t and t not in seen:
            seen.add(t)
            tokens.append(t)
    return tokens

# -------------------- App & CORS --------------------

app = FastAPI()

allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [
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
async def startup():
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS execution_start TIMESTAMPTZ NULL;"))
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# -------------------- Health --------------------

@app.get("/")  # مسیر سلامت
def read_root():  # تابع سلامت
    return {"message": "Putzfee FastAPI Server is running!"}  # پاسخ سلامت

# -------------------- Auth helpers endpoints --------------------

@app.get("/verify_token")  # بررسی اعتبار توکن
def verify_token(request: Request):
    token = extract_bearer_token(request)  # استخراج توکن
    if not token:
        return {"status": "ok", "valid": False}
    payload = decode_access_token(token)
    return {"status": "ok", "valid": bool(payload and payload.get("sub"))}

@app.post("/logout")  # خروج کاربر
async def logout_user(body: LogoutRequest):
    if not body.refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token required")

    token_hash = hash_refresh_token(body.refresh_token)
    sel_rt = RefreshTokenTable.__table__.select().where(
        RefreshTokenTable.token_hash == token_hash
    )
    rt_row = await database.fetch_one(sel_rt)

    upd = RefreshTokenTable.__table__.update().where(
        RefreshTokenTable.token_hash == token_hash
    ).values(revoked=True)
    await database.execute(upd)

    if body.device_token and body.device_token.strip():
        delq = DeviceTokenTable.__table__.delete().where(
            DeviceTokenTable.token == body.device_token.strip()
        )
        await database.execute(delq)
    else:
        user_id_val = None
        if rt_row:
            user_id_val = rt_row["user_id"]
        if user_id_val is not None:
            sel_user = UserTable.__table__.select().where(UserTable.id == user_id_val)
            user = await database.fetch_one(sel_user)
            if user:
                del_all = DeviceTokenTable.__table__.delete().where(
                    DeviceTokenTable.user_phone == user["phone"]
                )
                await database.execute(del_all)

    return unified_response("ok", "LOGOUT", "refresh token revoked and device tokens removed", {})

# -------------------- Push endpoints --------------------

@app.post("/push/register")  # ثبت توکن پوش
async def register_push_token(body: PushRegister, request: Request):
    now = datetime.now(timezone.utc)
    sel = DeviceTokenTable.__table__.select().where(
        DeviceTokenTable.token == body.token
    )
    row = await database.fetch_one(sel)

    if row is None:
        ins = DeviceTokenTable.__table__.insert().values(
            token=body.token,
            role=body.role,
            platform=body.platform,
            user_phone=body.user_phone,
            created_at=now,
            updated_at=now
        )
        await database.execute(ins)
    else:
        upd = DeviceTokenTable.__table__.update().where(
            DeviceTokenTable.id == row["id"]
        ).values(
            role=body.role,
            platform=body.platform,
            user_phone=body.user_phone or row["user_phone"],
            updated_at=now
        )
        await database.execute(upd)

    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": body.role})

@app.post("/push/unregister")  # لغو ثبت توکن پوش
async def unregister_push_token(body: PushUnregister):
    delq = DeviceTokenTable.__table__.delete().where(
        DeviceTokenTable.token == body.token
    )
    await database.execute(delq)
    return unified_response("ok", "TOKEN_UNREGISTERED", "unregistered", {})

# -------------------- Auth / User --------------------

@app.get("/users/exists")  # بررسی وجود کاربر
async def user_exists(phone: str):
    q = select(func.count()).select_from(UserTable).where(
        UserTable.phone == phone
    )
    count = await database.fetch_val(q)
    exists = bool(count and int(count) > 0)
    return unified_response(
        "ok",
        "USER_EXISTS" if exists else "USER_NOT_FOUND",
        "user exists check",
        {"exists": exists}
    )

@app.post("/register_user")  # ثبت‌نام کاربر
async def register_user(user: UserRegisterRequest):
    q = select(func.count()).select_from(UserTable).where(
        UserTable.phone == user.phone
    )
    count = await database.fetch_val(q)
    if count and int(count) > 0:
        raise HTTPException(status_code=400, detail="User already exists")

    password_hash = bcrypt_hash_password(user.password)
    ins = UserTable.__table__.insert().values(
        phone=user.phone,
        password_hash=password_hash,
        address=(user.address or "").strip(),
        name="",
        car_list=[]
    )
    await database.execute(ins)
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})

@app.post("/login")  # ورود کاربر
async def login_user(user: UserLoginRequest, request: Request):
    now = datetime.now(timezone.utc)
    client_ip = get_client_ip(request)

    sel_user = UserTable.__table__.select().where(
        UserTable.phone == user.phone
    )
    db_user = await database.fetch_one(sel_user)
    if not db_user:
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})

    if not verify_password_secure(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD"})

    access_token = create_access_token(db_user["phone"])
    refresh_token = create_refresh_token()
    refresh_hash = hash_refresh_token(refresh_token)
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    ins_rt = RefreshTokenTable.__table__.insert().values(
        user_id=db_user["id"],
        token_hash=refresh_hash,
        expires_at=refresh_exp,
        revoked=False
    )
    await database.execute(ins_rt)

    return {
        "status": "ok",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "phone": db_user["phone"],
            "address": db_user["address"] or "",
            "name": db_user["name"] or ""
        }
    }

# -------------------- Orders --------------------

@app.post("/order")  # ثبت سفارش
async def create_order(order: OrderRequest, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=order.user_phone, enforce=False)
    if auth_phone != order.user_phone:
        raise HTTPException(status_code=403, detail="forbidden")

    ins = RequestTable.__table__.insert().values(
        user_phone=order.user_phone,
        latitude=order.location.latitude,
        longitude=order.location.longitude,
        car_list=[car.dict() for car in order.car_list],
        address=order.address.strip(),
        home_number=(order.home_number or "").strip(),
        service_type=order.service_type,
        price=order.price,
        request_datetime=order.request_datetime,
        status="NEW",
        payment_type=order.payment_type.strip().lower(),
        service_place=order.service_place.strip().lower()
    ).returning(RequestTable.id)

    row = await database.fetch_one(ins)
    new_id = row["id"] if row else None

    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})

@app.post("/cancel_order")  # لغو سفارش
async def cancel_order(cancel: CancelRequest, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=cancel.user_phone, enforce=False)
    if auth_phone != cancel.user_phone:
        raise HTTPException(status_code=403, detail="forbidden")

    upd = (
        RequestTable.__table__.update()
        .where(
            (RequestTable.user_phone == cancel.user_phone) &
            (RequestTable.service_type == cancel.service_type) &
            (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))
        )
        .values(status="CANCELED", scheduled_start=None)
        .returning(RequestTable.id)
    )
    rows = await database.fetch_all(upd)
    if rows:
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})

    raise HTTPException(status_code=404, detail="active order not found")

@app.get("/user_active_services/{user_phone}")  # سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)
    if auth_phone != user_phone:
        raise HTTPException(status_code=403, detail="forbidden")

    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))
    )
    result = await database.fetch_all(sel)
    items = [dict(r) for r in result]
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})

@app.get("/user_orders/{user_phone}")  # لیست سفارش‌ها
async def get_user_orders(user_phone: str, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)
    if auth_phone != user_phone:
        raise HTTPException(status_code=403, detail="forbidden")

    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)
    result = await database.fetch_all(sel)
    items = [dict(r) for r in result]
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})

# -------------------- Scheduling --------------------

@app.get("/provider/{provider_phone}/free_hours")  # ساعات آزاد
async def get_free_hours(
    provider_phone: str,
    date: str,
    work_start: int = 8,
    work_end: int = 20,
    limit: int = 24
):
    d = datetime.fromisoformat(date).date()
    provider = provider_phone.strip()
    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)
    day_end = datetime(d.year, d.month, d.day, work_end, 0, tzinfo=timezone.utc)

    results: List[str] = []
    cur = day_start
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:
        s, e = cur, cur + timedelta(hours=1)
        if await provider_is_free(provider, s, e):
            results.append(s.isoformat())
        cur += timedelta(hours=1)

    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})

@app.get("/busy_slots")  # ساعات مشغول
async def get_busy_slots(provider_phone: str, date: str, exclude_order_id: Optional[int] = None):
    d = datetime.fromisoformat(date).date()
    provider = provider_phone.strip()

    day_start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)
    day_end = day_start + timedelta(days=1)

    sel_sched = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.slot_start >= day_start) &
        (ScheduleSlotTable.slot_start < day_end) &
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &
        (ScheduleSlotTable.provider_phone == provider)
    )
    if exclude_order_id is not None:
        sel_sched = sel_sched.where(ScheduleSlotTable.request_id != exclude_order_id)

    rows_sched = await database.fetch_all(sel_sched)

    sel_app = AppointmentTable.__table__.select().where(
        (AppointmentTable.start_time >= day_start) &
        (AppointmentTable.start_time < day_end) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.provider_phone == provider)
    )
    rows_app = await database.fetch_all(sel_app)

    busy: set[str] = set()
    for r in rows_sched:
        busy.add(r["slot_start"].isoformat())
    for r in rows_app:
        busy.add(r["start_time"].isoformat())

    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": sorted(busy)})

# -------------------- Admin workflow --------------------

@app.get("/admin/requests/active")  # لیست درخواست‌های فعال مدیر
async def admin_active_requests(request: Request):
    require_admin(request)
    active = ["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]
    sel = RequestTable.__table__.select().where(
        RequestTable.status.in_(active)
    ).order_by(RequestTable.id.desc())
    rows = await database.fetch_all(sel)
    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": [dict(r) for r in rows]})

@app.post("/order/{order_id}/propose_slots")  # پیشنهاد زمان‌ها
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):
    require_admin(request)
    provider = body.provider_phone.strip()
    accepted: List[str] = []

    for s in body.slots[:3]:
        start = parse_iso(s)
        end = start + timedelta(hours=1)
        if await provider_is_free(provider, start, end):
            await database.execute(
                ScheduleSlotTable.__table__.insert().values(
                    request_id=order_id,
                    provider_phone=provider,
                    slot_start=start,
                    status="PROPOSED",
                    created_at=datetime.now(timezone.utc)
                )
            )
            accepted.append(start.isoformat())

    if accepted:
        await database.execute(
            RequestTable.__table__.update()
            .where(RequestTable.id == order_id)
            .values(status="WAITING", driver_phone=provider, scheduled_start=None)
        )

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})

# -------------------- Confirm / Finish workflow --------------------

@app.post("/order/{order_id}/confirm_slot")  # تأیید زمان توسط کاربر
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):
    start = parse_iso(body.slot)  # start=زمان شروع UTC
    end = start + timedelta(hours=1)  # end=زمان پایان UTC

    sel_slot = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.status == "PROPOSED") &
        (ScheduleSlotTable.slot_start == start)
    )
    slot = await database.fetch_one(sel_slot)
    if not slot:
        raise HTTPException(status_code=404, detail="slot not found")

    if not await provider_is_free(slot["provider_phone"], start, end):
        raise HTTPException(status_code=409, detail="slot busy")

    await database.execute(
        ScheduleSlotTable.__table__.update()
        .where(ScheduleSlotTable.id == slot["id"])
        .values(status="ACCEPTED")
    )

    await database.execute(
        ScheduleSlotTable.__table__.update()
        .where(
            (ScheduleSlotTable.request_id == order_id) &
            (ScheduleSlotTable.status == "PROPOSED")
        )
        .values(status="REJECTED")
    )

    await database.execute(
        AppointmentTable.__table__.insert().values(
            provider_phone=slot["provider_phone"],
            request_id=order_id,
            start_time=start,
            end_time=end,
            status="BOOKED",
            created_at=datetime.now(timezone.utc)
        )
    )

    await database.execute(
        RequestTable.__table__.update()
        .where(RequestTable.id == order_id)
        .values(
            scheduled_start=start,
            status="ASSIGNED",
            driver_phone=slot["provider_phone"]
        )
    )

    return unified_response(
        "ok",
        "SLOT_CONFIRMED",
        "slot confirmed",
        {"start": start.isoformat(), "end": end.isoformat()}
    )

@app.post("/order/{order_id}/finish")  # اتمام کار توسط مدیر
async def finish_order(order_id: int, request: Request):
    require_admin(request)

    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)
    req = await database.fetch_one(sel)
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    now_iso = datetime.now(timezone.utc).isoformat()

    await database.execute(
        RequestTable.__table__.update()
        .where(RequestTable.id == order_id)
        .values(
            status="FINISH",
            finish_datetime=now_iso
        )
    )

    return unified_response(
        "ok",
        "ORDER_FINISHED",
        "order finished",
        {"order_id": order_id, "status": "FINISH"}
    )

# -------------------- Profile --------------------

@app.post("/user/profile")  # ذخیره پروفایل
async def update_profile(body: UserProfileUpdate, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=body.phone, enforce=False)
    if auth_phone != body.phone:
        raise HTTPException(status_code=403, detail="forbidden")

    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)
    user = await database.fetch_one(sel)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await database.execute(
        UserTable.__table__.update()
        .where(UserTable.phone == body.phone)
        .values(
            name=body.name.strip(),
            address=body.address.strip()
        )
    )

    return unified_response(
        "ok",
        "PROFILE_UPDATED",
        "profile saved",
        {"phone": body.phone}
    )

@app.get("/user/profile/{phone}")  # دریافت پروفایل
async def get_user_profile(phone: str, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)
    if auth_phone != phone:
        raise HTTPException(status_code=403, detail="forbidden")

    sel = UserTable.__table__.select().where(UserTable.phone == phone)
    user = await database.fetch_one(sel)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return unified_response(
        "ok",
        "PROFILE_FETCHED",
        "profile data",
        {
            "phone": user["phone"],
            "name": user["name"] or "",
            "address": user["address"] or ""
        }
    )

# -------------------- Debug --------------------

@app.get("/debug/users")  # دیباگ کاربران
async def debug_users():
    rows = await database.fetch_all(UserTable.__table__.select())
    out = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "phone": r["phone"],
                "name": r["name"],
                "address": r["address"]
            }
        )
    return out

# -------------------- End of server/main.py --------------------
