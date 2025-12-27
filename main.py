# FILE: server/main.py  # فایل=فایل اصلی سرور
# -*- coding: utf-8 -*-  # تنظیم=کدینگ

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

from sqlalchemy import (  # import=SQLAlchemy
    Column, Integer, String, Float, Boolean, DateTime,  # ستون‌ها
    ForeignKey, Index, select, func, and_, text, UniqueConstraint  # ابزارها
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
GOOGLE_APPLICATION_CREDENTIALS_JSON = os.getenv(  # خواندن service account json
    "GOOGLE_APPLICATIONS_CREDENTIALS_JSON",  # نام کلید قدیمی
    os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")  # نام کلید صحیح
).strip()  # trim
GOOGLE_APPLICATION_CREDENTIALS_JSON_B64 = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON_B64", "").strip()  # service account b64

ADMIN_KEY = os.getenv("ADMIN_KEY", "CHANGE_ME_ADMIN")  # کلید ادمین قدیمی
ADMIN_PHONES_ENV = os.getenv("ADMIN_PHONES", "").strip()  # شماره مدیران

def _normalize_phone(p: str) -> str:  # نرمال‌سازی شماره
    return "".join(ch for ch in str(p or "") if ch.isdigit() or ch == "+")  # نگه‌داشتن رقم و +

def _parse_admin_phones(s: str) -> set[str]:  # پارس شماره مدیران
    out = set()  # مجموعه خروجی
    for part in (s or "").split(","):  # جداکردن با کاما
        vv = _normalize_phone(part.strip())  # نرمال‌سازی
        if vv:  # اگر خالی نبود
            out.add(vv)  # افزودن
    return out  # بازگشت

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
if not logger.handlers:  # اگر هندلر ثبت نشده
    h = logging.StreamHandler()  # handler
    fmt = logging.Formatter("[PUSH] %(levelname)s: %(message)s")  # فرمت
    h.setFormatter(fmt)  # ست فرمت
    logger.addHandler(h)  # افزودن handler
logger.setLevel(logging.INFO)  # سطح لاگ

# -------------------- Database --------------------
database = Database(DATABASE_URL)  # اتصال async
Base = declarative_base()  # Base ORM

# -------------------- Time helpers (UTC ONLY) --------------------
def parse_iso(ts: str) -> datetime:  # پارس ISO فقط UTC
    try:  # try
        raw = ts.strip()  # trim
        if raw.endswith("Z"):  # اگر Z داشت
            raw = raw.replace("Z", "+00:00")  # تبدیل به آفست
        dt = datetime.fromisoformat(raw)  # پارس
        if dt.tzinfo is None:  # اگر timezone نداشت
            raise ValueError("timezone required")  # خطا
        return dt.astimezone(timezone.utc)  # تبدیل به UTC
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail=f"invalid UTC datetime: {ts}")  # پاسخ 400

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
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    first_name = Column(String)  # نام
    last_name = Column(String)  # نام خانوادگی
    photo_url = Column(String)  # عکس
    id_card_number = Column(String)  # شماره کارت
    phone = Column(String, unique=True, index=True)  # شماره
    phone_verified = Column(Boolean, default=False)  # تایید
    is_online = Column(Boolean, default=False)  # آنلاین
    status = Column(String, default="فعال")  # وضعیت

class RequestTable(Base):  # جدول سفارش‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    user_phone = Column(String, index=True)  # شماره کاربر
    latitude = Column(Float)  # lat
    longitude = Column(Float)  # lng
    car_list = Column(JSONB)  # لیست خودرو
    address = Column(String)  # آدرس
    home_number = Column(String, default="")  # پلاک
    service_type = Column(String, index=True)  # سرویس
    price = Column(Integer)  # قیمت
    request_datetime = Column(String)  # زمان ثبت
    status = Column(String)  # وضعیت
    driver_name = Column(String)  # نام راننده/سرویس‌دهنده
    driver_phone = Column(String)  # شماره سرویس‌دهنده
    finish_datetime = Column(String)  # زمان پایان
    payment_type = Column(String)  # نوع پرداخت
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # زمان قطعی (UTC)
    service_place = Column(String, default="client")  # محل سرویس
    execution_start = Column(DateTime(timezone=True), nullable=True)  # زمان اجرا (UTC)

class RefreshTokenTable(Base):  # جدول رفرش توکن
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id
    token_hash = Column(String, unique=True, index=True)  # هش توکن
    expires_at = Column(DateTime(timezone=True), index=True)  # انقضا
    revoked = Column(Boolean, default=False)  # ابطال
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (  # ایندکس‌ها
        Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),  # ایندکس ترکیبی
    )

class LoginAttemptTable(Base):  # جدول تلاش‌های لاگین
    __tablename__ = "login_attempts"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    phone = Column(String, index=True)  # شماره
    ip = Column(String, index=True)  # ip
    attempt_count = Column(Integer, default=0)  # تعداد تلاش
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # شروع پنجره
    locked_until = Column(DateTime(timezone=True), nullable=True)  # تا زمان قفل
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # آخرین تلاش
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (  # ایندکس‌ها
        Index("ix_login_attempt_phone_ip", "phone", "ip"),  # ایندکس
    )

class ScheduleSlotTable(Base):  # جدول اسلات‌های پیشنهادی
    __tablename__ = "schedule_slots"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id
    provider_phone = Column(String, index=True)  # شماره سرویس‌دهنده
    slot_start = Column(DateTime(timezone=True), index=True)  # UTC
    status = Column(String, default="PROPOSED")  # وضعیت
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (  # ایندکس‌ها
        Index("ix_schedule_slots_req_status", "request_id", "status"),  # ایندکس
    )

class AppointmentTable(Base):  # جدول رزرو نهایی
    __tablename__ = "appointments"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    provider_phone = Column(String, index=True)  # شماره سرویس‌دهنده
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id
    start_time = Column(DateTime(timezone=True), index=True)  # UTC
    end_time = Column(DateTime(timezone=True), index=True)  # UTC
    status = Column(String, default="BOOKED")  # وضعیت
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (  # قیود/ایندکس‌ها
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),  # یکتا بودن
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),  # ایندکس
    )

class NotificationTable(Base):  # جدول اعلان‌ها
    __tablename__ = "notifications"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    user_phone = Column(String, index=True)  # شماره گیرنده
    title = Column(String)  # عنوان
    body = Column(String)  # متن
    data = Column(JSONB, default=dict)  # دیتا
    read = Column(Boolean, default=False, index=True)  # خوانده شده؟
    read_at = Column(DateTime(timezone=True), nullable=True)  # زمان خواندن
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)  # ایجاد
    __table_args__ = (  # ایندکس‌ها
        Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),  # ایندکس
    )

class DeviceTokenTable(Base):  # جدول توکن دستگاه
    __tablename__ = "device_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    token = Column(String, unique=True, index=True)  # توکن
    role = Column(String, index=True)  # نقش
    platform = Column(String, default="android", index=True)  # پلتفرم
    user_phone = Column(String, nullable=True)  # شماره (اختیاری)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # آپدیت
    __table_args__ = (  # ایندکس‌ها
        Index("ix_tokens_role_platform", "role", "platform"),  # ایندکس
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

class RefreshAccessRequest(BaseModel):  # درخواست رفرش اکسس
    refresh_token: str  # رفرش توکن

# -------------------- Security helpers --------------------

def bcrypt_hash_password(password: str) -> str:  # هش رمز
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # نمک
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی

def verify_password_secure(password: str, stored_hash: str) -> bool:  # بررسی رمز
    try:  # try
        if stored_hash.startswith("$2"):  # bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # بررسی
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # هش قدیمی
        return old == stored_hash  # مقایسه
    except Exception:  # خطا
        return False  # false

def create_access_token(subject_phone: str) -> str:  # ساخت access token
    now = datetime.now(timezone.utc)  # زمان فعلی UTC
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # زمان انقضا
    payload = {  # payload
        "sub": str(subject_phone),  # sub=شماره
        "type": "access",  # نوع=اکسس
        "iat": int(now.timestamp()),  # زمان صدور
        "exp": int(exp.timestamp()),  # زمان انقضا
    }  # پایان payload
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # تولید JWT
    return token  # بازگشت

def create_refresh_token() -> str:  # ساخت رفرش
    return secrets.token_urlsafe(48)  # تولید

def hash_refresh_token(token: str) -> str:  # هش رفرش
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # sha256

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # پاسخ واحد
    return {"status": status, "code": code, "message": message, "data": (data or {})}  # دیکشنری

def extract_bearer_token(request: Request) -> Optional[str]:  # استخراج Bearer
    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""  # هدر
    if not auth.lower().startswith("bearer "):  # اگر bearer نبود
        return None  # None
    return auth.split(" ", 1)[1].strip()  # توکن

def decode_access_token(token: str) -> Optional[dict]:  # دیکود JWT
    try:  # try
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode
        if payload.get("type") != "access":  # اگر نوع اکسس نبود
            return None  # None
        return payload  # بازگشت payload
    except Exception:  # خطا
        return None  # None

def get_auth_phone(request: Request, fallback_phone: Optional[str] = None, enforce: bool = False) -> str:  # احراز شماره
    token = extract_bearer_token(request)  # توکن
    if token:  # اگر توکن بود
        payload = decode_access_token(token)  # payload
        if not payload or not payload.get("sub"):  # اگر نامعتبر
            raise HTTPException(status_code=401, detail="invalid token")  # 401
        sub = str(payload["sub"])  # شماره
        if fallback_phone and sub != fallback_phone:  # اگر mismatch
            raise HTTPException(status_code=403, detail="forbidden")  # 403
        return sub  # بازگشت
    if AUTH_COMPAT == "1" and fallback_phone:  # سازگاری قدیمی
        return fallback_phone  # بازگشت
    if enforce:  # اجبار
        raise HTTPException(status_code=401, detail="missing bearer token")  # 401
    return fallback_phone or ""  # بازگشت

def require_admin(request: Request):  # احراز مدیر
    token = extract_bearer_token(request)  # توکن
    if token:  # اگر توکن بود
        payload = decode_access_token(token)  # payload
        sub = (payload or {}).get("sub")  # sub
        norm = _normalize_phone(sub or "")  # نرمال
        if norm and norm in ADMIN_PHONES_SET:  # اگر در لیست مدیران بود
            return  # ok
        raise HTTPException(status_code=401, detail="admin auth required")  # 401
    key = request.headers.get("x-admin-key", "")  # کلید قدیمی
    if key and key == ADMIN_KEY:  # اگر برابر بود
        return  # ok
    raise HTTPException(status_code=401, detail="admin auth required")  # 401

# -------------------- Utils --------------------

def get_client_ip(request: Request) -> str:  # گرفتن IP کلاینت
    xff = request.headers.get("x-forwarded-for", "")  # xff
    if xff:  # اگر بود
        return xff.split(",")[0].strip()  # اولین ip
    return request.client.host or "unknown"  # ip

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:  # بررسی آزاد بودن
    q = AppointmentTable.__table__.select().where(  # select
        (AppointmentTable.provider_phone == provider_phone) &  # provider
        (AppointmentTable.status == "BOOKED") &  # booked
        (AppointmentTable.start_time < end) &  # تداخل
        (AppointmentTable.end_time > start)  # تداخل
    )  # پایان where
    rows = await database.fetch_all(q)  # اجرا
    return len(rows) == 0  # آزاد؟

# -------------------- Push helpers --------------------

_FCM_OAUTH_TOKEN = ""  # کش توکن OAuth
_FCM_OAUTH_EXP = 0.0  # زمان انقضا OAuth

def _load_service_account() -> Optional[dict]:  # لود service account
    raw = GOOGLE_APPLICATION_CREDENTIALS_JSON  # json خام
    if not raw and GOOGLE_APPLICATION_CREDENTIALS_JSON_B64:  # اگر b64 بود
        try:  # try
            raw = base64.b64decode(GOOGLE_APPLICATION_CREDENTIALS_JSON_B64).decode("utf-8")  # decode
        except Exception:  # خطا
            raw = ""  # خالی
    if not raw:  # اگر خالی
        return None  # None
    try:  # try
        data = json.loads(raw)  # json loads
        if "client_email" in data and "private_key" in data:  # اگر کلیدها بود
            pk = data.get("private_key", "")  # private_key
            if "\\n" in pk:  # اگر \n اسکیپ داشت
                data["private_key"] = pk.replace("\\n", "\n")  # تبدیل
            return data  # بازگشت
    except Exception:  # خطا
        return None  # None
    return None  # None

def _get_oauth2_token_for_fcm() -> Optional[str]:  # گرفتن OAuth token برای FCM v1
    global _FCM_OAUTH_TOKEN, _FCM_OAUTH_EXP  # استفاده از متغیرهای global
    now = time.time()  # زمان فعلی
    if _FCM_OAUTH_TOKEN and (_FCM_OAUTH_EXP - 60) > now:  # اگر هنوز معتبر است
        return _FCM_OAUTH_TOKEN  # بازگشت کش
    sa = _load_service_account()  # سرویس اکانت
    if not sa:  # اگر نبود
        return None  # None
    issued = int(now)  # iat
    expires = issued + 3600  # exp
    payload = {  # payload JWT
        "iss": sa["client_email"],  # صادرکننده
        "scope": "https://www.googleapis.com/auth/firebase.messaging",  # scope
        "aud": "https://oauth2.googleapis.com/token",  # مخاطب
        "iat": issued,  # iat
        "exp": expires  # exp
    }  # پایان payload
    assertion = jwt.encode(payload, sa["private_key"], algorithm="RS256")  # jwt assertion
    resp = httpx.post(  # درخواست sync
        "https://oauth2.googleapis.com/token",  # url
        data={  # form
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",  # grant
            "assertion": assertion  # assertion
        },  # پایان data
        timeout=10.0  # timeout
    )  # پایان post
    if resp.status_code != 200:  # اگر ok نبود
        return None  # None
    data = resp.json()  # json
    token = data.get("access_token")  # access_token
    if not token:  # اگر نبود
        return None  # None
    _FCM_OAUTH_TOKEN = token  # ذخیره
    _FCM_OAUTH_EXP = now + int(data.get("expires_in", 3600))  # انقضا
    return token  # بازگشت

def _to_fcm_data(data: dict) -> dict:  # تبدیل data به رشته برای FCM
    out = {}  # خروجی
    for k, v in (data or {}).items():  # حلقه
        if v is None:  # اگر None
            continue  # رد
        out[str(k)] = str(v)  # تبدیل به string
    return out  # بازگشت

async def _send_fcm_legacy(tokens: List[str], title: str, body: str, data: dict):  # ارسال FCM legacy
    if not tokens:  # بدون توکن
        return  # خروج
    if not FCM_SERVER_KEY:  # نبود کلید
        logger.error("FCM_SERVER_KEY is empty")  # لاگ
        return  # خروج
    headers = {  # هدرها
        "Authorization": f"key={FCM_SERVER_KEY}",  # کلید
        "Content-Type": "application/json"  # json
    }  # پایان headers
    payload = {  # payload
        "registration_ids": tokens,  # توکن‌ها
        "notification": {  # notification
            "title": title,  # عنوان
            "body": body  # متن
        },  # پایان notification
        "data": _to_fcm_data(data)  # data رشته‌ای
    }  # پایان payload
    async with httpx.AsyncClient(timeout=10.0) as client:  # کلاینت async
        resp = await client.post("https://fcm.googleapis.com/fcm/send", headers=headers, json=payload)  # ارسال
    if resp.status_code != 200:  # اگر ok نبود
        logger.error(f"FCM legacy send failed HTTP_{resp.status_code} body={resp.text}")  # لاگ

async def _send_fcm_v1_single(token: str, title: str, body: str, data: dict):  # ارسال FCM v1 تک‌توکن
    access = _get_oauth2_token_for_fcm()  # oauth token
    if not access:  # نبود
        logger.error("FCM v1 oauth token not available")  # لاگ
        return  # خروج
    if not FCM_PROJECT_ID:  # نبود project
        logger.error("FCM_PROJECT_ID is empty")  # لاگ
        return  # خروج
    headers = {  # هدرها
        "Authorization": f"Bearer {access}",  # bearer
        "Content-Type": "application/json"  # json
    }  # پایان headers
    msg = {  # message
        "message": {  # message
            "token": token,  # توکن
            "notification": {  # notification
                "title": title,  # عنوان
                "body": body  # متن
            },  # پایان notification
            "data": _to_fcm_data(data)  # data رشته‌ای
        }  # پایان message
    }  # پایان msg
    url = f"https://fcm.googleapis.com/v1/projects/{FCM_PROJECT_ID}/messages:send"  # url v1
    async with httpx.AsyncClient(timeout=10.0) as client:  # کلاینت
        resp = await client.post(url, headers=headers, json=msg)  # ارسال
    if resp.status_code not in (200, 201):  # اگر ok نبود
        logger.error(f"FCM v1 send failed HTTP_{resp.status_code} body={resp.text}")  # لاگ

async def push_notify_tokens(tokens: List[str], title: str, body: str, data: dict):  # ارسال پوش به لیست توکن‌ها
    if not tokens:  # بدون توکن
        return  # خروج
    if PUSH_BACKEND == "fcm":  # fcm
        if FCM_PROJECT_ID and (_load_service_account() is not None):  # v1 available
            for t in tokens:  # حلقه
                await _send_fcm_v1_single(t, title, body, data)  # ارسال v1
            return  # خروج
        await _send_fcm_legacy(tokens, title, body, data)  # ارسال legacy
        return  # خروج
    if PUSH_BACKEND == "ntfy":  # ntfy
        base = (NTFY_BASE_URL or "https://ntfy.sh").strip()  # base
        headers = {}  # headers
        if NTFY_AUTH:  # اگر auth داشت
            headers["Authorization"] = NTFY_AUTH  # هدر auth
        async with httpx.AsyncClient(timeout=10.0) as client:  # کلاینت
            for topic in tokens:  # توکن=topic
                await client.post(f"{base}/{topic}", headers=headers, data=body.encode("utf-8"))  # ارسال
        return  # خروج
    logger.error(f"unknown PUSH_BACKEND={PUSH_BACKEND}")  # لاگ

async def get_manager_tokens() -> List[str]:  # گرفتن توکن‌های مدیر (همه)
    sel = DeviceTokenTable.__table__.select().where(  # select
        (DeviceTokenTable.role == "manager") &  # role manager
        (DeviceTokenTable.platform == "android")  # android
    )  # پایان where
    rows = await database.fetch_all(sel)  # اجرا
    seen, tokens = set(), []  # جلوگیری از تکرار
    for r in rows:  # حلقه
        t = r["token"]  # token
        if t and t not in seen:  # شرط
            seen.add(t)  # seen
            tokens.append(t)  # افزودن
    return tokens  # بازگشت

async def get_manager_tokens_for_phone(phone: str) -> List[str]:  # گرفتن توکن‌های مدیر برای یک شماره
    norm = _normalize_phone(phone)  # نرمال
    sel = DeviceTokenTable.__table__.select().where(  # select
        (DeviceTokenTable.role == "manager") &  # role
        (DeviceTokenTable.platform == "android") &  # platform
        (DeviceTokenTable.user_phone == norm)  # شماره
    )  # پایان where
    rows = await database.fetch_all(sel)  # اجرا
    seen, tokens = set(), []  # جلوگیری از تکرار
    for r in rows:  # حلقه
        t = r["token"]  # token
        if t and t not in seen:  # شرط
            seen.add(t)  # seen
            tokens.append(t)  # افزودن
    return tokens  # بازگشت

async def get_user_tokens(phone: str) -> List[str]:  # گرفتن توکن‌های کاربر
    norm = _normalize_phone(phone)  # نرمال‌سازی شماره
    sel = DeviceTokenTable.__table__.select().where(  # select
        (DeviceTokenTable.role.in_(["client", "user"])) &  # نقش کاربر
        (DeviceTokenTable.user_phone == norm)  # شماره نرمال
    )  # پایان where
    rows = await database.fetch_all(sel)  # اجرا
    seen, tokens = set(), []  # جلوگیری از تکرار
    for r in rows:  # حلقه
        t = r["token"]  # token
        if t and t not in seen:  # شرط
            seen.add(t)  # seen
            tokens.append(t)  # افزودن
    return tokens  # بازگشت

async def notify_user(phone: str, title: str, body: str, data: Optional[dict] = None):  # ثبت اعلان + ارسال پوش به کاربر
    norm_phone = _normalize_phone(phone)  # نرمال‌سازی شماره
    ins = NotificationTable.__table__.insert().values(  # insert notification
        user_phone=norm_phone,  # شماره
        title=title,  # عنوان
        body=body,  # متن
        data=(data or {}),  # دیتا
        read=False,  # خوانده نشده
        created_at=datetime.now(timezone.utc)  # زمان ایجاد
    )  # پایان insert
    await database.execute(ins)  # اجرای insert

    tokens = await get_user_tokens(norm_phone)  # گرفتن توکن‌های کاربر
    if not tokens:  # اگر توکن نبود
        logger.info(f"no user tokens for phone={norm_phone}")  # لاگ
        return  # خروج
    await push_notify_tokens(tokens, title, body, (data or {}))  # ارسال پوش

async def notify_managers(title: str, body: str, data: Optional[dict] = None, target_phone: Optional[str] = None):  # ارسال اعلان به مدیرها
    tokens: List[str] = []  # لیست توکن‌ها
    if target_phone and _normalize_phone(target_phone):  # اگر شماره هدف داده شد
        tokens = await get_manager_tokens_for_phone(_normalize_phone(target_phone))  # توکن‌های همان مدیر
    if not tokens:  # اگر برای شماره پیدا نشد یا شماره نبود
        tokens = await get_manager_tokens()  # همه توکن‌های مدیر
    if not tokens:  # اگر هیچ توکنی نبود
        logger.info("no manager tokens")  # لاگ
        return  # خروج
    await push_notify_tokens(tokens, title, body, (data or {}))  # ارسال پوش

# -------------------- App & CORS --------------------

app = FastAPI()  # ساخت اپ

allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [  # لیست origin
    o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()  # پارس
]  # پایان

app.add_middleware(  # افزودن middleware
    CORSMiddleware,  # کلاس CORS
    allow_origins=allow_origins,  # originها
    allow_credentials=True,  # credentials
    allow_methods=["*"],  # همه متدها
    allow_headers=["*"],  # همه هدرها
)  # پایان middleware

# -------------------- Startup / Shutdown --------------------

@app.on_event("startup")  # رویداد startup
async def startup():  # تابع startup
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # ساخت engine sync
    Base.metadata.create_all(engine)  # ساخت جداول
    with engine.begin() as conn:  # کانکشن
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # افزودن ستون
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS execution_start TIMESTAMPTZ NULL;"))  # افزودن ستون
    await database.connect()  # اتصال async

@app.on_event("shutdown")  # رویداد shutdown
async def shutdown():  # تابع shutdown
    await database.disconnect()  # قطع اتصال

# -------------------- Health --------------------

@app.get("/")  # مسیر سلامت
def read_root():  # تابع سلامت
    return {"message": "Putzfee FastAPI Server is running!"}  # پاسخ

# -------------------- Auth helpers endpoints --------------------

@app.get("/verify_token")  # بررسی اعتبار توکن
def verify_token(request: Request):  # تابع
    token = extract_bearer_token(request)  # استخراج توکن
    if not token:  # اگر نبود
        return {"status": "ok", "valid": False}  # پاسخ
    payload = decode_access_token(token)  # دیکود
    return {"status": "ok", "valid": bool(payload and payload.get("sub"))}  # پاسخ

@app.post("/auth/refresh")  # رفرش access
async def refresh_access(body: RefreshAccessRequest):  # تابع رفرش
    raw = (body.refresh_token or "").strip()  # گرفتن رفرش
    if not raw:  # اگر خالی
        raise HTTPException(status_code=400, detail="refresh_token required")  # 400
    token_hash = hash_refresh_token(raw)  # هش رفرش
    sel = RefreshTokenTable.__table__.select().where(  # select ردیف
        (RefreshTokenTable.token_hash == token_hash)  # شرط هش
    )  # پایان where
    row = await database.fetch_one(sel)  # گرفتن ردیف
    if not row:  # اگر نبود
        raise HTTPException(status_code=401, detail="invalid refresh token")  # 401
    if row["revoked"]:  # اگر revoked بود
        raise HTTPException(status_code=401, detail="refresh token revoked")  # 401
    now = datetime.now(timezone.utc)  # اکنون UTC
    exp = row["expires_at"]  # زمان انقضا
    if exp is None or exp <= now:  # اگر منقضی شده
        raise HTTPException(status_code=401, detail="refresh token expired")  # 401
    user_id = row["user_id"]  # user_id
    sel_u = UserTable.__table__.select().where(UserTable.id == user_id)  # select user
    user = await database.fetch_one(sel_u)  # گرفتن user
    if not user:  # اگر نبود
        raise HTTPException(status_code=401, detail="user not found")  # 401
    access = create_access_token(user["phone"])  # ساخت access
    return unified_response("ok", "ACCESS_REFRESHED", "access token refreshed", {"access_token": access})  # پاسخ

@app.post("/logout")  # خروج کاربر
async def logout_user(body: LogoutRequest):  # تابع خروج
    if not body.refresh_token:  # اگر نبود
        raise HTTPException(status_code=400, detail="refresh_token required")  # 400

    token_hash = hash_refresh_token(body.refresh_token)  # هش رفرش
    sel_rt = RefreshTokenTable.__table__.select().where(  # select رفرش
        RefreshTokenTable.token_hash == token_hash  # شرط
    )  # پایان where
    rt_row = await database.fetch_one(sel_rt)  # گرفتن ردیف

    upd = RefreshTokenTable.__table__.update().where(  # update
        RefreshTokenTable.token_hash == token_hash  # شرط
    ).values(revoked=True)  # مقدار
    await database.execute(upd)  # اجرا

    if body.device_token and body.device_token.strip():  # اگر توکن دستگاه داده شد
        delq = DeviceTokenTable.__table__.delete().where(  # delete
            DeviceTokenTable.token == body.device_token.strip()  # شرط
        )  # پایان
        await database.execute(delq)  # اجرا
    else:  # اگر توکن دستگاه نبود
        user_id_val = None  # مقدار
        if rt_row:  # اگر ردیف بود
            user_id_val = rt_row["user_id"]  # user_id
        if user_id_val is not None:  # اگر user_id داشت
            sel_user = UserTable.__table__.select().where(UserTable.id == user_id_val)  # select user
            user = await database.fetch_one(sel_user)  # گرفتن user
            if user:  # اگر وجود داشت
                del_all = DeviceTokenTable.__table__.delete().where(  # delete all tokens
                    DeviceTokenTable.user_phone == _normalize_phone(user["phone"])  # شرط شماره
                )  # پایان
                await database.execute(del_all)  # اجرا

    return unified_response("ok", "LOGOUT", "refresh token revoked and device tokens removed", {})  # پاسخ

# -------------------- Push endpoints --------------------

@app.post("/push/register")  # ثبت توکن پوش
async def register_push_token(body: PushRegister, request: Request):  # ثبت توکن
    now = datetime.now(timezone.utc)  # زمان فعلی
    norm_phone = _normalize_phone(body.user_phone) if body.user_phone else None  # نرمال‌سازی شماره
    sel = DeviceTokenTable.__table__.select().where(  # select by token
        DeviceTokenTable.token == body.token  # شرط
    )  # پایان
    row = await database.fetch_one(sel)  # گرفتن ردیف

    if row is None:  # اگر نبود
        ins = DeviceTokenTable.__table__.insert().values(  # insert
            token=body.token,  # token
            role=body.role,  # role
            platform=body.platform,  # platform
            user_phone=norm_phone,  # phone
            created_at=now,  # created
            updated_at=now  # updated
        )  # پایان values
        await database.execute(ins)  # اجرا
    else:  # اگر بود
        upd = DeviceTokenTable.__table__.update().where(  # update
            DeviceTokenTable.id == row["id"]  # شرط
        ).values(  # values
            role=body.role,  # role
            platform=body.platform,  # platform
            user_phone=(norm_phone or row["user_phone"]),  # phone
            updated_at=now  # updated
        )  # پایان values
        await database.execute(upd)  # اجرا

    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": body.role})  # پاسخ

@app.post("/push/unregister")  # لغو ثبت توکن پوش
async def unregister_push_token(body: PushUnregister):  # تابع
    delq = DeviceTokenTable.__table__.delete().where(  # delete
        DeviceTokenTable.token == body.token  # شرط
    )  # پایان
    await database.execute(delq)  # اجرا
    return unified_response("ok", "TOKEN_UNREGISTERED", "unregistered", {})  # پاسخ

# -------------------- Auth / User --------------------

@app.get("/users/exists")  # بررسی وجود کاربر
async def user_exists(phone: str):  # تابع
    q = select(func.count()).select_from(UserTable).where(  # count
        UserTable.phone == phone  # شرط
    )  # پایان where
    count = await database.fetch_val(q)  # اجرا
    exists = bool(count and int(count) > 0)  # bool
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ

@app.post("/register_user")  # ثبت‌نام کاربر
async def register_user(user: UserRegisterRequest):  # تابع
    q = select(func.count()).select_from(UserTable).where(  # count
        UserTable.phone == user.phone  # شرط
    )  # پایان
    count = await database.fetch_val(q)  # اجرا
    if count and int(count) > 0:  # اگر وجود داشت
        raise HTTPException(status_code=400, detail="User already exists")  # 400

    password_hash = bcrypt_hash_password(user.password)  # هش رمز
    ins = UserTable.__table__.insert().values(  # insert
        phone=user.phone,  # شماره
        password_hash=password_hash,  # هش
        address=(user.address or "").strip(),  # آدرس
        name="",  # نام
        car_list=[]  # لیست خودرو
    )  # پایان insert
    await database.execute(ins)  # اجرا
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ

@app.post("/login")  # ورود کاربر
async def login_user(user: UserLoginRequest, request: Request):  # تابع
    now = datetime.now(timezone.utc)  # اکنون
    client_ip = get_client_ip(request)  # ip (فعلاً استفاده نشده)

    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # select user
    db_user = await database.fetch_one(sel_user)  # گرفتن user
    if not db_user:  # اگر نبود
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})  # 404

    if not verify_password_secure(user.password, db_user["password_hash"]):  # بررسی رمز
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD"})  # 401

    access_token = create_access_token(db_user["phone"])  # ساخت access
    refresh_token = create_refresh_token()  # ساخت refresh
    refresh_hash = hash_refresh_token(refresh_token)  # هش refresh
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # انقضای refresh

    ins_rt = RefreshTokenTable.__table__.insert().values(  # insert refresh
        user_id=db_user["id"],  # user_id
        token_hash=refresh_hash,  # hash
        expires_at=refresh_exp,  # exp
        revoked=False  # revoked
    )  # پایان insert
    await database.execute(ins_rt)  # اجرا

    return {  # پاسخ
        "status": "ok",  # status
        "access_token": access_token,  # access
        "refresh_token": refresh_token,  # refresh
        "user": {  # user
            "phone": db_user["phone"],  # phone
            "address": db_user["address"] or "",  # address
            "name": db_user["name"] or ""  # name
        }  # پایان user
    }  # پایان پاسخ

# -------------------- Orders --------------------

@app.post("/order")  # ثبت سفارش
async def create_order(order: OrderRequest, request: Request):  # تابع
    auth_phone = get_auth_phone(request, fallback_phone=order.user_phone, enforce=False)  # احراز
    if auth_phone != order.user_phone:  # اگر mismatch
        raise HTTPException(status_code=403, detail="forbidden")  # 403

    ins = RequestTable.__table__.insert().values(  # insert order
        user_phone=order.user_phone,  # شماره
        latitude=order.location.latitude,  # lat
        longitude=order.location.longitude,  # lng
        car_list=[car.dict() for car in order.car_list],  # لیست خودرو
        address=order.address.strip(),  # آدرس
        home_number=(order.home_number or "").strip(),  # پلاک
        service_type=order.service_type,  # سرویس
        price=order.price,  # قیمت
        request_datetime=order.request_datetime,  # زمان ثبت
        status="NEW",  # وضعیت
        payment_type=order.payment_type.strip().lower(),  # پرداخت
        service_place=order.service_place.strip().lower()  # محل
    ).returning(RequestTable.id)  # returning id

    row = await database.fetch_one(ins)  # اجرا
    new_id = row["id"] if row else None  # id جدید

    try:  # محافظ نوتیف مدیر
        await notify_managers(  # ارسال به مدیرها
            title="سفارش جدید",  # عنوان
            body=f"سفارش جدید ثبت شد: {order.service_type}",  # متن
            data={"order_id": int(new_id or 0), "user_phone": _normalize_phone(order.user_phone), "service_type": order.service_type, "status": "NEW"}  # دیتا
        )  # پایان notify_managers
    except Exception as e:  # خطا
        logger.error(f"notify_managers(create_order) failed: {e}")  # لاگ

    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # پاسخ

@app.post("/cancel_order")  # لغو سفارش
async def cancel_order(cancel: CancelRequest, request: Request):  # تابع
    auth_phone = get_auth_phone(request, fallback_phone=cancel.user_phone, enforce=False)  # احراز
    if auth_phone != cancel.user_phone:  # اگر mismatch
        raise HTTPException(status_code=403, detail="forbidden")  # 403

    upd = (  # update
        RequestTable.__table__.update()  # update
        .where(  # where
            (RequestTable.user_phone == cancel.user_phone) &  # user_phone
            (RequestTable.service_type == cancel.service_type) &  # service_type
            (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))  # فعال‌ها
        )  # پایان where
        .values(status="CANCELED", scheduled_start=None)  # values
        .returning(RequestTable.id, RequestTable.driver_phone)  # returning
    )  # پایان upd
    rows = await database.fetch_all(upd)  # اجرا
    if rows:  # اگر داشت
        ids = [int(r["id"]) for r in rows]  # لیست id
        driver_phones = list({(r["driver_phone"] or "").strip() for r in rows if r["driver_phone"]})  # شماره‌های سرویس‌دهنده
        try:  # محافظ نوتیف مدیر
            await notify_managers(  # ارسال به مدیرها
                title="لغو سفارش",  # عنوان
                body=f"سفارش توسط کاربر لغو شد ({cancel.service_type})",  # متن
                data={"order_ids": ",".join(str(x) for x in ids), "user_phone": _normalize_phone(cancel.user_phone), "service_type": cancel.service_type, "status": "CANCELED"}  # دیتا
            )  # پایان notify_managers
            for dp in driver_phones:  # حلقه روی سرویس‌دهنده‌ها
                await notify_managers(  # ارسال هدفمند
                    title="لغو سفارش",  # عنوان
                    body=f"سفارش شما لغو شد (id={ids[0]})",  # متن
                    data={"order_ids": ",".join(str(x) for x in ids), "status": "CANCELED"},  # دیتا
                    target_phone=dp  # هدف
                )  # پایان notify_managers
        except Exception as e:  # خطا
            logger.error(f"notify_managers(cancel_order) failed: {e}")  # لاگ
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # پاسخ

    raise HTTPException(status_code=404, detail="active order not found")  # 404

@app.get("/user_active_services/{user_phone}")  # سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str, request: Request):  # تابع
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)  # احراز
    if auth_phone != user_phone:  # اگر mismatch
        raise HTTPException(status_code=403, detail="forbidden")  # 403

    sel = RequestTable.__table__.select().where(  # select
        (RequestTable.user_phone == user_phone) &  # user_phone
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))  # فعال
    )  # پایان where
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # تبدیل
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # پاسخ

@app.get("/user_orders/{user_phone}")  # لیست سفارش‌ها
async def get_user_orders(user_phone: str, request: Request):  # تابع
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)  # احراز
    if auth_phone != user_phone:  # اگر mismatch
        raise HTTPException(status_code=403, detail="forbidden")  # 403

    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # select
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # تبدیل
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # پاسخ

# -------------------- Scheduling --------------------

@app.get("/provider/{provider_phone}/free_hours")  # ساعات آزاد
async def get_free_hours(provider_phone: str, date: str, work_start: int = 8, work_end: int = 20, limit: int = 24):  # تابع
    d = datetime.fromisoformat(date).date()  # تاریخ
    provider = provider_phone.strip()  # شماره
    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)  # شروع روز UTC
    day_end = datetime(d.year, d.month, d.day, work_end, 0, tzinfo=timezone.utc)  # پایان روز UTC

    results: List[str] = []  # لیست خروجی
    cur = day_start  # شروع
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:  # حلقه ساعتی
        s, e = cur, cur + timedelta(hours=1)  # بازه
        if await provider_is_free(provider, s, e):  # اگر آزاد
            results.append(s.isoformat())  # افزودن ISO
        cur += timedelta(hours=1)  # حرکت
    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})  # پاسخ

@app.get("/busy_slots")  # ساعات مشغول
async def get_busy_slots(provider_phone: str, date: str, exclude_order_id: Optional[int] = None):  # تابع
    d = datetime.fromisoformat(date).date()  # تاریخ
    provider = provider_phone.strip()  # شماره

    day_start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)  # شروع روز
    day_end = day_start + timedelta(days=1)  # پایان روز

    sel_sched = ScheduleSlotTable.__table__.select().where(  # select schedule slots
        (ScheduleSlotTable.slot_start >= day_start) &  # شروع
        (ScheduleSlotTable.slot_start < day_end) &  # پایان
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &  # وضعیت
        (ScheduleSlotTable.provider_phone == provider)  # provider
    )  # پایان where
    if exclude_order_id is not None:  # اگر exclude بود
        sel_sched = sel_sched.where(ScheduleSlotTable.request_id != exclude_order_id)  # افزودن شرط

    rows_sched = await database.fetch_all(sel_sched)  # اجرا

    sel_app = AppointmentTable.__table__.select().where(  # select appointments
        (AppointmentTable.start_time >= day_start) &  # شروع
        (AppointmentTable.start_time < day_end) &  # پایان
        (AppointmentTable.status == "BOOKED") &  # booked
        (AppointmentTable.provider_phone == provider)  # provider
    )  # پایان where
    rows_app = await database.fetch_all(sel_app)  # اجرا

    busy: set[str] = set()  # مجموعه
    for r in rows_sched:  # حلقه
        busy.add(r["slot_start"].isoformat())  # افزودن
    for r in rows_app:  # حلقه
        busy.add(r["start_time"].isoformat())  # افزودن

    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": sorted(busy)})  # پاسخ

# -------------------- Admin workflow --------------------

@app.get("/admin/requests/active")  # لیست درخواست‌های فعال مدیر
async def admin_active_requests(request: Request):  # تابع
    require_admin(request)  # احراز مدیر
    active = ["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]  # وضعیت‌های فعال
    sel = RequestTable.__table__.select().where(RequestTable.status.in_(active)).order_by(RequestTable.id.desc())  # select
    rows = await database.fetch_all(sel)  # اجرا
    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": [dict(r) for r in rows]})  # پاسخ

@app.post("/order/{order_id}/propose_slots")  # پیشنهاد زمان‌ها
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):  # تابع
    require_admin(request)  # احراز مدیر
    provider = body.provider_phone.strip()  # provider
    accepted: List[str] = []  # لیست پذیرفته‌شده

    for s in body.slots[:3]:  # حداکثر ۳
        start = parse_iso(s)  # پارس UTC
        end = start + timedelta(hours=1)  # پایان
        if await provider_is_free(provider, start, end):  # اگر آزاد
            await database.execute(  # درج slot
                ScheduleSlotTable.__table__.insert().values(
                    request_id=order_id,
                    provider_phone=provider,
                    slot_start=start,
                    status="PROPOSED",
                    created_at=datetime.now(timezone.utc)
                )
            )
            accepted.append(start.isoformat())  # افزودن

    if accepted:  # اگر چیزی ثبت شد
        await database.execute(  # آپدیت درخواست
            RequestTable.__table__.update()
            .where(RequestTable.id == order_id)
            .values(status="WAITING", driver_phone=provider, scheduled_start=None)
        )
        try:  # محافظ اعلان کاربر
            sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # select
            req = await database.fetch_one(sel_req)  # گرفتن
            if req:  # اگر هست
                await notify_user(  # اعلان به کاربر
                    phone=req["user_phone"],
                    title="پیشنهاد زمان",
                    body="زمان‌های پیشنهادی برای سفارش شما ثبت شد. لطفاً یکی را تأیید کنید.",
                    data={"order_id": int(order_id), "status": "WAITING", "accepted": ",".join(accepted), "provider_phone": _normalize_phone(provider)}
                )
        except Exception as e:  # خطا
            logger.error(f"notify_user(propose_slots) failed: {e}")  # لاگ

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # پاسخ

@app.post("/admin/order/{order_id}/price")  # ثبت قیمت/توافق توسط مدیر
async def admin_set_price(order_id: int, body: PriceBody, request: Request):  # تابع
    require_admin(request)  # احراز مدیر

    sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # select request
    req_row = await database.fetch_one(sel_req)  # گرفتن سفارش
    if not req_row:  # اگر نبود
        raise HTTPException(status_code=404, detail="order not found")  # 404

    exec_dt: Optional[datetime] = None  # زمان اجرا
    new_status = "PRICE_REJECTED"  # وضعیت پیش‌فرض عدم توافق

    if body.agree:  # اگر توافق
        if not body.exec_time or not str(body.exec_time).strip():  # اگر زمان اجرا نداشت
            raise HTTPException(status_code=400, detail="exec_time required when agree=true")  # 400
        exec_dt = parse_iso(body.exec_time)  # پارس UTC
        new_status = "IN_PROGRESS"  # وضعیت پس از توافق

    upd = (  # update
        RequestTable.__table__.update()
        .where(RequestTable.id == order_id)
        .values(
            price=int(body.price),
            status=new_status,
            execution_start=exec_dt
        )
        .returning(RequestTable.id, RequestTable.price, RequestTable.status, RequestTable.execution_start)
    )
    saved = await database.fetch_one(upd)  # اجرا

    try:  # اعلان کاربر
        if body.agree:  # توافق
            await notify_user(
                phone=req_row["user_phone"],
                title="توافق قیمت",
                body=f"قیمت {int(body.price)} ثبت شد. زمان اجرا: {exec_dt.isoformat() if exec_dt else ''}",
                data={"order_id": int(order_id), "status": new_status, "price": int(body.price), "execution_start": exec_dt.isoformat() if exec_dt else ""}
            )
        else:  # عدم توافق
            await notify_user(
                phone=req_row["user_phone"],
                title="عدم توافق قیمت",
                body="قیمت مورد توافق قرار نگرفت.",
                data={"order_id": int(order_id), "status": new_status, "price": int(body.price)}
            )
    except Exception as e:  # خطا
        logger.error(f"notify_user(admin_set_price) failed: {e}")  # لاگ

    return unified_response(
        "ok",
        "PRICE_SET",
        "price/status updated",
        {
            "order_id": int(saved["id"]) if saved else int(order_id),
            "price": int(saved["price"]) if saved else int(body.price),
            "status": str(saved["status"]) if saved else new_status,
            "execution_start": (saved["execution_start"].isoformat() if (saved and saved["execution_start"]) else None)
        }
    )

# -------------------- Confirm / Finish workflow --------------------

@app.post("/order/{order_id}/confirm_slot")  # تأیید زمان توسط کاربر
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):  # تابع
    start = parse_iso(body.slot)  # شروع UTC
    end = start + timedelta(hours=1)  # پایان UTC

    sel_slot = ScheduleSlotTable.__table__.select().where(  # select slot
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.status == "PROPOSED") &
        (ScheduleSlotTable.slot_start == start)
    )
    slot = await database.fetch_one(sel_slot)  # گرفتن
    if not slot:  # اگر نبود
        raise HTTPException(status_code=404, detail="slot not found")  # 404

    if not await provider_is_free(slot["provider_phone"], start, end):  # اگر مشغول شد
        raise HTTPException(status_code=409, detail="slot busy")  # 409

    await database.execute(  # قبول slot
        ScheduleSlotTable.__table__.update()
        .where(ScheduleSlotTable.id == slot["id"])
        .values(status="ACCEPTED")
    )

    await database.execute(  # رد بقیه slotها
        ScheduleSlotTable.__table__.update()
        .where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED"))
        .values(status="REJECTED")
    )

    await database.execute(  # ساخت appointment
        AppointmentTable.__table__.insert().values(
            provider_phone=slot["provider_phone"],
            request_id=order_id,
            start_time=start,
            end_time=end,
            status="BOOKED",
            created_at=datetime.now(timezone.utc)
        )
    )

    await database.execute(  # آپدیت درخواست
        RequestTable.__table__.update()
        .where(RequestTable.id == order_id)
        .values(scheduled_start=start, status="ASSIGNED", driver_phone=slot["provider_phone"])
    )

    try:  # اعلان‌ها
        sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # select request
        req = await database.fetch_one(sel_req)  # گرفتن
        if req:  # اگر بود
            await notify_user(  # اعلان به کاربر
                phone=req["user_phone"],
                title="زمان تأیید شد",
                body="زمان انتخابی شما ثبت شد.",
                data={"order_id": int(order_id), "status": "ASSIGNED", "scheduled_start": start.isoformat(), "provider_phone": _normalize_phone(slot["provider_phone"])}
            )
        await notify_managers(  # اعلان به مدیر/سرویس‌دهنده
            title="تأیید زمان توسط کاربر",
            body=f"زمان سفارش {order_id} تأیید شد: {start.isoformat()}",
            data={"order_id": int(order_id), "status": "ASSIGNED", "scheduled_start": start.isoformat(), "provider_phone": _normalize_phone(slot["provider_phone"])},
            target_phone=_normalize_phone(slot["provider_phone"])
        )
    except Exception as e:  # خطا
        logger.error(f"notify(confirm_slot) failed: {e}")  # لاگ

    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})  # پاسخ

@app.post("/order/{order_id}/finish")  # اتمام کار توسط مدیر
async def finish_order(order_id: int, request: Request):  # تابع
    require_admin(request)  # احراز مدیر

    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # select
    req = await database.fetch_one(sel)  # گرفتن
    if not req:  # اگر نبود
        raise HTTPException(status_code=404, detail="order not found")  # 404

    now_iso = datetime.now(timezone.utc).isoformat()  # زمان پایان

    await database.execute(  # آپدیت
        RequestTable.__table__.update()
        .where(RequestTable.id == order_id)
        .values(status="FINISH", finish_datetime=now_iso)
    )

    try:  # اعلان‌ها
        await notify_user(  # اعلان به کاربر
            phone=req["user_phone"],
            title="اتمام کار",
            body="سفارش شما انجام شد.",
            data={"order_id": int(order_id), "status": "FINISH"}
        )
        await notify_managers(  # اعلان به مدیرها
            title="اتمام کار ثبت شد",
            body=f"سفارش {order_id} به اتمام رسید.",
            data={"order_id": int(order_id), "status": "FINISH"},
            target_phone=_normalize_phone(req.get("driver_phone") or "")
        )
    except Exception as e:  # خطا
        logger.error(f"notify(finish_order) failed: {e}")  # لاگ

    return unified_response("ok", "ORDER_FINISHED", "order finished", {"order_id": order_id, "status": "FINISH"})  # پاسخ

# -------------------- Profile --------------------

@app.post("/user/profile")  # ذخیره پروفایل
async def update_profile(body: UserProfileUpdate, request: Request):  # تابع
    auth_phone = get_auth_phone(request, fallback_phone=body.phone, enforce=False)  # احراز
    if auth_phone != body.phone:  # اگر mismatch
        raise HTTPException(status_code=403, detail="forbidden")  # 403

    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # select
    user = await database.fetch_one(sel)  # گرفتن
    if not user:  # اگر نبود
        raise HTTPException(status_code=404, detail="User not found")  # 404

    await database.execute(  # update
        UserTable.__table__.update()
        .where(UserTable.phone == body.phone)
        .values(name=body.name.strip(), address=body.address.strip())
    )

    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # پاسخ

@app.get("/user/profile/{phone}")  # دریافت پروفایل
async def get_user_profile(phone: str, request: Request):  # تابع
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)  # احراز
    if auth_phone != phone:  # اگر mismatch
        raise HTTPException(status_code=403, detail="forbidden")  # 403

    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # select
    user = await database.fetch_one(sel)  # گرفتن
    if not user:  # اگر نبود
        raise HTTPException(status_code=404, detail="User not found")  # 404

    return unified_response("ok", "PROFILE_FETCHED", "profile data", {"phone": user["phone"], "name": user["name"] or "", "address": user["address"] or ""})  # پاسخ

# -------------------- Debug --------------------

@app.get("/debug/users")  # دیباگ کاربران
async def debug_users():  # تابع
    rows = await database.fetch_all(UserTable.__table__.select())  # select
    out = []  # خروجی
    for r in rows:  # حلقه
        out.append({"id": r["id"], "phone": r["phone"], "name": r["name"], "address": r["address"]})  # افزودن
    return out  # بازگشت
# -------------------- End of server/main.py --------------------
