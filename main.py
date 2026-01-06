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
    ForeignKey, Index, select, func, and_, or_, text, UniqueConstraint  # ابزارها  # or_=عملگر OR برای جستجو روی raw/norm
)  # پایان import
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

def _normalize_phone(p: str) -> str:  # نرمال‌سازی شماره (یکسان‌سازی برای جلوگیری از رزرو دوباره)
    raw = str(p or "").strip()  # raw=رشته ورودی + trim
    if not raw:  # شرط=ورودی خالی است
        return ""  # خروجی=رشته خالی

    cleaned = "".join(ch for ch in raw if ch.isdigit() or ch == "+")  # cleaned=فقط رقم‌ها و + باقی بماند
    if not cleaned:  # شرط=بعد از پاکسازی خالی شد
        return ""  # خروجی=خالی

    if cleaned.startswith("+"):  # شرط=شماره با + شروع شده
        cleaned = cleaned[1:]  # cleaned=حذف + ابتدای شماره

    if cleaned.startswith("00"):  # شرط=شماره با 00 شروع شده (مثل 0098...)
        cleaned = cleaned[2:]  # cleaned=حذف 00

    digits = "".join(ch for ch in cleaned if ch.isdigit())  # digits=فقط رقم‌ها (بدون +)
    if not digits:  # شرط=خالی
        return ""  # خروجی=خالی

    if digits.startswith("98") and len(digits) >= 12:  # شرط=پیشوند ایران 98 و طول کافی
        tail10 = digits[-10:]  # tail10=آخرین ۱۰ رقم شماره
        if tail10.startswith("9"):  # شرط=موبایل ایران با 9 شروع می‌شود
            return "0" + tail10  # خروجی=فرمت واحد ایران مثل 0919...

    return digits  # خروجی=شماره نهایی به صورت فقط رقم
    
def get_admin_provider_phone(request: Request) -> str:  # تابع=گرفتن شماره سرویس‌دهنده از ادمین (توکن یا env)
    token = extract_bearer_token(request)  # token=توکن Bearer
    if token:  # شرط=توکن موجود است
        payload = decode_access_token(token)  # payload=دیکود توکن
        sub = str((payload or {}).get("sub") or "")  # sub=شماره داخل توکن
        norm = _normalize_phone(sub)  # norm=شماره نرمال
        if norm and norm in ADMIN_PHONES_SET:  # شرط=شماره معتبر و داخل لیست مدیران
            return norm  # خروجی=شماره مدیر به عنوان سرویس‌دهنده

    # fallback: استفاده از اولین شماره موجود در env  # توضیح=برای حالتی که bearer ندارید
    if ADMIN_PHONES_SET:  # شرط=لیست مدیران خالی نیست
        return sorted(list(ADMIN_PHONES_SET))[0]  # خروجی=اولین شماره مدیر به عنوان سرویس‌دهنده

    raise HTTPException(status_code=400, detail="admin provider phone not available")  # خطا=شماره سرویس‌دهنده قابل استخراج نیست
    
def _parse_admin_phones(s: str) -> set[str]:  # پارس شماره مدیران
    out = set()  # مجموعه خروجی
    for part in (s or "").split(","):  # جداکردن با کاما
        vv = _normalize_phone(part.strip())  # نرمال‌سازی
        if vv:  # شرط=خالی نبودن
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
if not logger.handlers:  # شرط=هندلر نداشت
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
        if raw.endswith("Z"):  # حالت Z
            raw = raw.replace("Z", "+00:00")  # تبدیل به آفست
        dt = datetime.fromisoformat(raw)  # پارس
        if dt.tzinfo is None:  # شرط=بدون timezone
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

class ProposedSlotsRequest(BaseModel):  # مدل=پیشنهاد زمان
    slots: List[str]  # slots=لیست ISO UTC
    provider_phone: Optional[str] = None  # provider_phone=اختیاری برای سازگاری (دیگر از UI لازم نیست)
    
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

def get_client_ip(request: Request) -> str:  # گرفتن IP کلاینت
    xff = request.headers.get("x-forwarded-for", "")  # xff
    if xff:  # اگر بود
        return xff.split(",")[0].strip()  # اولین ip
    return request.client.host or "unknown"  # ip

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

def order_push_data(  # تابع=ساخت دیتای استاندارد برای پوش (سازگار با اپ کاربر)
    msg_type: str,  # ورودی=نوع پیام (type)
    order_id: int,  # ورودی=شناسه سفارش
    status: str,  # ورودی=وضعیت سفارش
    service_type: str = "",  # ورودی=نوع سرویس
    scheduled_start: Optional[datetime] = None,  # ورودی=زمان بازدید (UTC)
    execution_start: Optional[datetime] = None,  # ورودی=زمان اجرا (UTC)
    price: Optional[int] = None  # ورودی=قیمت
) -> dict:  # خروجی=دیکشنری قابل ارسال در FCM data
    data = {  # data=دیکشنری خروجی
        "type": str(msg_type or "").strip(),  # type=نوع پیام
        "order_id": str(int(order_id)),  # order_id=به رشته (برای FCM)
        "status": str(status or "").strip()  # status=وضعیت
    }  # پایان data
    if service_type:  # شرط=سرویس موجود است
        data["service_type"] = str(service_type).strip()  # service_type=ثبت سرویس
    if scheduled_start is not None:  # شرط=زمان بازدید موجود است
        data["scheduled_start"] = scheduled_start.astimezone(timezone.utc).isoformat()  # scheduled_start=ISO UTC
    if execution_start is not None:  # شرط=زمان اجرا موجود است
        data["execution_start"] = execution_start.astimezone(timezone.utc).isoformat()  # execution_start=ISO UTC
    if price is not None:  # شرط=قیمت موجود است
        data["price"] = str(int(price))  # price=به رشته (برای FCM)
    return data  # بازگشت=data

async def _send_fcm_legacy(tokens: List[str], title: str, body: str, data: dict):  # ارسال FCM legacy به صورت Data-only
    if not tokens:  # شرط=توکن‌ها خالی
        return  # خروج
    if not FCM_SERVER_KEY:  # شرط=کلید FCM خالی
        logger.error("FCM_SERVER_KEY is empty")  # لاگ=کلید خالی
        return  # خروج

    headers = {  # headers=هدرها
        "Authorization": f"key={FCM_SERVER_KEY}",  # Authorization=کلید legacy
        "Content-Type": "application/json"  # Content-Type=json
    }  # پایان headers

    merged = dict(data or {})  # merged=کپی دیتا
    merged["title"] = str(title or "")  # title=عنوان داخل دیتا
    merged["body"] = str(body or "")  # body=متن داخل دیتا

    payload = {  # payload=بدنه درخواست
        "registration_ids": tokens,  # registration_ids=توکن‌ها
        "priority": "high",  # priority=اولویت بالا
        "data": _to_fcm_data(merged)  # data=فقط دیتا (بدون notification)
    }  # پایان payload

    async with httpx.AsyncClient(timeout=10.0) as client:  # client=کلاینت async
        resp = await client.post("https://fcm.googleapis.com/fcm/send", headers=headers, json=payload)  # ارسال
    if resp.status_code != 200:  # شرط=عدم موفقیت
        logger.error(f"FCM legacy send failed HTTP_{resp.status_code} body={resp.text}")  # لاگ=خطا
        
async def _send_fcm_v1_single(token: str, title: str, body: str, data: dict):  # تابع=ارسال FCM v1 تک‌توکن به صورت Data-only
    access = _get_oauth2_token_for_fcm()  # access=گرفتن توکن OAuth برای FCM v1
    if not access:  # شرط=توکن OAuth موجود نیست
        logger.error("FCM v1 oauth token not available")  # لاگ=عدم دسترسی به OAuth
        return  # خروج
    if not FCM_PROJECT_ID:  # شرط=شناسه پروژه Firebase تنظیم نشده
        logger.error("FCM_PROJECT_ID is empty")  # لاگ=شناسه پروژه خالی است
        return  # خروج

    headers = {  # headers=هدرهای درخواست HTTP
        "Authorization": f"Bearer {access}",  # Authorization=توکن Bearer
        "Content-Type": "application/json"  # Content-Type=نوع محتوا JSON
    }  # پایان headers

    merged = dict(data or {})  # merged=کپی از data برای دستکاری امن
    merged["title"] = str(title or "")  # title=قرار دادن عنوان داخل data (برای Data-only)
    merged["body"] = str(body or "")  # body=قرار دادن متن داخل data (برای Data-only)

    msg = {  # msg=بدنه پیام برای FCM v1
        "message": {  # message=شیء پیام
            "token": str(token or "").strip(),  # token=توکن دستگاه مقصد
            "android": {  # android=تنظیمات اندروید
                "priority": "HIGH"  # priority=اولویت بالا برای دریافت سریع/پس‌زمینه
            },  # پایان android
            "data": _to_fcm_data(merged)  # data=ارسال فقط data (بدون notification) برای اجرای onMessageReceived
        }  # پایان message
    }  # پایان msg

    url = f"https://fcm.googleapis.com/v1/projects/{FCM_PROJECT_ID}/messages:send"  # url=آدرس endpoint ارسال پیام v1
    async with httpx.AsyncClient(timeout=10.0) as client:  # client=کلاینت HTTP async
        resp = await client.post(url, headers=headers, json=msg)  # resp=ارسال درخواست POST با بدنه JSON
    if resp.status_code not in (200, 201):  # شرط=موفق نبودن ارسال
        logger.error(f"FCM v1 send failed HTTP_{resp.status_code} body={resp.text}")  # لاگ=خطا با بدنه پاسخ
        
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

# -------------------- Admin workflow (alias fix) --------------------  # بخش=ادمین (رفع 404 با alias)
@app.get("/admin/requests/active")  # مسیر=لیست درخواست‌های فعال مدیر (بدون اسلش)
@app.get("/admin/requests/active/")  # مسیر=لیست درخواست‌های فعال مدیر (با اسلش)  # توضیح=پوشش هر دو حالت
async def admin_active_requests(request: Request):  # تابع=درخواست‌های فعال
    require_admin(request)  # احراز=مدیر
    active = ["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]  # active=وضعیت‌های فعال
    sel = RequestTable.__table__.select().where(RequestTable.status.in_(active)).order_by(RequestTable.id.desc())  # sel=کوئری انتخاب
    rows = await database.fetch_all(sel)  # rows=اجرای کوئری
    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": [dict(r) for r in rows]})  # پاسخ=لیست

# -------------------- Debug: list routes --------------------  # بخش=دیباگ لیست مسیرها
@app.get("/debug/routes")  # مسیر=لیست مسیرهای ثبت‌شده
def debug_routes():  # تابع=بازگرداندن مسیرها
    out = []  # out=لیست خروجی
    for r in app.router.routes:  # حلقه=روی تمام routeها
        path = getattr(r, "path", "")  # path=مسیر
        methods = sorted(list(getattr(r, "methods", []) or []))  # methods=متدها
        name = getattr(r, "name", "")  # name=نام
        out.append({"path": path, "methods": methods, "name": name})  # افزودن=آیتم
    return {"items": out}  # پاسخ=لیست

# -------------------- Startup / Shutdown --------------------

@app.on_event("startup")  # رویداد startup
async def startup():  # تابع startup
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # ساخت engine sync
    Base.metadata.create_all(engine)  # ساخت جداول
    with engine.begin() as conn:  # کانکشن
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # افزودن ستون
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS execution_start TIMESTAMPTZ NULL;"))  # افزودن ستون
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_schedule_slots_provider_start_active ON schedule_slots (provider_phone, slot_start) WHERE status IN ('PROPOSED','ACCEPTED');"))  # افزودن=ایندکس یکتا برای جلوگیری از رزرو همزمان زمان‌های پیشنهادی
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
    raw = (body.refresh_token or "").strip()  # raw=گرفتن رفرش
    if not raw:  # شرط=خالی
        raise HTTPException(status_code=400, detail="refresh_token required")  # خطا=۴۰۰
    token_hash = hash_refresh_token(raw)  # token_hash=هش رفرش
    sel = RefreshTokenTable.__table__.select().where(  # sel=کوئری خواندن ردیف رفرش
        (RefreshTokenTable.token_hash == token_hash)  # شرط=هش برابر
    )  # پایان where
    row = await database.fetch_one(sel)  # row=گرفتن ردیف
    if not row:  # شرط=نبود
        raise HTTPException(status_code=401, detail="invalid refresh token")  # خطا=۴۰۱
    if row["revoked"]:  # شرط=ابطال شده
        raise HTTPException(status_code=401, detail="refresh token revoked")  # خطا=۴۰۱
    now = datetime.now(timezone.utc)  # now=زمان فعلی UTC
    exp = row["expires_at"]  # exp=زمان انقضا
    if exp is None or exp <= now:  # شرط=منقضی
        raise HTTPException(status_code=401, detail="refresh token expired")  # خطا=۴۰۱
    user_id = row["user_id"]  # user_id=شناسه کاربر
    sel_u = UserTable.__table__.select().where(UserTable.id == user_id)  # sel_u=کوئری کاربر
    user = await database.fetch_one(sel_u)  # user=گرفتن کاربر
    if not user:  # شرط=کاربر نبود
        raise HTTPException(status_code=401, detail="user not found")  # خطا=۴۰۱
    access = create_access_token(user["phone"])  # access=ساخت access
    return unified_response("ok", "ACCESS_REFRESHED", "access token refreshed", {"access_token": access})  # پاسخ=توکن جدید

@app.post("/logout")  # خروج کاربر
async def logout_user(body: LogoutRequest):  # تابع خروج
    if not body.refresh_token:  # شرط=رفرش نبود
        raise HTTPException(status_code=400, detail="refresh_token required")  # خطا=۴۰۰

    token_hash = hash_refresh_token(body.refresh_token)  # token_hash=هش رفرش
    sel_rt = RefreshTokenTable.__table__.select().where(  # sel_rt=کوئری رفرش
        RefreshTokenTable.token_hash == token_hash  # شرط=هش برابر
    )  # پایان where
    rt_row = await database.fetch_one(sel_rt)  # rt_row=گرفتن ردیف

    upd = RefreshTokenTable.__table__.update().where(  # upd=کوئری ابطال
        RefreshTokenTable.token_hash == token_hash  # شرط=هش
    ).values(revoked=True)  # values=revoked
    await database.execute(upd)  # اجرا=ابطال

    if body.device_token and body.device_token.strip():  # شرط=توکن دستگاه داده شد
        delq = DeviceTokenTable.__table__.delete().where(  # delq=حذف توکن دستگاه
            DeviceTokenTable.token == body.device_token.strip()  # شرط=توکن
        )  # پایان delete
        await database.execute(delq)  # اجرا=حذف
    else:  # حالت=توکن دستگاه نداد
        user_id_val = None  # user_id_val=پیش‌فرض
        if rt_row:  # شرط=ردیف رفرش داشت
            user_id_val = rt_row["user_id"]  # user_id_val=شناسه کاربر
        if user_id_val is not None:  # شرط=شناسه موجود
            sel_user = UserTable.__table__.select().where(UserTable.id == user_id_val)  # sel_user=کوئری کاربر
            user = await database.fetch_one(sel_user)  # user=گرفتن کاربر
            if user:  # شرط=کاربر موجود
                del_all = DeviceTokenTable.__table__.delete().where(  # del_all=حذف همه توکن‌های آن کاربر
                    DeviceTokenTable.user_phone == _normalize_phone(user["phone"])  # شرط=شماره
                )  # پایان delete
                await database.execute(del_all)  # اجرا=حذف

    return unified_response("ok", "LOGOUT", "refresh token revoked and device tokens removed", {})  # پاسخ=خروج

# -------------------- Push endpoints --------------------

@app.post("/push/register")  # ثبت توکن پوش
async def register_push_token(body: PushRegister, request: Request):  # ثبت توکن
    now = datetime.now(timezone.utc)  # now=زمان فعلی
    norm_phone = _normalize_phone(body.user_phone) if body.user_phone else None  # norm_phone=نرمال شماره
    sel = DeviceTokenTable.__table__.select().where(  # sel=کوئری بر اساس token
        DeviceTokenTable.token == body.token  # شرط=token
    )  # پایان where
    row = await database.fetch_one(sel)  # row=گرفتن ردیف

    if row is None:  # شرط=توکن موجود نبود
        ins = DeviceTokenTable.__table__.insert().values(  # ins=insert
            token=body.token,  # token=توکن
            role=body.role,  # role=نقش
            platform=body.platform,  # platform=پلتفرم
            user_phone=norm_phone,  # user_phone=شماره
            created_at=now,  # created_at=اکنون
            updated_at=now  # updated_at=اکنون
        )  # پایان insert
        await database.execute(ins)  # اجرا=insert
    else:  # حالت=توکن موجود است
        upd = DeviceTokenTable.__table__.update().where(  # upd=update
            DeviceTokenTable.id == row["id"]  # شرط=id
        ).values(  # values=مقادیر
            role=body.role,  # role=نقش
            platform=body.platform,  # platform=پلتفرم
            user_phone=(norm_phone or row["user_phone"]),  # user_phone=اگر جدید نبود قبلی
            updated_at=now  # updated_at=اکنون
        )  # پایان values
        await database.execute(upd)  # اجرا=update

    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": body.role})  # پاسخ=ثبت شد

@app.post("/push/unregister")  # لغو ثبت توکن پوش
async def unregister_push_token(body: PushUnregister):  # تابع
    delq = DeviceTokenTable.__table__.delete().where(  # delq=delete
        DeviceTokenTable.token == body.token  # شرط=token
    )  # پایان delete
    await database.execute(delq)  # اجرا=حذف
    return unified_response("ok", "TOKEN_UNREGISTERED", "unregistered", {})  # پاسخ=لغو شد

# -------------------- Auth / User --------------------

@app.get("/users/exists")  # بررسی وجود کاربر
async def user_exists(phone: str):  # تابع
    raw = str(phone or "").strip()  # raw=شماره خام ورودی
    norm = _normalize_phone(raw)  # norm=شماره نرمال‌شده

    if not raw and not norm:  # شرط=شماره خالی
        return unified_response("ok", "USER_NOT_FOUND", "user exists check", {"exists": False})  # پاسخ=وجود ندارد

    conds = []  # conds=شرط‌ها
    if raw:  # شرط=raw موجود
        conds.append(UserTable.phone == raw)  # افزودن=شماره خام
    if norm and norm != raw:  # شرط=نرمال معتبر و متفاوت
        conds.append(UserTable.phone == norm)  # افزودن=شماره نرمال

    q = select(func.count()).select_from(UserTable).where(or_(*conds))  # q=کوئری count روی raw/norm
    count = await database.fetch_val(q)  # count=اجرای count
    exists = bool(count and int(count) > 0)  # exists=نتیجه وجود

    return unified_response(  # پاسخ
        "ok",  # status=ok
        "USER_EXISTS" if exists else "USER_NOT_FOUND",  # code=کد
        "user exists check",  # message=پیام
        {"exists": exists}  # data=نتیجه
    )  # پایان پاسخ
    
@app.post("/register_user")  # ثبت‌نام کاربر
async def register_user(user: UserRegisterRequest):  # تابع
    raw = str(user.phone or "").strip()  # raw=شماره خام
    norm = _normalize_phone(raw)  # norm=شماره نرمال‌شده
    canonical = norm or raw  # canonical=شماره نهایی ذخیره‌سازی (اولویت با نرمال)

    if not canonical:  # شرط=شماره خالی
        raise HTTPException(status_code=400, detail="phone required")  # خطا=۴۰۰

    conds = []  # conds=شرط‌ها
    if raw:  # شرط=raw موجود
        conds.append(UserTable.phone == raw)  # افزودن=شماره خام
    if norm and norm != raw:  # شرط=نرمال معتبر و متفاوت
        conds.append(UserTable.phone == norm)  # افزودن=شماره نرمال

    q = select(func.count()).select_from(UserTable).where(or_(*conds))  # q=count برای جلوگیری از ثبت تکراری
    count = await database.fetch_val(q)  # count=اجرای count
    if count and int(count) > 0:  # شرط=کاربر موجود
        raise HTTPException(status_code=400, detail="User already exists")  # خطا=۴۰۰

    password_hash = bcrypt_hash_password(user.password)  # password_hash=هش رمز
    ins = UserTable.__table__.insert().values(  # ins=insert user
        phone=canonical,  # phone=شماره ذخیره‌شده (canonical)
        password_hash=password_hash,  # password_hash=هش
        address=(user.address or "").strip(),  # address=آدرس
        name="",  # name=نام
        car_list=[]  # car_list=لیست خالی
    )  # پایان insert
    await database.execute(ins)  # اجرا=insert

    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": canonical})  # پاسخ=ثبت شد
    
@app.post("/login")  # مسیر=ورود کاربر
async def login_user(user: UserLoginRequest, request: Request):  # تابع=ورود
    now = datetime.now(timezone.utc)  # now=زمان فعلی UTC
    client_ip = get_client_ip(request)  # client_ip=آی‌پی کلاینت

    raw_phone = str(user.phone or "").strip()  # raw_phone=شماره خام ورودی
    phone_norm = _normalize_phone(raw_phone)  # phone_norm=شماره نرمال‌شده برای یکسان‌سازی

    # --- Login attempts: load or create row ---  # توضیح=مدیریت تعداد تلاش ورود بر اساس phone+ip
    sel_att = LoginAttemptTable.__table__.select().where(  # sel_att=کوئری تلاش ورود
        (LoginAttemptTable.phone == phone_norm) &  # شرط=شماره نرمال
        (LoginAttemptTable.ip == client_ip)  # شرط=آی‌پی
    )  # پایان where
    att = await database.fetch_one(sel_att)  # att=ردیف تلاش ورود

    if not att:  # شرط=اگر ردیف وجود ندارد
        ins_att = LoginAttemptTable.__table__.insert().values(  # ins_att=ایجاد ردیف جدید
            phone=phone_norm,  # phone=شماره نرمال
            ip=client_ip,  # ip=آی‌پی
            attempt_count=0,  # attempt_count=شروع از صفر
            window_start=now,  # window_start=شروع پنجره زمانی
            locked_until=None,  # locked_until=بدون قفل
            last_attempt_at=now,  # last_attempt_at=اکنون
            created_at=now  # created_at=اکنون
        )  # پایان insert
        await database.execute(ins_att)  # اجرا=insert
        att = await database.fetch_one(sel_att)  # att=خواندن مجدد ردیف
    else:  # حالت=ردیف موجود است
        locked_until = att["locked_until"]  # locked_until=زمان پایان قفل
        if locked_until is not None and locked_until > now:  # شرط=هنوز قفل است
            lock_remaining = int((locked_until - now).total_seconds())  # lock_remaining=ثانیه باقی‌مانده قفل
            raise HTTPException(  # خطا=۴۲۹
                status_code=429,  # status_code=Too Many Requests
                detail={"code": "RATE_LIMITED", "lock_remaining": lock_remaining},  # detail=کد و زمان باقی‌مانده
                headers={  # headers=هدرهای کمکی
                    "Retry-After": str(lock_remaining),  # Retry-After=زمان انتظار
                    "X-Remaining-Attempts": "0"  # X-Remaining-Attempts=۰
                }  # پایان headers
            )  # پایان raise

        # اگر قفل گذشته باشد یا پنجره زمانی تمام شده باشد، شمارنده را ریست می‌کنیم  # توضیح=همگام با LOGIN_WINDOW_SECONDS
        window_start = att["window_start"] or now  # window_start=شروع پنجره یا اکنون
        window_age = (now - window_start).total_seconds()  # window_age=سن پنجره به ثانیه
        if window_age > LOGIN_WINDOW_SECONDS or (locked_until is not None and locked_until <= now):  # شرط=پایان پنجره یا پایان قفل
            upd_reset = LoginAttemptTable.__table__.update().where(  # upd_reset=آپدیت ریست تلاش‌ها
                LoginAttemptTable.id == att["id"]  # شرط=id ردیف
            ).values(  # values=مقادیر جدید
                attempt_count=0,  # attempt_count=صفر
                window_start=now,  # window_start=اکنون
                locked_until=None,  # locked_until=بدون قفل
                last_attempt_at=now  # last_attempt_at=اکنون
            )  # پایان values
            await database.execute(upd_reset)  # اجرا=ریست
            att = await database.fetch_one(sel_att)  # att=خواندن مجدد ردیف بعد ریست

    # --- Load user (compat: try raw and normalized) ---  # توضیح=سازگاری با داده‌های قدیمی که ممکن است نرمال نشده باشند
    sel_user = UserTable.__table__.select().where(  # sel_user=کوئری کاربر
        or_(  # or_=یکی از این دو شماره
            UserTable.phone == raw_phone,  # شرط=شماره خام
            UserTable.phone == phone_norm  # شرط=شماره نرمال
        )  # پایان or_
    )  # پایان where
    db_user = await database.fetch_one(sel_user)  # db_user=گرفتن کاربر
    if not db_user:  # شرط=کاربر نبود
        # اینجا تلاش ناموفق را هم حساب می‌کنیم  # توضیح=جلوگیری از brute-force / enumeration
        cur_count = int(att["attempt_count"] or 0) + 1  # cur_count=تلاش جدید
        remaining = max(0, LOGIN_MAX_ATTEMPTS - cur_count)  # remaining=تلاش باقی‌مانده
        lock_remaining = None  # lock_remaining=پیش‌فرض

        if cur_count >= LOGIN_MAX_ATTEMPTS:  # شرط=رسیدن به سقف
            locked_until_new = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # locked_until_new=زمان قفل جدید
            lock_remaining = int((locked_until_new - now).total_seconds())  # lock_remaining=ثانیه قفل
            await database.execute(  # اجرا=آپدیت قفل
                LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == att["id"]).values(  # update=login_attempts
                    attempt_count=cur_count,  # attempt_count=تلاش جدید
                    locked_until=locked_until_new,  # locked_until=قفل
                    last_attempt_at=now  # last_attempt_at=اکنون
                )  # پایان values
            )  # پایان execute
            raise HTTPException(  # خطا=۴۲۹
                status_code=429,  # status_code=Too Many Requests
                detail={"code": "RATE_LIMITED", "lock_remaining": lock_remaining},  # detail=قفل
                headers={"Retry-After": str(lock_remaining), "X-Remaining-Attempts": "0"}  # headers=هدرها
            )  # پایان raise

        await database.execute(  # اجرا=ثبت تلاش ناموفق بدون قفل
            LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == att["id"]).values(  # update=login_attempts
                attempt_count=cur_count,  # attempt_count=تلاش جدید
                last_attempt_at=now  # last_attempt_at=اکنون
            )  # پایان values
        )  # پایان execute

        raise HTTPException(  # خطا=۴۰۴
            status_code=404,  # status_code=Not Found
            detail={"code": "USER_NOT_FOUND"}  # detail=کد کاربر یافت نشد
        )  # پایان raise

    # --- Password check ---  # توضیح=بررسی رمز
    if not verify_password_secure(user.password, db_user["password_hash"]):  # شرط=رمز اشتباه
        cur_count = int(att["attempt_count"] or 0) + 1  # cur_count=تلاش جدید
        remaining = max(0, LOGIN_MAX_ATTEMPTS - cur_count)  # remaining=تلاش باقی‌مانده

        if cur_count >= LOGIN_MAX_ATTEMPTS:  # شرط=رسیدن به سقف
            locked_until_new = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # locked_until_new=زمان قفل
            lock_remaining = int((locked_until_new - now).total_seconds())  # lock_remaining=ثانیه قفل
            await database.execute(  # اجرا=قفل کردن
                LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == att["id"]).values(  # update=login_attempts
                    attempt_count=cur_count,  # attempt_count=ثبت تلاش
                    locked_until=locked_until_new,  # locked_until=قفل
                    last_attempt_at=now  # last_attempt_at=اکنون
                )  # پایان values
            )  # پایان execute

            raise HTTPException(  # خطا=۴۲۹
                status_code=429,  # status_code=Too Many Requests
                detail={"code": "RATE_LIMITED", "lock_remaining": lock_remaining},  # detail=قفل
                headers={  # headers=هدرها
                    "Retry-After": str(lock_remaining),  # Retry-After=زمان انتظار
                    "X-Remaining-Attempts": "0"  # Remaining=۰
                }  # پایان headers
            )  # پایان raise

        await database.execute(  # اجرا=ثبت تلاش ناموفق
            LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == att["id"]).values(  # update=login_attempts
                attempt_count=cur_count,  # attempt_count=تلاش جدید
                last_attempt_at=now  # last_attempt_at=اکنون
            )  # پایان values
        )  # پایان execute

        raise HTTPException(  # خطا=۴۰۱
            status_code=401,  # status_code=Unauthorized
            detail={"code": "WRONG_PASSWORD", "remaining_attempts": int(remaining)},  # detail=کد + تلاش باقی‌مانده
            headers={"X-Remaining-Attempts": str(int(remaining))}  # headers=ارسال باقی‌مانده
        )  # پایان raise

    # --- Success: reset attempts ---  # توضیح=در ورود موفق، ریست تلاش‌ها
    await database.execute(  # اجرا=ریست تلاش‌ها
        LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == att["id"]).values(  # update=login_attempts
            attempt_count=0,  # attempt_count=صفر
            window_start=now,  # window_start=اکنون
            locked_until=None,  # locked_until=بدون قفل
            last_attempt_at=now  # last_attempt_at=اکنون
        )  # پایان values
    )  # پایان execute

    access_token = create_access_token(db_user["phone"])  # access_token=ساخت access token
    refresh_token = create_refresh_token()  # refresh_token=ساخت refresh token
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش refresh token
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # refresh_exp=انقضای refresh token

    ins_rt = RefreshTokenTable.__table__.insert().values(  # ins_rt=ثبت refresh token
        user_id=db_user["id"],  # user_id=شناسه کاربر
        token_hash=refresh_hash,  # token_hash=هش توکن
        expires_at=refresh_exp,  # expires_at=انقضا
        revoked=False  # revoked=ابطال نشده
    )  # پایان insert
    await database.execute(ins_rt)  # اجرا=insert refresh token

    return {  # پاسخ=موفق
        "status": "ok",  # status=ok
        "access_token": access_token,  # access_token=توکن دسترسی
        "refresh_token": refresh_token,  # refresh_token=توکن نوسازی
        "user": {  # user=اطلاعات کاربر
            "phone": db_user["phone"],  # phone=شماره
            "address": db_user["address"] or "",  # address=آدرس
            "name": db_user["name"] or ""  # name=نام
        }  # پایان user
    }  # پایان پاسخ
# -------------------- Cars --------------------

@app.get("/user_cars/{user_phone}")  # مسیر=گرفتن لیست ماشین‌های کاربر
async def get_user_cars(user_phone: str, request: Request):  # تابع=گرفتن ماشین‌ها
    raw = str(user_phone or "").strip()  # raw=شماره خام مسیر
    norm = _normalize_phone(raw)  # norm=شماره نرمال مسیر

    auth_phone = _normalize_phone(get_auth_phone(request, fallback_phone=raw, enforce=False))  # auth_phone=شماره احراز شده نرمال
    if auth_phone != norm:  # شرط=عدم تطابق (همیشه با نرمال مقایسه می‌شود)
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    user = await fetch_user_by_phone_any(raw)  # user=یافتن کاربر با raw/norm
    if not user:  # شرط=کاربر نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=۴۰۴

    cars = user.get("car_list") or []  # cars=لیست خودروها
    return unified_response("ok", "USER_CARS", "cars list", {"items": cars})  # پاسخ=لیست
    
@app.post("/user_cars")  # مسیر=آپدیت لیست ماشین‌ها (بدون اسلش)
@app.post("/user_cars/")  # مسیر=آپدیت لیست ماشین‌ها (با اسلش)
async def update_user_cars(body: CarListUpdateRequest, request: Request):  # تابع=آپدیت ماشین‌ها
    phone = _normalize_phone(body.user_phone)  # phone=نرمال‌سازی
    auth_phone = _normalize_phone(get_auth_phone(request, fallback_phone=phone, enforce=False))  # auth_phone=احراز
    if auth_phone != phone:  # شرط=عدم تطابق
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # sel=کوئری کاربر
    user = await database.fetch_one(sel)  # user=گرفتن
    if not user:  # شرط=نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=۴۰۴

    cars_payload = [c.dict() for c in (body.car_list or [])]  # cars_payload=تبدیل به dict
    upd = UserTable.__table__.update().where(UserTable.phone == phone).values(car_list=cars_payload)  # upd=update car_list
    await database.execute(upd)  # اجرا=update

    return unified_response("ok", "USER_CARS_UPDATED", "cars updated", {"count": len(cars_payload)})  # پاسخ=موفق

# -------------------- Orders --------------------

@app.post("/order")  # ثبت سفارش
async def create_order(order: OrderRequest, request: Request):  # تابع
    raw = str(order.user_phone or "").strip()  # raw=شماره خام کاربر
    norm = _normalize_phone(raw)  # norm=شماره نرمال کاربر
    if not norm:  # شرط=شماره نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰

    auth_phone = _normalize_phone(get_auth_phone(request, fallback_phone=raw, enforce=False))  # auth_phone=شماره احراز نرمال
    if auth_phone != norm:  # شرط=عدم تطابق
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    ins = RequestTable.__table__.insert().values(  # insert=ثبت سفارش
        user_phone=norm,  # user_phone=شماره نرمال ذخیره می‌شود
        latitude=order.location.latitude,  # latitude=عرض
        longitude=order.location.longitude,  # longitude=طول
        car_list=[car.dict() for car in order.car_list],  # car_list=لیست خودرو
        address=order.address.strip(),  # address=آدرس
        home_number=(order.home_number or "").strip(),  # home_number=پلاک
        service_type=str(order.service_type or "").strip(),  # service_type=سرویس
        price=int(order.price),  # price=قیمت
        request_datetime=str(order.request_datetime or "").strip(),  # request_datetime=زمان ثبت
        status="NEW",  # status=NEW
        payment_type=str(order.payment_type or "").strip().lower(),  # payment_type=پرداخت
        service_place=str(order.service_place or "").strip().lower()  # service_place=محل
    ).returning(RequestTable.id)  # returning=id

    row = await database.fetch_one(ins)  # row=اجرا
    new_id = row["id"] if row else None  # new_id=شناسه

    try:  # try=محافظ اعلان مدیر
        await notify_managers(  # اعلان=به مدیر
            title="سفارش جدید",  # title=عنوان
            body=f"سفارش جدید ثبت شد: {order.service_type}",  # body=متن
            data={"order_id": int(new_id or 0), "user_phone": norm, "service_type": str(order.service_type or ""), "status": "NEW"}  # data=داده
        )  # پایان notify_managers
    except Exception as e:  # خطا
        logger.error(f"notify_managers(create_order) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # پاسخ=موفق
    
@app.post("/cancel_order")  # لغو سفارش
async def cancel_order(cancel: CancelRequest, request: Request):  # تابع
    raw = str(cancel.user_phone or "").strip()  # raw=شماره خام
    norm = _normalize_phone(raw)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰

    auth_phone = _normalize_phone(get_auth_phone(request, fallback_phone=raw, enforce=False))  # auth_phone=احراز نرمال
    if auth_phone != norm:  # شرط=عدم تطابق
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    phones = [norm]  # phones=لیست شماره‌ها
    if raw and raw != norm:  # شرط=برای سازگاری با داده‌های قدیمی
        phones.append(raw)  # افزودن raw

    upd = (  # upd=آپدیت لغو
        RequestTable.__table__.update()  # update=requests
        .where(  # where=شرایط
            (RequestTable.user_phone.in_(phones)) &  # شرط=شماره (raw/norm)
            (RequestTable.service_type == cancel.service_type) &  # شرط=سرویس
            (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED"])) &  # شرط=قابل لغو
            (RequestTable.execution_start.is_(None))  # شرط=بدون زمان اجرا
        )  # پایان where
        .values(status="CANCELED", scheduled_start=None, execution_start=None)  # values=لغو + پاکسازی زمان‌ها
        .returning(RequestTable.id, RequestTable.driver_phone)  # returning=شناسه‌ها
    )  # پایان upd

    rows = await database.fetch_all(upd)  # rows=اجرا
    if rows:  # شرط=لغو شد
        ids = [int(r["id"]) for r in rows]  # ids=لیست id
        driver_phones = list({(r["driver_phone"] or "").strip() for r in rows if r["driver_phone"]})  # driver_phones=شماره‌ها

        try:  # try=پاکسازی زمان‌ها
            await database.execute(  # update=اسلات‌ها
                ScheduleSlotTable.__table__.update()  # update=schedule_slots
                .where(  # where
                    (ScheduleSlotTable.request_id.in_(ids)) &  # شرط=در ids
                    (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))  # شرط=فعال
                )  # پایان where
                .values(status="REJECTED")  # values=رد شده
            )  # پایان execute

            await database.execute(  # update=appointmentها
                AppointmentTable.__table__.update()  # update=appointments
                .where(  # where
                    (AppointmentTable.request_id.in_(ids)) &  # شرط=در ids
                    (AppointmentTable.status == "BOOKED")  # شرط=رزرو
                )  # پایان where
                .values(status="CANCELED")  # values=لغو
            )  # پایان execute
        except Exception as e:  # خطا
            logger.error(f"cleanup(cancel_order) failed: {e}")  # لاگ=خطا

        try:  # try=اعلان‌ها
            await notify_managers(  # اعلان=به مدیرها
                title="لغو سفارش",  # title=عنوان
                body=f"سفارش توسط کاربر لغو شد ({cancel.service_type})",  # body=متن
                data={"order_ids": ",".join(str(x) for x in ids), "user_phone": norm, "service_type": cancel.service_type, "status": "CANCELED"}  # data=داده
            )  # پایان notify_managers
            for dp in driver_phones:  # حلقه=روی سرویس‌دهنده‌ها
                await notify_managers(  # اعلان=هدفمند
                    title="لغو سفارش",  # title=عنوان
                    body=f"سفارش شما لغو شد (id={ids[0]})",  # body=متن
                    data={"order_ids": ",".join(str(x) for x in ids), "status": "CANCELED"},  # data=داده
                    target_phone=dp  # target_phone=هدف
                )  # پایان notify_managers
        except Exception as e:  # خطا
            logger.error(f"notify_managers(cancel_order) failed: {e}")  # لاگ=خطا

        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # پاسخ=موفق

    raise HTTPException(status_code=409, detail={"code": "CANNOT_CANCEL", "message": "order cannot be canceled at this stage"})  # خطا=۴۰۹
    
@app.get("/user_active_services/{user_phone}")  # سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str, request: Request):  # تابع
    raw = str(user_phone or "").strip()  # raw=شماره خام مسیر
    norm = _normalize_phone(raw)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰

    auth_phone = _normalize_phone(get_auth_phone(request, fallback_phone=raw, enforce=False))  # auth_phone=احراز نرمال
    if auth_phone != norm:  # شرط=عدم تطابق
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    phones = [norm]  # phones=لیست شماره‌ها
    if raw and raw != norm:  # شرط=سازگاری قدیمی
        phones.append(raw)  # افزودن raw

    sel = RequestTable.__table__.select().where(  # sel=کوئری فعال‌ها
        (RequestTable.user_phone.in_(phones)) &  # شرط=شماره
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))  # شرط=فعال
    )  # پایان where
    result = await database.fetch_all(sel)  # result=اجرا
    items = [dict(r) for r in result]  # items=تبدیل
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # پاسخ
    
@app.get("/user_orders/{user_phone}")  # لیست سفارش‌ها
async def get_user_orders(user_phone: str, request: Request):  # تابع
    raw = str(user_phone or "").strip()  # raw=شماره خام مسیر
    norm = _normalize_phone(raw)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰

    auth_phone = _normalize_phone(get_auth_phone(request, fallback_phone=raw, enforce=False))  # auth_phone=احراز نرمال
    if auth_phone != norm:  # شرط=عدم تطابق
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    phones = [norm]  # phones=لیست شماره‌ها
    if raw and raw != norm:  # شرط=سازگاری قدیمی
        phones.append(raw)  # افزودن raw

    sel = RequestTable.__table__.select().where(RequestTable.user_phone.in_(phones))  # sel=کوئری سفارش‌ها
    result = await database.fetch_all(sel)  # result=اجرا
    items = [dict(r) for r in result]  # items=تبدیل
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # پاسخ
    
# -------------------- Utils --------------------  # بخش=ابزارها

async def provider_is_free(provider_phone: str, start: datetime, end: datetime, exclude_order_id: Optional[int] = None) -> bool:  # تابع=بررسی آزاد بودن سرویس‌دهنده
    provider = _normalize_phone(provider_phone or "")  # provider=شماره سرویس‌دهنده نرمال‌شده
    if not provider:  # شرط=شماره خالی/نامعتبر
        return False  # خروجی=غیرآزاد

    one_hour = text("interval '1 hour'")  # one_hour=اینترول یک ساعت در PostgreSQL

    q_app = select(func.count()).select_from(AppointmentTable).where(  # q_app=شمارش رزروهای قطعی
        (AppointmentTable.provider_phone == provider) &  # شرط=شماره سرویس‌دهنده
        (AppointmentTable.status == "BOOKED") &  # شرط=رزرو شده
        (AppointmentTable.start_time < end) &  # شرط=شروع قبل از پایان بازه
        (AppointmentTable.end_time > start)  # شرط=پایان بعد از شروع بازه
    )  # پایان q_app
    if exclude_order_id is not None:  # شرط=نادیده گرفتن یک سفارش
        q_app = q_app.where(AppointmentTable.request_id != exclude_order_id)  # افزودن=حذف سفارش جاری
    app_count = await database.fetch_val(q_app)  # app_count=تعداد تداخل رزرو
    if app_count and int(app_count) > 0:  # شرط=تداخل دارد
        return False  # خروجی=غیرآزاد

    slot_end = ScheduleSlotTable.slot_start + one_hour  # slot_end=پایان اسلات پیشنهادی (۱ ساعت)
    q_slot = select(func.count()).select_from(ScheduleSlotTable).where(  # q_slot=شمارش زمان‌های رزرو-موقت
        (ScheduleSlotTable.provider_phone == provider) &  # شرط=شماره سرویس‌دهنده
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &  # شرط=پیشنهادی/پذیرفته (برای دیگران مشغول)
        (ScheduleSlotTable.slot_start < end) &  # شرط=شروع اسلات قبل از پایان بازه
        (slot_end > start)  # شرط=پایان اسلات بعد از شروع بازه
    )  # پایان q_slot
    if exclude_order_id is not None:  # شرط=نادیده گرفتن یک سفارش
        q_slot = q_slot.where(ScheduleSlotTable.request_id != exclude_order_id)  # افزودن=حذف سفارش جاری
    slot_count = await database.fetch_val(q_slot)  # slot_count=تعداد تداخل اسلات
    if slot_count and int(slot_count) > 0:  # شرط=تداخل دارد
        return False  # خروجی=غیرآزاد

    exec_end = RequestTable.execution_start + one_hour  # exec_end=پایان اجرای کار (۱ ساعت)
    q_exec = select(func.count()).select_from(RequestTable).where(  # q_exec=شمارش اجرای فعال
        (RequestTable.driver_phone == provider) &  # شرط=شماره سرویس‌دهنده
        (RequestTable.execution_start.is_not(None)) &  # شرط=زمان اجرا ثبت شده
        (RequestTable.status.in_(["IN_PROGRESS", "STARTED"])) &  # شرط=در حال انجام/شروع
        (RequestTable.execution_start < end) &  # شرط=شروع قبل از پایان بازه
        (exec_end > start)  # شرط=پایان بعد از شروع بازه
    )  # پایان q_exec
    if exclude_order_id is not None:  # شرط=نادیده گرفتن سفارش
        q_exec = q_exec.where(RequestTable.id != exclude_order_id)  # افزودن=حذف سفارش جاری
    exec_count = await database.fetch_val(q_exec)  # exec_count=تعداد تداخل اجرا
    if exec_count and int(exec_count) > 0:  # شرط=تداخل دارد
        return False  # خروجی=غیرآزاد

    # --- FIX: scheduled_start هم زمان رزرو شده است (WAITING/ASSIGNED/...) ---  # توضیح=پوشش داده‌های قدیمی/ناهماهنگ که appointment ندارند
    visit_end = RequestTable.scheduled_start + one_hour  # visit_end=پایان زمان بازدید قطعی (۱ ساعت)
    q_visit = select(func.count()).select_from(RequestTable).where(  # q_visit=شمارش تداخل زمان‌های scheduled_start
        (RequestTable.driver_phone == provider) &  # شرط=شماره سرویس‌دهنده
        (RequestTable.scheduled_start.is_not(None)) &  # شرط=زمان بازدید قطعی وجود دارد
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"])) &  # شرط=وضعیت‌های فعال/در انتظار/تأیید
        (RequestTable.scheduled_start < end) &  # شرط=شروع بازدید قبل از پایان بازه
        (visit_end > start)  # شرط=پایان بازدید بعد از شروع بازه
    )  # پایان q_visit
    if exclude_order_id is not None:  # شرط=نادیده گرفتن سفارش
        q_visit = q_visit.where(RequestTable.id != exclude_order_id)  # افزودن=حذف سفارش جاری
    visit_count = await database.fetch_val(q_visit)  # visit_count=تعداد تداخل بازدید
    if visit_count and int(visit_count) > 0:  # شرط=تداخل دارد
        return False  # خروجی=غیرآزاد

    return True  # خروجی=آزاد

async def fetch_user_by_phone_any(phone_input: str) -> Optional[dict]:  # تابع=پیدا کردن کاربر با شماره خام یا نرمال (سازگار با داده‌های قدیمی)
    raw = str(phone_input or "").strip()  # raw=شماره خام ورودی + trim
    norm = _normalize_phone(raw)  # norm=شماره نرمال‌شده
    if not raw and not norm:  # شرط=هیچ شماره‌ای نداریم
        return None  # خروجی=None

    conds = []  # conds=لیست شرط‌ها
    if raw:  # شرط=raw خالی نیست
        conds.append(UserTable.phone == raw)  # افزودن=شرط شماره خام
    if norm and norm != raw:  # شرط=نرمال معتبر و متفاوت
        conds.append(UserTable.phone == norm)  # افزودن=شرط شماره نرمال

    sel = UserTable.__table__.select().where(or_(*conds)).limit(1)  # sel=کوئری انتخاب اولین کاربر با raw/norm
    row = await database.fetch_one(sel)  # row=اجرای کوئری
    return dict(row) if row else None  # خروجی=دیکشنری کاربر یا None
    
# -------------------- Scheduling --------------------

@app.get("/busy_slots")  # مسیر=ساعات مشغول (بدون نیاز به provider_phone از UI)
async def get_busy_slots(  # تابع=لیست زمان‌های مشغول
    request: Request,  # request=برای احراز مدیر و گرفتن شماره مدیر
    date: str,  # date=تاریخ (YYYY-MM-DD)
    exclude_order_id: Optional[int] = None,  # exclude_order_id=نادیده گرفتن یک سفارش
    provider_phone: Optional[str] = None  # provider_phone=اختیاری (برای سازگاری قدیمی)
):  # شروع تابع
    require_admin(request)  # احراز=فقط مدیر

    d = datetime.fromisoformat(date).date()  # d=تاریخ
    provider = _normalize_phone(provider_phone) if (provider_phone and provider_phone.strip()) else get_admin_provider_phone(request)  # provider=شماره سرویس‌دهنده (اولویت با ورودی، بعد شماره مدیر)

    day_start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)  # day_start=شروع روز UTC
    day_end = day_start + timedelta(days=1)  # day_end=پایان روز UTC

    sel_sched = ScheduleSlotTable.__table__.select().where(  # sel_sched=کوئری اسلات‌های فعال
        (ScheduleSlotTable.slot_start >= day_start) &  # شرط=از شروع روز
        (ScheduleSlotTable.slot_start < day_end) &  # شرط=تا پایان روز
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &  # شرط=پیشنهادی/پذیرفته (برای دیگران مشغول است)
        (ScheduleSlotTable.provider_phone == provider)  # شرط=شماره سرویس‌دهنده
    )  # پایان where
    if exclude_order_id is not None:  # شرط=exclude فعال است
        sel_sched = sel_sched.where(ScheduleSlotTable.request_id != exclude_order_id)  # افزودن شرط=حذف سفارش جاری
    rows_sched = await database.fetch_all(sel_sched)  # rows_sched=نتیجه اسلات‌ها

    sel_app = AppointmentTable.__table__.select().where(  # sel_app=کوئری رزروهای قطعی
        (AppointmentTable.start_time >= day_start) &  # شرط=از شروع روز
        (AppointmentTable.start_time < day_end) &  # شرط=تا پایان روز
        (AppointmentTable.status == "BOOKED") &  # شرط=رزرو شده
        (AppointmentTable.provider_phone == provider)  # شرط=شماره سرویس‌دهنده
    )  # پایان where
    if exclude_order_id is not None:  # شرط=exclude فعال است
        sel_app = sel_app.where(AppointmentTable.request_id != exclude_order_id)  # افزودن شرط=حذف سفارش جاری
    rows_app = await database.fetch_all(sel_app)  # rows_app=نتیجه رزروها

    sel_exec = RequestTable.__table__.select().where(  # sel_exec=کوئری زمان‌های اجرای فعال
        (RequestTable.execution_start >= day_start) &  # شرط=از شروع روز
        (RequestTable.execution_start < day_end) &  # شرط=تا پایان روز
        (RequestTable.execution_start.is_not(None)) &  # شرط=زمان اجرا ثبت شده
        (RequestTable.status.in_(["IN_PROGRESS", "STARTED"])) &  # شرط=در حال انجام/شروع
        (RequestTable.driver_phone == provider)  # شرط=شماره سرویس‌دهنده
    )  # پایان where
    if exclude_order_id is not None:  # شرط=exclude فعال است
        sel_exec = sel_exec.where(RequestTable.id != exclude_order_id)  # افزودن شرط=حذف سفارش جاری
    rows_exec = await database.fetch_all(sel_exec)  # rows_exec=نتیجه اجراها

    # --- FIX: scheduled_start هم باید به عنوان زمان مشغول برگردد ---  # توضیح=رزروهای WAITING/ASSIGNED که ممکن است appointment نداشته باشند
    sel_visit = RequestTable.__table__.select().where(  # sel_visit=کوئری زمان‌های بازدید قطعی/فعال
        (RequestTable.scheduled_start >= day_start) &  # شرط=از شروع روز
        (RequestTable.scheduled_start < day_end) &  # شرط=تا پایان روز
        (RequestTable.scheduled_start.is_not(None)) &  # شرط=scheduled_start موجود
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"])) &  # شرط=وضعیت‌های فعال/در انتظار/تأیید
        (RequestTable.driver_phone == provider)  # شرط=شماره سرویس‌دهنده
    )  # پایان where
    if exclude_order_id is not None:  # شرط=exclude فعال است
        sel_visit = sel_visit.where(RequestTable.id != exclude_order_id)  # افزودن شرط=حذف سفارش جاری
    rows_visit = await database.fetch_all(sel_visit)  # rows_visit=نتیجه بازدیدها

    busy: set[str] = set()  # busy=مجموعه زمان‌های مشغول
    for r in rows_sched:  # حلقه=اسلات‌ها
        busy.add(r["slot_start"].isoformat())  # افزودن=زمان اسلات
    for r in rows_app:  # حلقه=رزروها
        busy.add(r["start_time"].isoformat())  # افزودن=زمان رزرو
    for r in rows_exec:  # حلقه=اجراها
        busy.add(r["execution_start"].isoformat())  # افزودن=زمان اجرا
    for r in rows_visit:  # حلقه=بازدیدهای قطعی
        busy.add(r["scheduled_start"].isoformat())  # افزودن=زمان بازدید قطعی

    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": sorted(busy)})  # پاسخ=لیست زمان‌های مشغول    
# -------------------- Propose slots (Manager) --------------------

@app.post("/order/{order_id}/propose_slots")  # مسیر=ثبت زمان‌های پیشنهادی (بدون اسلش)
@app.post("/order/{order_id}/propose_slots/")  # مسیر=ثبت زمان‌های پیشنهادی (با اسلش)
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):  # تابع=ثبت اسلات‌های پیشنهادی توسط مدیر
    require_admin(request)  # احراز=فقط مدیر

    provider = _normalize_phone(body.provider_phone) if (body.provider_phone and str(body.provider_phone).strip()) else get_admin_provider_phone(request)  # provider=شماره سرویس‌دهنده (از body یا شماره مدیر)
    if not provider:  # شرط=شماره خالی
        raise HTTPException(status_code=400, detail="provider_phone required")  # خطا=۴۰۰

    sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel_req=کوئری سفارش
    req_row = await database.fetch_one(sel_req)  # req_row=سفارش
    if not req_row:  # شرط=سفارش نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    req_row = dict(req_row)  # تبدیل=Record به dict تا .get کار کند

    cur_status = str(req_row.get("status") or "").strip().upper()  # cur_status=وضعیت نرمال
    if cur_status in ["FINISH", "CANCELED"]:  # شرط=سفارش بسته
        raise HTTPException(status_code=409, detail="order cannot accept new proposed slots")  # خطا=۴۰۹
    if req_row.get("execution_start") is not None:  # شرط=زمان اجرا ثبت شده
        raise HTTPException(status_code=409, detail="order cannot accept new proposed slots after execution_time")  # خطا=۴۰۹

    raw_slots = body.slots or []  # raw_slots=لیست خام
    cleaned: List[str] = []  # cleaned=لیست پاکسازی
    seen: set[str] = set()  # seen=جلوگیری از تکرار

    for s in raw_slots:  # حلقه=روی ورودی‌ها
        ss = str(s or "").strip()  # ss=trim
        if not ss:  # شرط=خالی
            continue  # رد
        if ss in seen:  # شرط=تکراری
            continue  # رد
        seen.add(ss)  # افزودن=seen
        cleaned.append(ss)  # افزودن=لیست
        if len(cleaned) >= 3:  # شرط=حداکثر ۳
            break  # خروج

    if not cleaned:  # شرط=بدون زمان
        raise HTTPException(status_code=400, detail="slots required")  # خطا=۴۰۰

    slot_dts = [parse_iso(x) for x in cleaned]  # slot_dts=پارس ISO
    slot_dts.sort()  # مرتب‌سازی=صعودی

    accepted: List[str] = []  # accepted=لیست ثبت‌شده

    async with database.transaction():  # transaction=اتمیک
        await database.execute(  # رد=اسلات‌های قبلی همین سفارش
            ScheduleSlotTable.__table__.update()  # update=schedule_slots
            .where(  # where
                (ScheduleSlotTable.request_id == order_id) &  # شرط=همین سفارش
                (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))  # شرط=فعال
            )  # پایان where
            .values(status="REJECTED")  # values=رد شده
        )  # پایان execute

        await database.execute(  # لغو=رزروهای قبلی BOOKED همین سفارش
            AppointmentTable.__table__.update()  # update=appointments
            .where(  # where
                (AppointmentTable.request_id == order_id) &  # شرط=همین سفارش
                (AppointmentTable.status == "BOOKED")  # شرط=رزرو فعال
            )  # پایان where
            .values(status="CANCELED")  # values=لغو
        )  # پایان execute

        await database.execute(  # آپدیت=سفارش
            RequestTable.__table__.update()  # update=requests
            .where(RequestTable.id == order_id)  # where=id
            .values(driver_phone=provider, status="WAITING", scheduled_start=None)  # values=ثبت سرویس‌دهنده+WAITING+پاکسازی scheduled_start
        )  # پایان execute

        for dt in slot_dts:  # حلقه=روی زمان‌ها
            end_dt = dt + timedelta(hours=1)  # end_dt=پایان بازه
            free = await provider_is_free(provider, dt, end_dt)  # free=آزاد بودن
            if not free:  # شرط=تداخل
                raise HTTPException(status_code=409, detail="slot overlaps with existing schedule")  # خطا=۴۰۹

            try:  # try=محافظ برخورد همزمان
                await database.execute(  # درج=اسلات پیشنهادی
                    ScheduleSlotTable.__table__.insert().values(  # insert=schedule_slots
                        request_id=order_id,  # request_id=شناسه سفارش
                        provider_phone=provider,  # provider_phone=شماره سرویس‌دهنده
                        slot_start=dt,  # slot_start=شروع
                        status="PROPOSED",  # status=پیشنهادی
                        created_at=datetime.now(timezone.utc)  # created_at=اکنون
                    )  # پایان values
                )  # پایان execute
            except Exception as e:  # catch=خطا
                msg = str(e)  # msg=متن خطا
                if ("uq_schedule_slots_provider_start_active" in msg) or ("duplicate key value" in msg):  # شرط=برخورد ایندکس یکتا
                    raise HTTPException(status_code=409, detail="slot already reserved for another order")  # خطا=۴۰۹
                raise  # raise=پرتاب مجدد

            accepted.append(dt.isoformat())  # افزودن=به خروجی

    try:  # try=محافظ اعلان
        await notify_user(  # اعلان=به کاربر
            phone=req_row["user_phone"],  # phone=شماره کاربر
            title="پیشنهاد زمان بازدید",  # title=عنوان
            body="زمان‌های پیشنهادی برای بازدید ارسال شد.",  # body=متن
            data={  # data=داده
                "type": "visit_slots",  # type=نوع
                "order_id": int(order_id),  # order_id=شناسه
                "status": "WAITING",  # status=WAITING
                "service_type": str(req_row.get("service_type") or "")  # service_type=نوع سرویس
            }  # پایان data
        )  # پایان notify_user
    except Exception as e:  # خطا
        logger.error(f"notify_user(propose_slots) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # پاسخ
    
# -------------------- Admin workflow --------------------

# -------------------- Admin workflow --------------------

@app.post("/admin/order/{order_id}/price")  # مسیر=ثبت قیمت/توافق توسط مدیر
async def admin_set_price(order_id: int, body: PriceBody, request: Request):  # تابع=ثبت قیمت/زمان اجرا
    require_admin(request)  # احراز=مدیر

    sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel_req=کوئری سفارش
    req_row = await database.fetch_one(sel_req)  # req_row=سفارش
    if not req_row:  # شرط=سفارش نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    req_row = dict(req_row)  # تبدیل=Record به dict برای دسترسی با .get

    exec_dt: Optional[datetime] = None  # exec_dt=زمان اجرا
    new_status = "PRICE_REJECTED"  # new_status=پیش‌فرض وضعیت

    provider = (req_row.get("driver_phone") or "").strip()  # provider=شماره سرویس‌دهنده
    service_type = str(req_row.get("service_type") or "").strip()  # service_type=نوع سرویس (برای ارسال در پوش)

    async with database.transaction():  # transaction=اتمیک
        if body.agree:  # شرط=توافق
            if not body.exec_time or not str(body.exec_time).strip():  # شرط=زمان اجرا لازم است
                raise HTTPException(status_code=400, detail="exec_time required when agree=true")  # خطا=۴۰۰
            if not provider:  # شرط=سرویس‌دهنده ثبت نشده
                raise HTTPException(status_code=400, detail="driver_phone(provider) not set for this order")  # خطا=۴۰۰

            exec_dt = parse_iso(body.exec_time)  # exec_dt=پارس UTC
            end_dt = exec_dt + timedelta(hours=1)  # end_dt=پایان ۱ ساعت

            free = await provider_is_free(provider, exec_dt, end_dt)  # free=آزاد بودن
            if not free:  # شرط=تداخل
                raise HTTPException(status_code=409, detail="execution time overlaps with existing schedule")  # خطا=۴۰۹

            # --- FIX: به‌جای INSERT، اگر رکورد همان بازه قبلاً وجود دارد UPDATE می‌کنیم ---  # توضیح=رفع خطای uq_provider_slot
            sel_any = AppointmentTable.__table__.select().where(  # sel_any=جستجوی رکورد appointment با همان بازه
                (AppointmentTable.provider_phone == provider) &  # شرط=provider
                (AppointmentTable.start_time == exec_dt) &  # شرط=start
                (AppointmentTable.end_time == end_dt)  # شرط=end
            ).limit(1)  # limit=۱
            any_row = await database.fetch_one(sel_any)  # any_row=نتیجه

            if any_row:  # شرط=رکورد وجود دارد
                # اگر رکورد برای سفارش دیگری BOOKED است، تداخل واقعی است  # توضیح=محافظت در برابر race
                if (str(any_row["status"] or "").strip().upper() == "BOOKED") and (int(any_row["request_id"] or 0) != int(order_id)):  # شرط=BOOKED برای سفارش دیگر
                    raise HTTPException(status_code=409, detail="execution time overlaps with existing schedule")  # خطا=۴۰۹

                upd_app = AppointmentTable.__table__.update().where(  # upd_app=آپدیت رکورد موجود
                    AppointmentTable.id == any_row["id"]  # شرط=id
                ).values(  # values=مقادیر جدید
                    request_id=order_id,  # request_id=این سفارش
                    status="BOOKED"  # status=رزرو شده
                )  # پایان values
                await database.execute(upd_app)  # اجرا=آپدیت
            else:  # حالت=رکورد وجود ندارد
                try:  # try=محافظ برخورد همزمان
                    await database.execute(  # insert=appointment جدید
                        AppointmentTable.__table__.insert().values(  # values
                            provider_phone=provider,  # provider_phone=شماره
                            request_id=order_id,  # request_id=سفارش
                            start_time=exec_dt,  # start_time=شروع
                            end_time=end_dt,  # end_time=پایان
                            status="BOOKED",  # status=رزرو
                            created_at=datetime.now(timezone.utc)  # created_at=اکنون
                        )  # پایان values
                    )  # پایان execute
                except Exception as e:  # catch=خطا
                    msg = str(e)  # msg=متن خطا
                    if ("uq_provider_slot" in msg) or ("duplicate key value" in msg):  # شرط=برخورد یکتا
                        # در برخورد یکتا، مجدد رکورد را گرفته و UPDATE می‌کنیم  # توضیح=رفع خطای ثبت تکراری
                        any_row2 = await database.fetch_one(sel_any)  # any_row2=خواندن مجدد
                        if any_row2:  # شرط=پیدا شد
                            if (str(any_row2["status"] or "").strip().upper() == "BOOKED") and (int(any_row2["request_id"] or 0) != int(order_id)):  # شرط=BOOKED برای سفارش دیگر
                                raise HTTPException(status_code=409, detail="execution time overlaps with existing schedule")  # خطا=۴۰۹
                            await database.execute(  # اجرا=آپدیت
                                AppointmentTable.__table__.update().where(AppointmentTable.id == any_row2["id"]).values(  # update by id
                                    request_id=order_id,  # request_id=این سفارش
                                    status="BOOKED"  # status=رزرو
                                )  # پایان values
                            )  # پایان execute
                        else:  # حالت=باز هم پیدا نشد
                            raise  # raise=پرتاب مجدد
                    else:  # حالت=خطای دیگر
                        raise  # raise=پرتاب مجدد

            new_status = "IN_PROGRESS"  # new_status=در حال انجام

        upd = (  # upd=آپدیت سفارش
            RequestTable.__table__.update()  # update=requests
            .where(RequestTable.id == order_id)  # where=id
            .values(price=int(body.price), status=new_status, execution_start=exec_dt)  # values=قیمت+وضعیت+زمان اجرا
            .returning(RequestTable.id, RequestTable.price, RequestTable.status, RequestTable.execution_start)  # returning=خروجی
        )  # پایان upd
        saved = await database.fetch_one(upd)  # saved=خروجی آپدیت

    try:  # try=اعلان کاربر
        if body.agree:  # شرط=توافق
            await notify_user(  # اعلان=به کاربر
                phone=req_row["user_phone"],  # phone=شماره کاربر
                title="توافق قیمت",  # title=عنوان
                body=f"قیمت {int(body.price)} ثبت شد. زمان اجرا: {exec_dt.isoformat() if exec_dt else ''}",  # body=متن
                data=order_push_data(  # data=دیتای استاندارد
                    msg_type="execution_time",  # msg_type=نوع پیام
                    order_id=int(order_id),  # order_id=شناسه
                    status=str(new_status),  # status=وضعیت
                    service_type=service_type,  # service_type=نوع سرویس
                    scheduled_start=req_row.get("scheduled_start"),  # scheduled_start=برای سازگاری
                    execution_start=exec_dt,  # execution_start=زمان اجرا
                    price=int(body.price)  # price=قیمت
                )  # پایان data
            )  # پایان notify_user
        else:  # حالت=عدم توافق
            await notify_user(  # اعلان=به کاربر
                phone=req_row["user_phone"],  # phone=شماره کاربر
                title="عدم توافق قیمت",  # title=عنوان
                body="قیمت مورد توافق قرار نگرفت.",  # body=متن
                data=order_push_data(  # data=دیتای استاندارد
                    msg_type="price_set",  # msg_type=نوع پیام
                    order_id=int(order_id),  # order_id=شناسه
                    status=str(new_status),  # status=وضعیت
                    service_type=service_type,  # service_type=نوع سرویس
                    scheduled_start=req_row.get("scheduled_start"),  # scheduled_start=برای سازگاری
                    execution_start=None,  # execution_start=ندارد
                    price=int(body.price)  # price=قیمت
                )  # پایان data
            )  # پایان notify_user
    except Exception as e:  # خطا
        logger.error(f"notify_user(admin_set_price) failed: {e}")  # لاگ=خطا

    return unified_response(  # پاسخ=نتیجه
        "ok",  # status=ok
        "PRICE_SET",  # code=کد
        "price/status updated",  # message=پیام
        {  # data=داده
            "order_id": int(saved["id"]) if saved else int(order_id),  # order_id=شناسه
            "price": int(saved["price"]) if saved else int(body.price),  # price=قیمت
            "status": str(saved["status"]) if saved else new_status,  # status=وضعیت
            "execution_start": (saved["execution_start"].isoformat() if (saved and saved["execution_start"]) else None)  # execution_start=زمان اجرا
        }  # پایان data
    )  # پایان پاسخ


# -------------------- Confirm slot (User) --------------------

@app.post("/order/{order_id}/confirm_slot")  # مسیر=تأیید زمان (بدون اسلش)
@app.post("/order/{order_id}/confirm_slot/")  # مسیر=تأیید زمان (با اسلش)
async def confirm_slot(order_id: int, body: ConfirmSlotRequest, request: Request):  # تابع=تأیید زمان بازدید توسط کاربر
    sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel_req=کوئری سفارش
    req_row = await database.fetch_one(sel_req)  # req_row=گرفتن سفارش
    if not req_row:  # شرط=سفارش وجود ندارد
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    req = dict(req_row)  # req=تبدیل Record به dict

    authed = get_auth_phone(request, fallback_phone=req["user_phone"], enforce=False)  # authed=شماره احراز شده
    if authed != req["user_phone"]:  # شرط=عدم دسترسی
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    if req.get("execution_start") is not None:  # شرط=زمان اجرا قبلاً ثبت شده
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CONFIRM", "message": "cannot confirm slot after execution time is set"})  # خطا=۴۰۹

    st = str(req.get("status") or "").strip().upper()  # st=وضعیت سفارش نرمال
    if st not in ["WAITING", "ASSIGNED", "NEW"]:  # شرط=وضعیت نامعتبر برای تأیید
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CONFIRM", "message": "order is not in schedulable state"})  # خطا=۴۰۹

    slot_dt = parse_iso(body.slot)  # slot_dt=پارس زمان انتخابی (UTC)
    end_dt = slot_dt + timedelta(hours=1)  # end_dt=پایان بازه یک‌ساعته

    service_type = str(req.get("service_type") or "")  # service_type=نوع سرویس سفارش
    provider = ""  # provider=شماره سرویس‌دهنده

    async with database.transaction():  # transaction=اتمیک
        sel_slot = ScheduleSlotTable.__table__.select().where(  # sel_slot=کوئری اسلات انتخابی
            (ScheduleSlotTable.request_id == order_id) &  # شرط=همین سفارش
            (ScheduleSlotTable.slot_start == slot_dt) &  # شرط=همین زمان
            (ScheduleSlotTable.status == "PROPOSED")  # شرط=اسلات پیشنهادی
        )  # پایان where
        slot_row = await database.fetch_one(sel_slot)  # slot_row=گرفتن اسلات
        if not slot_row:  # شرط=اسلات یافت نشد
            raise HTTPException(status_code=404, detail="slot not found for this order")  # خطا=۴۰۴

        provider = _normalize_phone(slot_row["provider_phone"] or "")  # provider=نرمال شماره سرویس‌دهنده
        if not provider:  # شرط=شماره سرویس‌دهنده خالی
            raise HTTPException(status_code=400, detail="provider_phone missing on slot")  # خطا=۴۰۰

        free = await provider_is_free(provider, slot_dt, end_dt, exclude_order_id=order_id)  # free=بررسی تداخل
        if not free:  # شرط=تداخل زمان
            raise HTTPException(status_code=409, detail="selected slot overlaps with existing schedule")  # خطا=۴۰۹

        await database.execute(  # لغو=رزروهای BOOKED قبلی این سفارش غیر از زمان جدید
            AppointmentTable.__table__.update()
            .where(
                (AppointmentTable.request_id == order_id) &
                (AppointmentTable.status == "BOOKED") &
                ((AppointmentTable.start_time != slot_dt) | (AppointmentTable.end_time != end_dt))
            )
            .values(status="CANCELED")
        )

        await database.execute(  # رد=سایر اسلات‌های فعال
            ScheduleSlotTable.__table__.update()
            .where(
                (ScheduleSlotTable.request_id == order_id) &
                (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &
                (ScheduleSlotTable.slot_start != slot_dt)
            )
            .values(status="REJECTED")
        )

        await database.execute(  # قبول=اسلات انتخابی
            ScheduleSlotTable.__table__.update()
            .where(
                (ScheduleSlotTable.request_id == order_id) &
                (ScheduleSlotTable.slot_start == slot_dt)
            )
            .values(status="ACCEPTED")
        )

        # --- FIX: به‌جای INSERT، اگر appointment همان بازه قبلاً وجود دارد UPDATE می‌کنیم ---  # توضیح=رفع خطای uq_provider_slot
        sel_any = AppointmentTable.__table__.select().where(  # sel_any=جستجوی رکورد appointment با همان بازه
            (AppointmentTable.provider_phone == provider) &
            (AppointmentTable.start_time == slot_dt) &
            (AppointmentTable.end_time == end_dt)
        ).limit(1)
        any_row = await database.fetch_one(sel_any)  # any_row=نتیجه

        if any_row:  # شرط=رکورد وجود دارد
            if (str(any_row["status"] or "").strip().upper() == "BOOKED") and (int(any_row["request_id"] or 0) != int(order_id)):  # شرط=BOOKED برای سفارش دیگر
                raise HTTPException(status_code=409, detail="selected slot overlaps with existing schedule")  # خطا=۴۰۹

            await database.execute(  # اجرا=آپدیت رکورد موجود
                AppointmentTable.__table__.update().where(AppointmentTable.id == any_row["id"]).values(
                    request_id=order_id,
                    status="BOOKED"
                )
            )
        else:  # حالت=رکورد وجود ندارد
            try:
                await database.execute(  # insert=رزرو جدید
                    AppointmentTable.__table__.insert().values(
                        provider_phone=provider,
                        request_id=order_id,
                        start_time=slot_dt,
                        end_time=end_dt,
                        status="BOOKED",
                        created_at=datetime.now(timezone.utc)
                    )
                )
            except Exception as e:
                msg = str(e)
                if ("uq_provider_slot" in msg) or ("duplicate key value" in msg):
                    any_row2 = await database.fetch_one(sel_any)
                    if any_row2:
                        if (str(any_row2["status"] or "").strip().upper() == "BOOKED") and (int(any_row2["request_id"] or 0) != int(order_id)):
                            raise HTTPException(status_code=409, detail="selected slot overlaps with existing schedule")
                        await database.execute(
                            AppointmentTable.__table__.update().where(AppointmentTable.id == any_row2["id"]).values(
                                request_id=order_id,
                                status="BOOKED"
                            )
                        )
                    else:
                        raise
                else:
                    raise

        await database.execute(  # آپدیت=سفارش با زمان قطعی
            RequestTable.__table__.update()
            .where(RequestTable.id == order_id)
            .values(scheduled_start=slot_dt, status="ASSIGNED", driver_phone=provider)
        )

    try:  # try=اعلان مدیر
        await notify_managers(
            title="تأیید زمان بازدید",
            body=f"کاربر زمان بازدید را تأیید کرد (order_id={order_id}).",
            data=order_push_data(
                msg_type="time_confirm",
                order_id=order_id,
                status="ASSIGNED",
                service_type=service_type,
                scheduled_start=slot_dt
            ),
            target_phone=_normalize_phone(provider)
        )
    except Exception as e:
        logger.error(f"notify(confirm_slot->manager_only) failed: {e}")

    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": slot_dt.isoformat(), "end": end_dt.isoformat()})
    
# -------------------- Confirm / Finish workflow --------------------

@app.post("/order/{order_id}/finish")  # مسیر=اتمام کار
async def finish_order(order_id: int, request: Request):  # تابع=اتمام سفارش
    require_admin(request)  # احراز=مدیر

    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel=کوئری سفارش
    req = await database.fetch_one(sel)  # req=سفارش
    if not req:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    req = dict(req)  # FIX=تبدیل Record به dict تا .get کار کند

    now_iso = datetime.now(timezone.utc).isoformat()  # now_iso=زمان پایان

    async with database.transaction():  # transaction=اتمیک
        await database.execute(  # آپدیت=سفارش
            RequestTable.__table__.update()  # update=requests
            .where(RequestTable.id == order_id)  # where=id
            .values(status="FINISH", finish_datetime=now_iso)  # values=FINISH+زمان
        )  # پایان execute

        await database.execute(  # آزادسازی=appointmentهای رزرو
            AppointmentTable.__table__.update()  # update=appointments
            .where(  # where
                (AppointmentTable.request_id == order_id) &  # شرط=سفارش
                (AppointmentTable.status == "BOOKED")  # شرط=رزرو
            )  # پایان where
            .values(status="DONE")  # values=DONE
        )  # پایان execute

    try:  # try=اعلان‌ها
        await notify_user(  # اعلان=به کاربر
            phone=req["user_phone"],  # phone=شماره
            title="اتمام کار",  # title=عنوان
            body="سفارش شما انجام شد.",  # body=متن
            data={"type": "work_finished", "order_id": int(order_id), "status": "FINISH"}  # data=داده
        )  # پایان notify_user
        await notify_managers(  # اعلان=به مدیر/سرویس‌دهنده
            title="اتمام کار ثبت شد",  # title=عنوان
            body=f"سفارش {order_id} به اتمام رسید.",  # body=متن
            data={"order_id": int(order_id), "status": "FINISH"},  # data=داده
            target_phone=_normalize_phone(req.get("driver_phone") or "")  # target_phone=هدف
        )  # پایان notify_managers
    except Exception as e:  # خطا
        logger.error(f"notify(finish_order) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "ORDER_FINISHED", "order finished", {"order_id": order_id, "status": "FINISH"})  # پاسخ

@app.post("/admin/order/{order_id}/cancel")  # مسیر=لغو سفارش توسط مدیر
async def admin_cancel_order(order_id: int, request: Request):  # تابع=لغو
    require_admin(request)  # احراز=مدیر

    sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel_req=کوئری سفارش
    req = await database.fetch_one(sel_req)  # req=سفارش
    if not req:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    req = dict(req)  # FIX=تبدیل Record به dict تا .get کار کند

    upd_req = (  # upd_req=آپدیت سفارش
        RequestTable.__table__.update()  # update=requests
        .where(RequestTable.id == order_id)  # where=id
        .values(status="CANCELED", scheduled_start=None, execution_start=None)  # values=لغو+پاکسازی زمان‌ها
        .returning(RequestTable.user_phone, RequestTable.driver_phone, RequestTable.service_type)  # returning=داده لازم
    )  # پایان upd_req
    saved = await database.fetch_one(upd_req)  # saved=خروجی

    await database.execute(  # رد=اسلات‌ها
        ScheduleSlotTable.__table__.update()  # update=schedule_slots
        .where(  # where
            (ScheduleSlotTable.request_id == order_id) &  # شرط=سفارش
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))  # شرط=فعال
        )  # پایان where
        .values(status="REJECTED")  # values=REJECTED
    )  # پایان execute

    await database.execute(  # لغو=appointmentها
        AppointmentTable.__table__.update()  # update=appointments
        .where(  # where
            (AppointmentTable.request_id == order_id) &  # شرط=سفارش
            (AppointmentTable.status == "BOOKED")  # شرط=رزرو
        )  # پایان where
        .values(status="CANCELED")  # values=CANCELED
    )  # پایان execute

    try:  # try=اعلان‌ها
        user_phone = (saved["user_phone"] if saved else req["user_phone"])  # user_phone=شماره کاربر
        driver_phone = (saved["driver_phone"] if saved else req.get("driver_phone")) or ""  # driver_phone=شماره سرویس‌دهنده
        service_type = (saved["service_type"] if saved else req.get("service_type")) or ""  # service_type=نوع سرویس

        await notify_user(  # اعلان=به کاربر
            phone=user_phone,  # phone=کاربر
            title="لغو سفارش",  # title=عنوان
            body="سفارش شما توسط مدیر لغو شد.",  # body=متن
            data={"type": "order_canceled", "order_id": int(order_id), "status": "CANCELED", "service_type": str(service_type)}  # data=داده
        )  # پایان notify_user

        await notify_managers(  # اعلان=به مدیر/سرویس‌دهنده
            title="لغو سفارش توسط مدیر",  # title=عنوان
            body=f"سفارش {order_id} لغو شد.",  # body=متن
            data={"order_id": int(order_id), "status": "CANCELED", "service_type": str(service_type)},  # data=داده
            target_phone=_normalize_phone(driver_phone)  # target_phone=هدف
        )  # پایان notify_managers
    except Exception as e:  # خطا
        logger.error(f"notify(admin_cancel_order) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "ORDER_CANCELED", "order canceled by admin", {"order_id": int(order_id), "status": "CANCELED"})  # پاسخ

# -------------------- New endpoints for user app scheduling --------------------

@app.get("/order/{order_id}/proposed_slots")  # مسیر=اسلات‌های پیشنهادی کاربر
async def get_proposed_slots(order_id: int, request: Request):  # تابع
    sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel_req=کوئری سفارش
    req = await database.fetch_one(sel_req)  # req=سفارش
    if not req:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴
    _ = get_auth_phone(request, fallback_phone=req["user_phone"], enforce=False)  # احراز
    if _ != req["user_phone"]:  # شرط=عدم دسترسی
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    sel = ScheduleSlotTable.__table__.select().where(  # sel=کوئری اسلات‌ها
        (ScheduleSlotTable.request_id == order_id) &  # شرط=سفارش
        (ScheduleSlotTable.status == "PROPOSED")  # شرط=پیشنهادی
    ).order_by(ScheduleSlotTable.slot_start.asc())  # مرتب‌سازی
    rows = await database.fetch_all(sel)  # rows=اجرا
    items = [r["slot_start"].isoformat() for r in rows]  # items=لیست ISO
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})  # پاسخ

# -------------------- Confirm slot (User) --------------------

@app.post("/order/{order_id}/confirm_slot")  # مسیر=تأیید زمان (بدون اسلش)
@app.post("/order/{order_id}/confirm_slot/")  # مسیر=تأیید زمان (با اسلش)
async def confirm_slot(order_id: int, body: ConfirmSlotRequest, request: Request):  # تابع=تأیید زمان بازدید توسط کاربر
    sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel_req=کوئری سفارش
    req_row = await database.fetch_one(sel_req)  # req_row=گرفتن سفارش از دیتابیس
    if not req_row:  # شرط=سفارش وجود ندارد
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    req = dict(req_row)  # req=تبدیل Record به dict برای دسترسی امن با .get

    authed = get_auth_phone(request, fallback_phone=req["user_phone"], enforce=False)  # authed=شماره احراز شده
    if authed != req["user_phone"]:  # شرط=عدم دسترسی
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    if req.get("execution_start") is not None:  # شرط=زمان اجرا قبلاً ثبت شده
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CONFIRM", "message": "cannot confirm slot after execution time is set"})  # خطا=۴۰۹

    st = str(req.get("status") or "").strip().upper()  # st=وضعیت سفارش نرمال
    if st not in ["WAITING", "ASSIGNED", "NEW"]:  # شرط=وضعیت نامعتبر برای تأیید
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CONFIRM", "message": "order is not in schedulable state"})  # خطا=۴۰۹

    slot_dt = parse_iso(body.slot)  # slot_dt=پارس زمان انتخابی (UTC)
    end_dt = slot_dt + timedelta(hours=1)  # end_dt=پایان بازه یک‌ساعته

    service_type = str(req.get("service_type") or "")  # service_type=نوع سرویس سفارش
    provider = ""  # provider=شماره سرویس‌دهنده (از اسلات)

    async with database.transaction():  # transaction=اتمیک
        sel_slot = ScheduleSlotTable.__table__.select().where(  # sel_slot=کوئری اسلات انتخابی
            (ScheduleSlotTable.request_id == order_id) &  # شرط=همین سفارش
            (ScheduleSlotTable.slot_start == slot_dt) &  # شرط=همین زمان
            (ScheduleSlotTable.status == "PROPOSED")  # شرط=اسلات پیشنهادی
        )  # پایان where
        slot_row = await database.fetch_one(sel_slot)  # slot_row=گرفتن اسلات
        if not slot_row:  # شرط=اسلات یافت نشد
            raise HTTPException(status_code=404, detail="slot not found for this order")  # خطا=۴۰۴

        provider = _normalize_phone(slot_row["provider_phone"] or "")  # provider=نرمال شماره سرویس‌دهنده
        if not provider:  # شرط=شماره سرویس‌دهنده خالی
            raise HTTPException(status_code=400, detail="provider_phone missing on slot")  # خطا=۴۰۰

        free = await provider_is_free(provider, slot_dt, end_dt, exclude_order_id=order_id)  # free=بررسی تداخل برنامه
        if not free:  # شرط=تداخل زمان
            raise HTTPException(status_code=409, detail="selected slot overlaps with existing schedule")  # خطا=۴۰۹

        await database.execute(  # لغو=رزروهای BOOKED قبلی این سفارش غیر از زمان جدید
            AppointmentTable.__table__.update()  # update=appointments
            .where(  # where
                (AppointmentTable.request_id == order_id) &  # شرط=همین سفارش
                (AppointmentTable.status == "BOOKED") &  # شرط=رزرو فعال
                ((AppointmentTable.start_time != slot_dt) | (AppointmentTable.end_time != end_dt))  # شرط=غیر از انتخاب جدید
            )  # پایان where
            .values(status="CANCELED")  # values=لغو
        )  # پایان execute

        await database.execute(  # رد=سایر اسلات‌های فعال
            ScheduleSlotTable.__table__.update()  # update=schedule_slots
            .where(  # where
                (ScheduleSlotTable.request_id == order_id) &  # شرط=همین سفارش
                (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &  # شرط=فعال
                (ScheduleSlotTable.slot_start != slot_dt)  # شرط=غیر از انتخابی
            )  # پایان where
            .values(status="REJECTED")  # values=رد شده
        )  # پایان execute

        await database.execute(  # قبول=اسلات انتخابی
            ScheduleSlotTable.__table__.update()  # update=schedule_slots
            .where(  # where
                (ScheduleSlotTable.request_id == order_id) &  # شرط=همین سفارش
                (ScheduleSlotTable.slot_start == slot_dt)  # شرط=همین زمان
            )  # پایان where
            .values(status="ACCEPTED")  # values=پذیرفته
        )  # پایان execute

        sel_exist = AppointmentTable.__table__.select().where(  # sel_exist=بررسی رزرو موجود برای همین زمان
            (AppointmentTable.provider_phone == provider) &  # شرط=provider
            (AppointmentTable.request_id == order_id) &  # شرط=سفارش
            (AppointmentTable.start_time == slot_dt) &  # شرط=شروع
            (AppointmentTable.end_time == end_dt) &  # شرط=پایان
            (AppointmentTable.status == "BOOKED")  # شرط=رزرو
        )  # پایان where
        exist = await database.fetch_one(sel_exist)  # exist=گرفتن رزرو
        if not exist:  # شرط=رزرو وجود ندارد
            await database.execute(  # insert=رزرو جدید
                AppointmentTable.__table__.insert().values(  # values=داده‌ها
                    provider_phone=provider,  # provider_phone=شماره سرویس‌دهنده
                    request_id=order_id,  # request_id=شناسه سفارش
                    start_time=slot_dt,  # start_time=شروع
                    end_time=end_dt,  # end_time=پایان
                    status="BOOKED",  # status=رزرو
                    created_at=datetime.now(timezone.utc)  # created_at=اکنون UTC
                )  # پایان values
            )  # پایان execute

        await database.execute(  # آپدیت=سفارش با زمان قطعی
            RequestTable.__table__.update()  # update=requests
            .where(RequestTable.id == order_id)  # where=id
            .values(scheduled_start=slot_dt, status="ASSIGNED", driver_phone=provider)  # values=زمان قطعی + وضعیت + سرویس‌دهنده
        )  # پایان execute

    # --- تغییر اصلی: اعلان کاربر حذف شد؛ فقط مدیر اعلان می‌گیرد ---  # توضیح=طبق خواسته جدید
    try:  # try=محافظ اعلان مدیر
        await notify_managers(  # اعلان=به مدیر/سرویس‌دهنده
            title="تأیید زمان بازدید",  # title=عنوان
            body=f"کاربر زمان بازدید را تأیید کرد (order_id={order_id}).",  # body=متن
            data=order_push_data(  # data=دیتای استاندارد
                msg_type="time_confirm",  # msg_type=نوع پیام
                order_id=order_id,  # order_id=شناسه سفارش
                status="ASSIGNED",  # status=وضعیت جدید
                service_type=service_type,  # service_type=نوع سرویس
                scheduled_start=slot_dt  # scheduled_start=زمان قطعی بازدید
            ),  # پایان data
            target_phone=_normalize_phone(provider)  # target_phone=شماره مدیر هدف (سرویس‌دهنده)
        )  # پایان notify_managers
    except Exception as e:  # خطا
        logger.error(f"notify(confirm_slot->manager_only) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": slot_dt.isoformat(), "end": end_dt.isoformat()})  # پاسخ=موفقیت
    
@app.post("/order/{order_id}/reject_all_and_cancel")  # مسیر=رد همه و کنسل
async def reject_all_and_cancel(order_id: int, request: Request):  # تابع
    sel_req = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel_req=کوئری سفارش
    req = await database.fetch_one(sel_req)  # req=سفارش
    if not req:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    req = dict(req)  # FIX=تبدیل Record به dict تا .get کار کند

    authed = get_auth_phone(request, fallback_phone=req["user_phone"], enforce=False)  # authed=احراز
    if authed != req["user_phone"]:  # شرط=عدم دسترسی
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    if req.get("execution_start") is not None:  # شرط=زمان اجرا ثبت شده
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CANCEL", "message": "order cannot be canceled at this stage"})  # خطا=۴۰۹

    st = str(req.get("status") or "").strip().upper()  # st=وضعیت
    if st not in ["NEW", "WAITING", "ASSIGNED"]:  # شرط=قابل لغو
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CANCEL", "message": "order cannot be canceled at this stage"})  # خطا=۴۰۹

    await database.execute(  # رد=اسلات‌های فعال
        ScheduleSlotTable.__table__.update()  # update=schedule_slots
        .where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])))  # where=سفارش و فعال
        .values(status="REJECTED")  # values=REJECTED
    )  # پایان execute

    await database.execute(  # لغو=appointmentهای رزرو
        AppointmentTable.__table__.update()  # update=appointments
        .where((AppointmentTable.request_id == order_id) & (AppointmentTable.status == "BOOKED"))  # where=سفارش و رزرو
        .values(status="CANCELED")  # values=CANCELED
    )  # پایان execute

    await database.execute(  # لغو=سفارش
        RequestTable.__table__.update()  # update=requests
        .where(RequestTable.id == order_id)  # where=id
        .values(status="CANCELED", scheduled_start=None, execution_start=None)  # values=لغو+پاکسازی زمان‌ها
    )  # پایان execute

    try:  # try=اعلان مدیر
        await notify_managers(  # اعلان=به مدیر
            title="لغو سفارش",  # title=عنوان
            body=f"سفارش {order_id} توسط کاربر لغو شد.",  # body=متن
            data={"order_id": int(order_id), "status": "CANCELED", "user_phone": _normalize_phone(req["user_phone"])}  # data=داده
        )  # پایان notify_managers
    except Exception as e:  # خطا
        logger.error(f"notify_managers(reject_all_and_cancel) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "ORDER_CANCELED", "order canceled", {"order_id": int(order_id)})  # پاسخ

# -------------------- Profile --------------------

@app.post("/user/profile")  # ذخیره پروفایل
async def update_profile(body: UserProfileUpdate, request: Request):  # تابع
    raw = str(body.phone or "").strip()  # raw=شماره خام
    norm = _normalize_phone(raw)  # norm=شماره نرمال

    auth_phone = _normalize_phone(get_auth_phone(request, fallback_phone=raw, enforce=False))  # auth_phone=احراز نرمال
    if auth_phone != norm:  # شرط=عدم تطابق
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    user = await fetch_user_by_phone_any(raw)  # user=یافتن کاربر با raw/norm
    if not user:  # شرط=نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=۴۰۴

    await database.execute(  # اجرا=update پروفایل
        UserTable.__table__.update()  # update=users
        .where(UserTable.id == user["id"])  # where=id
        .values(name=body.name.strip(), address=body.address.strip())  # values=نام+آدرس
    )  # پایان execute

    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": user["phone"]})  # پاسخ=موفق
    
@app.get("/user/profile/{phone}")  # دریافت پروفایل
async def get_user_profile(phone: str, request: Request):  # تابع
    raw = str(phone or "").strip()  # raw=شماره خام
    norm = _normalize_phone(raw)  # norm=شماره نرمال

    auth_phone = _normalize_phone(get_auth_phone(request, fallback_phone=raw, enforce=False))  # auth_phone=احراز نرمال
    if auth_phone != norm:  # شرط=عدم تطابق
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳

    user = await fetch_user_by_phone_any(raw)  # user=یافتن کاربر
    if not user:  # شرط=نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=۴۰۴

    return unified_response(  # پاسخ
        "ok",  # status=ok
        "PROFILE_FETCHED",  # code=کد
        "profile data",  # message=پیام
        {"phone": user["phone"], "name": user.get("name") or "", "address": user.get("address") or ""}  # data=پروفایل
    )  # پایان پاسخ
    
# -------------------- Debug --------------------

@app.get("/debug/users")  # دیباگ کاربران
async def debug_users():  # تابع
    rows = await database.fetch_all(UserTable.__table__.select())  # rows=همه کاربران
    out = []  # out=خروجی
    for r in rows:  # حلقه=روی کاربران
        out.append({"id": r["id"], "phone": r["phone"], "name": r["name"], "address": r["address"]})  # افزودن=آیتم
    return out  # بازگشت









