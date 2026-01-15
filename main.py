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

FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "").strip()  # مقدار=کلید Legacy FCM

FCM_PROJECT_ID = os.getenv("FCM_PROJECT_ID", "").strip()  # مقدار=ProjectId FCM v1

GOOGLE_APPLICATION_CREDENTIALS_JSON = os.getenv(  # مقدار=Service Account JSON
    "GOOGLE_APPLICATIONS_CREDENTIALS_JSON",  # نام=کلید قدیمی
    os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")  # نام=کلید صحیح
).strip()  # trim=پاکسازی
GOOGLE_APPLICATION_CREDENTIALS_JSON_B64 = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON_B64", "").strip()  # مقدار=Service Account B64

ADMIN_KEY = os.getenv("ADMIN_KEY", "CHANGE_ME_ADMIN").strip()  # مقدار=کلید ادمین (fallback)
ADMIN_PHONES_ENV = os.getenv("ADMIN_PHONES", "").strip()  # مقدار=شماره‌های مدیر

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "600"))  # مقدار=پنجره ورود
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # مقدار=حداکثر تلاش
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "1800"))  # مقدار=قفل موقت

PUSH_BACKEND = os.getenv("PUSH_BACKEND", "fcm").strip().lower()  # مقدار=نوع پوش
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
    if not raw:  # شرط=خالی بودن
        return ""  # خروجی=خالی

    cleaned = "".join(ch for ch in raw if ch.isdigit() or ch == "+")  # cleaned=فقط رقم و +
    if not cleaned:  # شرط=خالی شدن
        return ""  # خروجی=خالی

    if cleaned.startswith("+"):  # شرط=شروع با +
        cleaned = cleaned[1:]  # عمل=حذف +

    if cleaned.startswith("00"):  # شرط=شروع با 00
        cleaned = cleaned[2:]  # عمل=حذف 00

    digits = "".join(ch for ch in cleaned if ch.isdigit())  # digits=فقط رقم
    if not digits:  # شرط=خالی بودن
        return ""  # خروجی=خالی

    if digits.startswith("98") and len(digits) >= 12:  # شرط=پیشوند ایران
        tail10 = digits[-10:]  # tail10=ده رقم آخر
        if tail10.startswith("9"):  # شرط=موبایل
            return "0" + tail10  # خروجی=فرمت 09...

    if digits.startswith("9") and len(digits) == 10:  # شرط=بدون صفر اول
        return "0" + digits  # خروجی=افزودن صفر

    return digits  # خروجی=شماره نهایی

def _parse_admin_phones(s: str) -> set[str]:  # تابع=تبدیل env مدیران به set
    out: set[str] = set()  # out=مجموعه خروجی
    for part in (s or "").split(","):  # حلقه=روی بخش‌ها
        vv = _normalize_phone(part.strip())  # vv=نرمال
        if vv:  # شرط=معتبر
            out.add(vv)  # add=افزودن
    return out  # خروجی=set

ADMIN_PHONES_SET = _parse_admin_phones(ADMIN_PHONES_ENV)  # مقدار=set مدیران

# -------------------- Helpers: time (UTC only) --------------------  # بخش=زمان UTC
def parse_iso(ts: str) -> datetime:  # تابع=پارس ISO با timezone و تبدیل به UTC
    try:  # try=محافظ
        raw = str(ts or "").strip()  # raw=trim
        if raw.endswith("Z"):  # شرط=پسوند Z
            raw = raw.replace("Z", "+00:00")  # عمل=تبدیل Z به آفست
        dt = datetime.fromisoformat(raw)  # dt=پارس ISO
        if dt.tzinfo is None:  # شرط=نبود timezone
            raise ValueError("timezone required")  # خطا=timezone لازم است
        return dt.astimezone(timezone.utc)  # خروجی=UTC
    except Exception:  # catch=خطا
        raise HTTPException(status_code=400, detail=f"invalid UTC datetime: {ts}")  # خطا=۴۰۰

# -------------------- Security helpers --------------------  # بخش=امنیت
def bcrypt_hash_password(password: str) -> str:  # تابع=هش رمز با bcrypt
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # salt=نمک
    mixed = (str(password) + PASSWORD_PEPPER).encode("utf-8")  # mixed=رمز+pepper
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی=هش

def verify_password_secure(password: str, stored_hash: str) -> bool:  # تابع=بررسی رمز با bcrypt
    try:  # try=محافظ
        mixed = (str(password) + PASSWORD_PEPPER).encode("utf-8")  # mixed=رمز+pepper
        return bcrypt.checkpw(mixed, str(stored_hash or "").encode("utf-8"))  # خروجی=نتیجه
    except Exception:  # catch=خطا
        return False  # خروجی=ناموفق

def create_access_token(subject_phone: str) -> str:  # تابع=ساخت access token
    now = datetime.now(timezone.utc)  # now=اکنون UTC
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # exp=انقضا
    payload = {  # payload=دیتای JWT
        "sub": str(subject_phone),  # sub=شماره
        "type": "access",  # type=نوع توکن
        "iat": int(now.timestamp()),  # iat=زمان صدور
        "exp": int(exp.timestamp())  # exp=زمان انقضا
    }  # پایان payload
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # خروجی=JWT

def create_refresh_token() -> str:  # تابع=ساخت رفرش توکن خام
    return secrets.token_urlsafe(48)  # خروجی=توکن امن

def hash_refresh_token(token: str) -> str:  # تابع=هش رفرش توکن برای ذخیره
    return hashlib.sha256((str(token) + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # خروجی=هش

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # تابع=پاسخ واحد
    return {"status": status, "code": code, "message": message, "data": (data or {})}  # خروجی=دیکشنری

def extract_bearer_token(request: Request) -> Optional[str]:  # تابع=استخراج Bearer
    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""  # auth=هدر
    if not auth.lower().startswith("bearer "):  # شرط=نبود Bearer
        return None  # خروجی=None
    return auth.split(" ", 1)[1].strip()  # خروجی=توکن

def decode_access_token(token: str) -> Optional[dict]:  # تابع=دیکود JWT access
    try:  # try=محافظ
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # payload=decode
        if payload.get("type") != "access":  # شرط=نوع نادرست
            return None  # خروجی=None
        return payload  # خروجی=payload
    except Exception:  # catch=خطا
        return None  # خروجی=None

def require_user_phone(request: Request, expected_phone: str) -> str:  # تابع=الزام Bearer و تطبیق شماره
    token = extract_bearer_token(request)  # token=توکن
    if not token:  # شرط=نبود توکن
        raise HTTPException(status_code=401, detail="missing bearer token")  # خطا=۴۰۱
    payload = decode_access_token(token)  # payload=دیکود
    if not payload or not payload.get("sub"):  # شرط=نامعتبر
        raise HTTPException(status_code=401, detail="invalid token")  # خطا=۴۰۱
    sub = _normalize_phone(str(payload.get("sub") or ""))  # sub=شماره نرمال از توکن
    exp = _normalize_phone(expected_phone)  # exp=شماره نرمال مسیر/بدنه
    if sub != exp:  # شرط=عدم تطابق
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=۴۰۳
    return sub  # خروجی=شماره معتبر

def get_client_ip(request: Request) -> str:  # تابع=گرفتن IP کلاینت
    xff = request.headers.get("x-forwarded-for", "")  # xff=هدر پروکسی
    if xff:  # شرط=وجود xff
        return xff.split(",")[0].strip()  # خروجی=اولین IP
    return request.client.host or "unknown"  # خروجی=IP

def require_admin(request: Request) -> None:  # تابع=الزام مدیر (Bearer یا X-Admin-Key)
    token = extract_bearer_token(request)  # token=توکن
    if token:  # شرط=وجود توکن
        payload = decode_access_token(token)  # payload=دیکود
        sub = _normalize_phone(str((payload or {}).get("sub") or ""))  # sub=شماره نرمال
        if sub and sub in ADMIN_PHONES_SET:  # شرط=مدیر بودن
            return  # خروج=قبول
    key = (request.headers.get("x-admin-key") or request.headers.get("X-Admin-Key") or "").strip()  # key=کلید
    if key and key == ADMIN_KEY:  # شرط=کلید صحیح
        return  # خروج=قبول
    raise HTTPException(status_code=401, detail="admin auth required")  # خطا=۴۰۱

def get_admin_provider_phone(request: Request) -> str:  # تابع=گرفتن شماره سرویس‌دهنده مدیر
    token = extract_bearer_token(request)  # token=توکن
    if token:  # شرط=وجود توکن
        payload = decode_access_token(token)  # payload=دیکود
        sub = _normalize_phone(str((payload or {}).get("sub") or ""))  # sub=شماره نرمال
        if sub and sub in ADMIN_PHONES_SET:  # شرط=مدیر بودن
            return sub  # خروجی=شماره مدیر
    if ADMIN_PHONES_SET:  # شرط=وجود مدیر در env
        return sorted(list(ADMIN_PHONES_SET))[0]  # خروجی=اولین شماره
    raise HTTPException(status_code=400, detail="admin provider phone not available")  # خطا=۴۰۰

# -------------------- ORM models --------------------  # بخش=مدل‌های دیتابیس
class UserTable(Base):  # کلاس=جدول کاربران
    __tablename__ = "users"  # نام جدول=users
    id = Column(Integer, primary_key=True, index=True)  # ستون=id
    phone = Column(String, unique=True, index=True)  # ستون=شماره (نرمال)
    password_hash = Column(String)  # ستون=هش رمز
    address = Column(String)  # ستون=آدرس
    name = Column(String, default="")  # ستون=نام
    car_list = Column(JSONB, default=list)  # ستون=لیست خودرو

class DriverTable(Base):  # کلاس=جدول راننده
    __tablename__ = "drivers"  # نام جدول=drivers
    id = Column(Integer, primary_key=True, index=True)  # ستون=id
    first_name = Column(String)  # ستون=نام
    last_name = Column(String)  # ستون=نام خانوادگی
    photo_url = Column(String)  # ستون=عکس
    id_card_number = Column(String)  # ستون=کارت
    phone = Column(String, unique=True, index=True)  # ستون=شماره
    phone_verified = Column(Boolean, default=False)  # ستون=تایید
    is_online = Column(Boolean, default=False)  # ستون=آنلاین
    status = Column(String, default="فعال")  # ستون=وضعیت

class RequestTable(Base):  # کلاس=جدول سفارش‌ها
    __tablename__ = "requests"  # نام جدول=requests
    id = Column(Integer, primary_key=True, index=True)  # ستون=id
    user_phone = Column(String, index=True)  # ستون=شماره کاربر (نرمال)
    latitude = Column(Float)  # ستون=lat
    longitude = Column(Float)  # ستون=lng
    car_list = Column(JSONB)  # ستون=لیست خودرو/خدمات
    address = Column(String)  # ستون=آدرس
    home_number = Column(String, default="")  # ستون=پلاک
    service_type = Column(String, index=True)  # ستون=نوع سرویس
    price = Column(Integer)  # ستون=قیمت
    request_datetime = Column(String)  # ستون=زمان ثبت (رشته)
    status = Column(String)  # ستون=وضعیت
    driver_name = Column(String)  # ستون=نام سرویس‌دهنده
    driver_phone = Column(String)  # ستون=شماره سرویس‌دهنده (نرمال)
    finish_datetime = Column(String)  # ستون=زمان پایان (رشته)
    payment_type = Column(String)  # ستون=پرداخت
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # ستون=زمان بازدید (UTC)
    service_place = Column(String, default="client")  # ستون=محل سرویس
    execution_start = Column(DateTime(timezone=True), nullable=True)  # ستون=زمان اجرا (UTC)

class RefreshTokenTable(Base):  # کلاس=جدول refresh token
    __tablename__ = "refresh_tokens"  # نام جدول=refresh_tokens
    id = Column(Integer, primary_key=True, index=True)  # ستون=id
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # ستون=user_id
    token_hash = Column(String, unique=True, index=True)  # ستون=هش توکن
    expires_at = Column(DateTime(timezone=True), index=True)  # ستون=انقضا
    revoked = Column(Boolean, default=False)  # ستون=ابطال
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ستون=ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # ایندکس=ترکیبی

class LoginAttemptTable(Base):  # کلاس=جدول تلاش ورود
    __tablename__ = "login_attempts"  # نام جدول=login_attempts
    id = Column(Integer, primary_key=True, index=True)  # ستون=id
    phone = Column(String, index=True)  # ستون=شماره (نرمال)
    ip = Column(String, index=True)  # ستون=ip
    attempt_count = Column(Integer, default=0)  # ستون=تعداد تلاش
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ستون=شروع پنجره
    locked_until = Column(DateTime(timezone=True), nullable=True)  # ستون=قفل تا
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ستون=آخرین تلاش
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ستون=ایجاد
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)  # ایندکس=phone+ip

class ScheduleSlotTable(Base):  # کلاس=جدول زمان‌های پیشنهادی
    __tablename__ = "schedule_slots"  # نام جدول=schedule_slots
    id = Column(Integer, primary_key=True, index=True)  # ستون=id
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # ستون=request_id
    provider_phone = Column(String, index=True)  # ستون=شماره سرویس‌دهنده
    slot_start = Column(DateTime(timezone=True), index=True)  # ستون=شروع (UTC)
    status = Column(String, default="PROPOSED")  # ستون=وضعیت
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ستون=ایجاد
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)  # ایندکس=req+status

class AppointmentTable(Base):  # کلاس=جدول رزرو قطعی
    __tablename__ = "appointments"  # نام جدول=appointments
    id = Column(Integer, primary_key=True, index=True)  # ستون=id
    provider_phone = Column(String, index=True)  # ستون=شماره سرویس‌دهنده
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # ستون=request_id
    start_time = Column(DateTime(timezone=True), index=True)  # ستون=شروع (UTC)
    end_time = Column(DateTime(timezone=True), index=True)  # ستون=پایان (UTC)
    status = Column(String, default="BOOKED")  # ستون=وضعیت
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ستون=ایجاد
    __table_args__ = (  # table_args=قیود/ایندکس‌ها
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),  # قید=یکتا بودن بازه
        Index("ix_provider_time", "provider_phone", "start_time", "end_time")  # ایندکس=زمانی
    )  # پایان table_args

class NotificationTable(Base):  # کلاس=جدول اعلان‌ها
    __tablename__ = "notifications"  # نام جدول=notifications
    id = Column(Integer, primary_key=True, index=True)  # ستون=id
    user_phone = Column(String, index=True)  # ستون=شماره گیرنده
    title = Column(String)  # ستون=عنوان
    body = Column(String)  # ستون=متن
    data = Column(JSONB, default=dict)  # ستون=data
    read = Column(Boolean, default=False, index=True)  # ستون=خوانده شده؟
    read_at = Column(DateTime(timezone=True), nullable=True)  # ستون=زمان خواندن
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)  # ستون=ایجاد
    __table_args__ = (Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),)  # ایندکس=ترکیبی

class DeviceTokenTable(Base):  # کلاس=توکن دستگاه
    __tablename__ = "device_tokens"  # نام جدول=device_tokens
    id = Column(Integer, primary_key=True, index=True)  # ستون=id
    token = Column(String, unique=True, index=True)  # ستون=توکن
    role = Column(String, index=True)  # ستون=نقش
    platform = Column(String, default="android", index=True)  # ستون=پلتفرم
    user_phone = Column(String, nullable=True)  # ستون=شماره (اختیاری)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ستون=ایجاد
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ستون=آپدیت
    __table_args__ = (Index("ix_tokens_role_platform", "role", "platform"),)  # ایندکس=role+platform
# -------------------- Pydantic models --------------------  # بخش=مدل‌های ورودی/خروجی API

class CarInfo(BaseModel):  # کلاس=مدل خودرو برای ذخیره لیست ماشین
    brand: str  # فیلد=برند
    model: str  # فیلد=مدل
    plate: str  # فیلد=پلاک

class Location(BaseModel):  # کلاس=مدل موقعیت مکانی
    latitude: float  # فیلد=عرض جغرافیایی
    longitude: float  # فیلد=طول جغرافیایی

class CarOrderItem(BaseModel):  # کلاس=آیتم سفارش برای یک خودرو/خدمت
    brand: str  # فیلد=برند
    model: str  # فیلد=مدل
    plate: str  # فیلد=پلاک
    wash_outside: bool = False  # فیلد=روشویی
    wash_inside: bool = False  # فیلد=توشویی
    polish: bool = False  # فیلد=پولیش

class OrderRequest(BaseModel):  # کلاس=ثبت سفارش
    user_phone: str  # فیلد=شماره کاربر
    location: Location  # فیلد=موقعیت
    car_list: List[CarOrderItem]  # فیلد=لیست خودروها
    address: str  # فیلد=آدرس
    home_number: Optional[str] = ""  # فیلد=پلاک خانه
    service_type: str  # فیلد=نوع سرویس
    price: int  # فیلد=قیمت
    request_datetime: str  # فیلد=زمان ثبت (رشته)
    payment_type: str  # فیلد=نوع پرداخت
    service_place: str  # فیلد=محل سرویس (client/provider)

class CarListUpdateRequest(BaseModel):  # کلاس=آپدیت لیست خودروها
    user_phone: str  # فیلد=شماره کاربر
    car_list: List[CarInfo]  # فیلد=لیست خودرو

class CancelRequest(BaseModel):  # کلاس=لغو سفارش
    user_phone: str  # فیلد=شماره کاربر
    service_type: str  # فیلد=نوع سرویس

class UserRegisterRequest(BaseModel):  # کلاس=ثبت‌نام
    phone: str  # فیلد=شماره
    password: str  # فیلد=رمز
    address: Optional[str] = None  # فیلد=آدرس

class UserLoginRequest(BaseModel):  # کلاس=ورود
    phone: str  # فیلد=شماره
    password: str  # فیلد=رمز

class UserProfileUpdate(BaseModel):  # کلاس=آپدیت پروفایل
    phone: str  # فیلد=شماره
    name: str = ""  # فیلد=نام
    address: str = ""  # فیلد=آدرس

class ProposedSlotsRequest(BaseModel):  # کلاس=ارسال زمان‌های پیشنهادی
    slots: List[str]  # فیلد=لیست ISO UTC

class ConfirmSlotRequest(BaseModel):  # کلاس=تأیید زمان بازدید
    slot: str  # فیلد=زمان ISO UTC

class PriceBody(BaseModel):  # کلاس=ثبت قیمت و توافق
    price: int  # فیلد=قیمت
    agree: bool  # فیلد=موافقت
    exec_time: Optional[str] = None  # فیلد=زمان اجرا ISO UTC

class PushRegister(BaseModel):  # کلاس=ثبت توکن پوش
    role: str  # فیلد=نقش (client/manager)
    token: str  # فیلد=توکن FCM
    platform: str = "android"  # فیلد=پلتفرم
    user_phone: Optional[str] = None  # فیلد=شماره (اختیاری)

class PushUnregister(BaseModel):  # کلاس=لغو ثبت پوش
    token: str  # فیلد=توکن

class LogoutRequest(BaseModel):  # کلاس=خروج
    refresh_token: str  # فیلد=رفرش توکن
    device_token: Optional[str] = None  # فیلد=توکن دستگاه برای حذف

class RefreshAccessRequest(BaseModel):  # کلاس=رفرش access
    refresh_token: str  # فیلد=رفرش توکن

# -------------------- Push helpers --------------------  # بخش=توابع ارسال پوش

_FCM_OAUTH_TOKEN = ""  # متغیر=کش توکن OAuth
_FCM_OAUTH_EXP = 0.0  # متغیر=زمان انقضای OAuth

def _load_service_account() -> Optional[dict]:  # تابع=خواندن service account برای FCM v1
    raw = GOOGLE_APPLICATION_CREDENTIALS_JSON  # raw=json خام
    if not raw and GOOGLE_APPLICATION_CREDENTIALS_JSON_B64:  # شرط=داشتن b64
        try:  # try=محافظ
            raw = base64.b64decode(GOOGLE_APPLICATION_CREDENTIALS_JSON_B64).decode("utf-8")  # decode=تبدیل b64 به json
        except Exception:  # catch=خطا
            raw = ""  # مقدار=خالی
    if not raw:  # شرط=خالی بودن
        return None  # خروجی=None
    try:  # try=محافظ
        data = json.loads(raw)  # data=پارس json
        if "client_email" in data and "private_key" in data:  # شرط=کلیدهای لازم
            pk = str(data.get("private_key", ""))  # pk=کلید خصوصی
            if "\\n" in pk:  # شرط=وجود \n اسکیپ
                data["private_key"] = pk.replace("\\n", "\n")  # عمل=تبدیل به خط جدید واقعی
            return data  # خروجی=data
    except Exception:  # catch=خطا
        return None  # خروجی=None
    return None  # خروجی=None

def _get_oauth2_token_for_fcm() -> Optional[str]:  # تابع=گرفتن OAuth token برای FCM v1
    global _FCM_OAUTH_TOKEN, _FCM_OAUTH_EXP  # global=استفاده از کش
    now = time.time()  # now=زمان فعلی
    if _FCM_OAUTH_TOKEN and (_FCM_OAUTH_EXP - 60) > now:  # شرط=معتبر بودن کش
        return _FCM_OAUTH_TOKEN  # خروجی=توکن کش
    sa = _load_service_account()  # sa=service account
    if not sa:  # شرط=نبودن
        return None  # خروجی=None
    issued = int(now)  # issued=iat
    expires = issued + 3600  # expires=exp
    payload = {  # payload=JWT assertion
        "iss": sa["client_email"],  # iss=ایمیل سرویس
        "scope": "https://www.googleapis.com/auth/firebase.messaging",  # scope=مجوز FCM
        "aud": "https://oauth2.googleapis.com/token",  # aud=توکن گوگل
        "iat": issued,  # iat=زمان صدور
        "exp": expires  # exp=زمان انقضا
    }  # پایان payload
    assertion = jwt.encode(payload, sa["private_key"], algorithm="RS256")  # assertion=JWT امضاشده
    resp = httpx.post(  # resp=درخواست توکن OAuth
        "https://oauth2.googleapis.com/token",  # url=توکن گوگل
        data={  # data=form
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",  # grant=نوع گرانت
            "assertion": assertion  # assertion=JWT
        },  # پایان data
        timeout=10.0  # timeout=مهلت
    )  # پایان post
    if resp.status_code != 200:  # شرط=عدم موفقیت
        return None  # خروجی=None
    data = resp.json()  # data=پارس json پاسخ
    token = str(data.get("access_token", "")).strip()  # token=access_token
    if not token:  # شرط=نبود توکن
        return None  # خروجی=None
    _FCM_OAUTH_TOKEN = token  # ذخیره=توکن در کش
    _FCM_OAUTH_EXP = now + int(data.get("expires_in", 3600))  # ذخیره=زمان انقضا
    return token  # خروجی=توکن

def _to_fcm_data(data: dict) -> dict:  # تابع=تبدیل دیتا به string برای FCM
    out: Dict[str, str] = {}  # out=دیکشنری خروجی
    for k, v in (data or {}).items():  # حلقه=روی کلیدها
        if v is None:  # شرط=None
            continue  # ادامه=رد
        out[str(k)] = str(v)  # تبدیل=به رشته
    return out  # خروجی=دیتای رشته‌ای

def order_push_data(  # تابع=ساخت payload استاندارد برای اپ‌ها
    msg_type: str,  # ورودی=نوع پیام
    order_id: int,  # ورودی=شناسه سفارش
    status: str,  # ورودی=وضعیت
    service_type: str = "",  # ورودی=نوع سرویس
    scheduled_start: Optional[datetime] = None,  # ورودی=زمان بازدید
    execution_start: Optional[datetime] = None,  # ورودی=زمان اجرا
    price: Optional[int] = None  # ورودی=قیمت
) -> dict:  # خروجی=دیکشنری data
    data = {  # data=بدنه اصلی
        "type": str(msg_type or "").strip(),  # type=نوع
        "order_id": str(int(order_id)),  # order_id=رشته
        "status": str(status or "").strip()  # status=رشته
    }  # پایان data
    if service_type:  # شرط=وجود سرویس
        data["service_type"] = str(service_type).strip()  # service_type=ثبت
    if scheduled_start is not None:  # شرط=وجود زمان بازدید
        data["scheduled_start"] = scheduled_start.astimezone(timezone.utc).isoformat()  # scheduled_start=ISO UTC
    if execution_start is not None:  # شرط=وجود زمان اجرا
        data["execution_start"] = execution_start.astimezone(timezone.utc).isoformat()  # execution_start=ISO UTC
    if price is not None:  # شرط=وجود قیمت
        data["price"] = str(int(price))  # price=رشته
    return data  # خروجی=data

async def _send_fcm_legacy(tokens: List[str], title: str, body: str, data: dict) -> None:  # تابع=ارسال Legacy FCM (Data-only)
    if not tokens:  # شرط=توکن خالی
        return  # خروج
    if not FCM_SERVER_KEY:  # شرط=کلید خالی
        logger.error("FCM_SERVER_KEY is empty")  # لاگ=خطا
        return  # خروج

    headers = {  # headers=هدرها
        "Authorization": f"key={FCM_SERVER_KEY}",  # Authorization=کلید legacy
        "Content-Type": "application/json"  # Content-Type=json
    }  # پایان headers

    merged = dict(data or {})  # merged=کپی data
    merged["title"] = str(title or "")  # title=در data
    merged["body"] = str(body or "")  # body=در data

    payload = {  # payload=بدنه درخواست FCM legacy
        "registration_ids": tokens,  # registration_ids=توکن‌ها
        "priority": "high",  # priority=بالا
        "data": _to_fcm_data(merged)  # data=Data-only
    }  # پایان payload

    async with httpx.AsyncClient(timeout=10.0) as client:  # client=کلاینت async
        resp = await client.post("https://fcm.googleapis.com/fcm/send", headers=headers, json=payload)  # ارسال=POST
    if resp.status_code != 200:  # شرط=عدم موفقیت
        logger.error(f"FCM legacy send failed HTTP_{resp.status_code} body={resp.text}")  # لاگ=خطا

async def _send_fcm_v1_single(token: str, title: str, body: str, data: dict) -> None:  # تابع=ارسال FCM v1 تک‌توکن
    access = _get_oauth2_token_for_fcm()  # access=توکن OAuth
    if not access:  # شرط=نبود OAuth
        logger.error("FCM v1 oauth token not available")  # لاگ=خطا
        return  # خروج
    if not FCM_PROJECT_ID:  # شرط=نبود project id
        logger.error("FCM_PROJECT_ID is empty")  # لاگ=خطا
        return  # خروج

    headers = {  # headers=هدرها
        "Authorization": f"Bearer {access}",  # Authorization=Bearer
        "Content-Type": "application/json"  # Content-Type=json
    }  # پایان headers

    merged = dict(data or {})  # merged=کپی دیتا
    merged["title"] = str(title or "")  # title=در data
    merged["body"] = str(body or "")  # body=در data

    msg = {  # msg=بدنه پیام v1
        "message": {  # message=پیام
            "token": str(token or "").strip(),  # token=توکن مقصد
            "android": {"priority": "HIGH"},  # android=اولویت بالا
            "data": _to_fcm_data(merged)  # data=Data-only
        }  # پایان message
    }  # پایان msg

    url = f"https://fcm.googleapis.com/v1/projects/{FCM_PROJECT_ID}/messages:send"  # url=اندپوینت v1
    async with httpx.AsyncClient(timeout=10.0) as client:  # client=کلاینت async
        resp = await client.post(url, headers=headers, json=msg)  # ارسال=POST
    if resp.status_code not in (200, 201):  # شرط=عدم موفقیت
        logger.error(f"FCM v1 send failed HTTP_{resp.status_code} body={resp.text}")  # لاگ=خطا

async def push_notify_tokens(tokens: List[str], title: str, body: str, data: dict) -> None:  # تابع=ارسال پوش به لیست توکن‌ها
    if not tokens:  # شرط=توکن خالی
        return  # خروج
    if PUSH_BACKEND == "fcm":  # شرط=بک‌اند FCM
        if FCM_PROJECT_ID and (_load_service_account() is not None):  # شرط=امکان v1
            for t in tokens:  # حلقه=روی توکن‌ها
                await _send_fcm_v1_single(t, title, body, data)  # ارسال=v1
            return  # خروج
        await _send_fcm_legacy(tokens, title, body, data)  # ارسال=legacy
        return  # خروج
    if PUSH_BACKEND == "ntfy":  # شرط=بک‌اند ntfy
        base = (NTFY_BASE_URL or "https://ntfy.sh").strip()  # base=آدرس
        headers: Dict[str, str] = {}  # headers=هدرها
        if NTFY_AUTH:  # شرط=وجود auth
            headers["Authorization"] = NTFY_AUTH  # set=هدر auth
        async with httpx.AsyncClient(timeout=10.0) as client:  # client=کلاینت async
            for topic in tokens:  # حلقه=topic
                await client.post(f"{base}/{topic}", headers=headers, data=body.encode("utf-8"))  # ارسال=POST
        return  # خروج
    logger.error(f"unknown PUSH_BACKEND={PUSH_BACKEND}")  # لاگ=بک‌اند ناشناخته

async def get_manager_tokens(target_phone: Optional[str] = None) -> List[str]:  # تابع=گرفتن توکن‌های مدیر
    q = DeviceTokenTable.__table__.select().where(  # q=کوئری
        (DeviceTokenTable.role == "manager") &  # شرط=role manager
        (DeviceTokenTable.platform == "android")  # شرط=android
    )  # پایان where
    if target_phone:  # شرط=شماره هدف
        q = q.where(DeviceTokenTable.user_phone == _normalize_phone(target_phone))  # شرط=شماره
    rows = await database.fetch_all(q)  # rows=اجرا
    seen: set[str] = set()  # seen=جلوگیری از تکرار
    out: List[str] = []  # out=خروجی
    for r in rows:  # حلقه=روی ردیف‌ها
        t = str(r["token"] or "").strip()  # t=توکن
        if t and t not in seen:  # شرط=توکن معتبر و غیرتکراری
            seen.add(t)  # add=به seen
            out.append(t)  # add=به خروجی
    return out  # خروجی=لیست

async def get_user_tokens(phone: str) -> List[str]:  # تابع=گرفتن توکن‌های کاربر
    norm = _normalize_phone(phone)  # norm=شماره نرمال
    q = DeviceTokenTable.__table__.select().where(  # q=کوئری
        (DeviceTokenTable.role.in_(["client", "user"])) &  # شرط=نقش کاربر
        (DeviceTokenTable.platform == "android") &  # شرط=اندروید
        (DeviceTokenTable.user_phone == norm)  # شرط=شماره
    )  # پایان where
    rows = await database.fetch_all(q)  # rows=اجرا
    seen: set[str] = set()  # seen=جلوگیری از تکرار
    out: List[str] = []  # out=خروجی
    for r in rows:  # حلقه=روی ردیف‌ها
        t = str(r["token"] or "").strip()  # t=توکن
        if t and t not in seen:  # شرط=توکن معتبر و غیرتکراری
            seen.add(t)  # add=به seen
            out.append(t)  # add=به خروجی
    return out  # خروجی=لیست

async def notify_user(phone: str, title: str, body: str, data: Optional[dict] = None) -> None:  # تابع=ثبت اعلان + ارسال پوش کاربر
    norm = _normalize_phone(phone)  # norm=شماره نرمال
    ins = NotificationTable.__table__.insert().values(  # ins=درج اعلان
        user_phone=norm,  # user_phone=شماره
        title=str(title or ""),  # title=عنوان
        body=str(body or ""),  # body=متن
        data=(data or {}),  # data=داده
        read=False,  # read=خوانده نشده
        created_at=datetime.now(timezone.utc)  # created_at=اکنون
    )  # پایان insert
    await database.execute(ins)  # اجرا=insert

    tokens = await get_user_tokens(norm)  # tokens=توکن‌های کاربر
    if not tokens:  # شرط=بدون توکن
        logger.info(f"no user tokens for phone={norm}")  # لاگ=بدون توکن
        return  # خروج
    await push_notify_tokens(tokens, str(title or ""), str(body or ""), (data or {}))  # ارسال پوش

async def notify_managers(title: str, body: str, data: Optional[dict] = None, target_phone: Optional[str] = None) -> None:  # تابع=ارسال اعلان به مدیرها
    tokens = await get_manager_tokens(target_phone=target_phone)  # tokens=توکن‌های هدف یا همه
    if not tokens and not target_phone:  # شرط=بدون توکن و بدون هدف
        logger.info("no manager tokens")  # لاگ=بدون توکن
        return  # خروج
    if not tokens and target_phone:  # شرط=شماره هدف ولی توکن ندارد
        tokens = await get_manager_tokens(target_phone=None)  # tokens=همه مدیرها
    if not tokens:  # شرط=باز هم خالی
        logger.info("no manager tokens")  # لاگ=بدون توکن
        return  # خروج
    await push_notify_tokens(tokens, str(title or ""), str(body or ""), (data or {}))  # ارسال پوش
# -------------------- App & CORS --------------------  # بخش=ساخت اپ و CORS

app = FastAPI()  # app=ساخت اپ FastAPI

allow_origins = ["*"] if ALLOW_ORIGINS_ENV == "*" else [  # allow_origins=لیست origin ها
    o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()  # پارس=از env
]  # پایان allow_origins

app.add_middleware(  # افزودن=middleware
    CORSMiddleware,  # نوع=CORSMiddleware
    allow_origins=allow_origins,  # تنظیم=origin های مجاز
    allow_credentials=True,  # تنظیم=اجازه credential
    allow_methods=["*"],  # تنظیم=تمام متدها
    allow_headers=["*"],  # تنظیم=تمام هدرها
)  # پایان add_middleware

# -------------------- Startup / Shutdown --------------------  # بخش=شروع/پایان برنامه

@app.on_event("startup")  # رویداد=startup
async def startup() -> None:  # تابع=startup
    if not DATABASE_URL:  # شرط=آدرس دیتابیس خالی
        raise RuntimeError("DATABASE_URL is empty")  # خطا=عدم تنظیم دیتابیس

    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # engine=ساخت engine sync
    Base.metadata.create_all(engine)  # create_all=ساخت جداول

    with engine.begin() as conn:  # conn=اتصال تراکنشی sync
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # مهاجرت=افزودن scheduled_start
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS execution_start TIMESTAMPTZ NULL;"))  # مهاجرت=افزودن execution_start
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place VARCHAR DEFAULT 'client';"))  # مهاجرت=افزودن service_place
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_schedule_slots_provider_start_active ON schedule_slots (provider_phone, slot_start) WHERE status IN ('PROPOSED','ACCEPTED');"))  # ایندکس=یونیک اسلات فعال

    await database.connect()  # اتصال=async به دیتابیس

@app.on_event("shutdown")  # رویداد=shutdown
async def shutdown() -> None:  # تابع=shutdown
    await database.disconnect()  # قطع اتصال=async

# -------------------- Health --------------------  # بخش=سلامت سرور

@app.get("/")  # مسیر=ریشه
def read_root():  # تابع=سلامت
    return {"message": "Putzfee FastAPI Server is running!"}  # پاسخ=متن سلامت

# -------------------- Token verify --------------------  # بخش=اعتبارسنجی توکن

@app.get("/verify_token")  # مسیر=بررسی توکن
def verify_token(request: Request):  # تابع=verify_token
    token = extract_bearer_token(request)  # token=توکن Bearer
    if not token:  # شرط=نبود توکن
        return {"status": "ok", "valid": False}  # پاسخ=نامعتبر
    payload = decode_access_token(token)  # payload=دیکود
    return {"status": "ok", "valid": bool(payload and payload.get("sub"))}  # پاسخ=معتبر یا نامعتبر

# -------------------- Auth: refresh --------------------  # بخش=رفرش توکن دسترسی

@app.post("/auth/refresh")  # مسیر=رفرش access
async def refresh_access(body: RefreshAccessRequest):  # تابع=رفرش
    raw = str(body.refresh_token or "").strip()  # raw=رفرش خام
    if not raw:  # شرط=خالی
        raise HTTPException(status_code=400, detail="refresh_token required")  # خطا=۴۰۰

    token_hash = hash_refresh_token(raw)  # token_hash=هش رفرش
    sel = RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash)  # sel=کوئری رفرش
    row = await database.fetch_one(sel)  # row=گرفتن ردیف

    if not row:  # شرط=نبود
        raise HTTPException(status_code=401, detail="invalid refresh token")  # خطا=۴۰۱
    if bool(row["revoked"]):  # شرط=ابطال شده
        raise HTTPException(status_code=401, detail="refresh token revoked")  # خطا=۴۰۱

    now = datetime.now(timezone.utc)  # now=اکنون UTC
    exp = row["expires_at"]  # exp=انقضا
    if exp is None or exp <= now:  # شرط=منقضی
        raise HTTPException(status_code=401, detail="refresh token expired")  # خطا=۴۰۱

    user_id = int(row["user_id"])  # user_id=شناسه کاربر
    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.id == user_id))  # user=کاربر
    if not user:  # شرط=نبود کاربر
        raise HTTPException(status_code=401, detail="user not found")  # خطا=۴۰۱

    access = create_access_token(_normalize_phone(user["phone"]))  # access=توکن جدید
    return unified_response("ok", "ACCESS_REFRESHED", "access token refreshed", {"access_token": access})  # پاسخ=توکن جدید

# -------------------- Logout --------------------  # بخش=خروج

@app.post("/logout")  # مسیر=خروج
async def logout_user(body: LogoutRequest):  # تابع=logout
    refresh_raw = str(body.refresh_token or "").strip()  # refresh_raw=رفرش ورودی
    if not refresh_raw:  # شرط=خالی
        raise HTTPException(status_code=400, detail="refresh_token required")  # خطا=۴۰۰

    token_hash = hash_refresh_token(refresh_raw)  # token_hash=هش رفرش

    rt_row = await database.fetch_one(  # rt_row=خواندن ردیف رفرش
        RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash)  # select=بر اساس هش
    )  # پایان fetch_one

    await database.execute(  # اجرا=revoked کردن رفرش
        RefreshTokenTable.__table__.update().where(RefreshTokenTable.token_hash == token_hash).values(revoked=True)  # update=revoked
    )  # پایان execute

    device_token = str(body.device_token or "").strip()  # device_token=توکن دستگاه ورودی
    if device_token:  # شرط=توکن دستگاه داده شده
        await database.execute(  # اجرا=حذف آن توکن
            DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == device_token)  # delete=توکن
        )  # پایان execute
    else:  # حالت=توکن دستگاه داده نشده
        if rt_row:  # شرط=ردیف رفرش داریم
            user = await database.fetch_one(UserTable.__table__.select().where(UserTable.id == int(rt_row["user_id"])))  # user=کاربر
            if user:  # شرط=کاربر موجود
                phone = _normalize_phone(user["phone"])  # phone=شماره نرمال
                await database.execute(  # اجرا=حذف همه توکن‌های کاربر
                    DeviceTokenTable.__table__.delete().where(DeviceTokenTable.user_phone == phone)  # delete=بر اساس شماره
                )  # پایان execute

    return unified_response("ok", "LOGOUT", "refresh token revoked and device tokens removed", {})  # پاسخ=خروج موفق

# -------------------- Push endpoints --------------------  # بخش=ثبت/حذف توکن پوش

@app.post("/push/register")  # مسیر=ثبت توکن پوش
async def register_push_token(body: PushRegister):  # تابع=register push
    now = datetime.now(timezone.utc)  # now=اکنون UTC
    norm_phone = _normalize_phone(body.user_phone) if body.user_phone else None  # norm_phone=شماره نرمال یا None

    sel = DeviceTokenTable.__table__.select().where(DeviceTokenTable.token == str(body.token).strip())  # sel=کوئری توکن
    row = await database.fetch_one(sel)  # row=ردیف موجود

    if row is None:  # شرط=توکن جدید
        await database.execute(  # اجرا=insert توکن
            DeviceTokenTable.__table__.insert().values(  # insert=مقادیر
                token=str(body.token).strip(),  # token=توکن
                role=str(body.role).strip(),  # role=نقش
                platform=str(body.platform or "android").strip(),  # platform=پلتفرم
                user_phone=norm_phone,  # user_phone=شماره
                created_at=now,  # created_at=اکنون
                updated_at=now  # updated_at=اکنون
            )  # پایان values
        )  # پایان execute
    else:  # حالت=توکن قبلاً هست
        await database.execute(  # اجرا=update توکن
            DeviceTokenTable.__table__.update().where(DeviceTokenTable.id == int(row["id"])).values(  # update=بر اساس id
                role=str(body.role).strip(),  # role=نقش جدید
                platform=str(body.platform or "android").strip(),  # platform=پلتفرم
                user_phone=norm_phone if norm_phone else row["user_phone"],  # user_phone=شماره جدید یا قبلی
                updated_at=now  # updated_at=اکنون
            )  # پایان values
        )  # پایان execute

    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": str(body.role).strip()})  # پاسخ=ثبت شد

@app.post("/push/unregister")  # مسیر=حذف توکن پوش
async def unregister_push_token(body: PushUnregister):  # تابع=unregister
    await database.execute(  # اجرا=delete
        DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == str(body.token).strip())  # delete=بر اساس token
    )  # پایان execute
    return unified_response("ok", "TOKEN_UNREGISTERED", "unregistered", {})  # پاسخ=حذف شد
# -------------------- Users: exists/register/login --------------------  # بخش=کاربر (وجود/ثبت‌نام/ورود)

@app.get("/users/exists")  # مسیر=بررسی وجود کاربر
async def user_exists(phone: str):  # تابع=بررسی وجود
    norm = _normalize_phone(phone)  # norm=شماره نرمال
    if not norm:  # شرط=شماره نامعتبر
        return unified_response("ok", "USER_NOT_FOUND", "user exists check", {"exists": False})  # پاسخ=وجود ندارد
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == norm)  # q=کوئری count
    count = await database.fetch_val(q)  # count=نتیجه count
    exists = bool(count and int(count) > 0)  # exists=وجود یا عدم وجود
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ=نتیجه

@app.post("/register_user")  # مسیر=ثبت‌نام کاربر
async def register_user(user: UserRegisterRequest):  # تابع=ثبت‌نام
    raw = str(user.phone or "").strip()  # raw=شماره خام
    norm = _normalize_phone(raw)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="phone required")  # خطا=۴۰۰

    q = select(func.count()).select_from(UserTable).where(UserTable.phone == norm)  # q=کوئری جلوگیری از تکرار
    count = await database.fetch_val(q)  # count=تعداد
    if count and int(count) > 0:  # شرط=وجود کاربر
        raise HTTPException(status_code=400, detail="User already exists")  # خطا=۴۰۰

    password_hash = bcrypt_hash_password(user.password)  # password_hash=هش رمز
    await database.execute(  # اجرا=درج کاربر
        UserTable.__table__.insert().values(  # insert=values
            phone=norm,  # phone=شماره نرمال
            password_hash=password_hash,  # password_hash=هش
            address=str(user.address or "").strip(),  # address=آدرس
            name="",  # name=نام
            car_list=[]  # car_list=لیست خالی
        )  # پایان values
    )  # پایان execute

    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": norm})  # پاسخ=ثبت موفق

@app.post("/login")  # مسیر=ورود کاربر (هم کاربر هم مدیر با شماره مدیر)
async def login_user(user: UserLoginRequest, request: Request):  # تابع=ورود
    now = datetime.now(timezone.utc)  # now=اکنون UTC
    client_ip = get_client_ip(request)  # client_ip=آی‌پی کلاینت

    raw_phone = str(user.phone or "").strip()  # raw_phone=شماره خام
    phone_norm = _normalize_phone(raw_phone)  # phone_norm=شماره نرمال
    if not phone_norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid phone")  # خطا=۴۰۰

    sel_att = LoginAttemptTable.__table__.select().where(  # sel_att=کوئری تلاش ورود
        (LoginAttemptTable.phone == phone_norm) &  # شرط=شماره
        (LoginAttemptTable.ip == client_ip)  # شرط=ip
    )  # پایان where
    att = await database.fetch_one(sel_att)  # att=ردیف تلاش

    if not att:  # شرط=نبود ردیف
        await database.execute(  # اجرا=ایجاد ردیف
            LoginAttemptTable.__table__.insert().values(  # insert=values
                phone=phone_norm,  # phone=شماره
                ip=client_ip,  # ip=آی‌پی
                attempt_count=0,  # attempt_count=۰
                window_start=now,  # window_start=اکنون
                locked_until=None,  # locked_until=بدون قفل
                last_attempt_at=now,  # last_attempt_at=اکنون
                created_at=now  # created_at=اکنون
            )  # پایان values
        )  # پایان execute
        att = await database.fetch_one(sel_att)  # att=خواندن مجدد
    else:  # حالت=ردیف موجود
        locked_until = att["locked_until"]  # locked_until=زمان قفل
        if locked_until is not None and locked_until > now:  # شرط=قفل فعال
            lock_remaining = int((locked_until - now).total_seconds())  # lock_remaining=ثانیه باقیمانده
            raise HTTPException(  # خطا=۴۲۹
                status_code=429,  # کد=429
                detail={"code": "RATE_LIMITED", "lock_remaining": lock_remaining},  # detail=قفل
                headers={"Retry-After": str(lock_remaining), "X-Remaining-Attempts": "0"}  # headers=هدرها
            )  # پایان raise

        window_start = att["window_start"] or now  # window_start=شروع پنجره
        window_age = (now - window_start).total_seconds()  # window_age=سن پنجره
        if window_age > LOGIN_WINDOW_SECONDS or (locked_until is not None and locked_until <= now):  # شرط=ریست پنجره
            await database.execute(  # اجرا=ریست شمارنده
                LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(  # update=by id
                    attempt_count=0,  # attempt_count=۰
                    window_start=now,  # window_start=اکنون
                    locked_until=None,  # locked_until=پاک
                    last_attempt_at=now  # last_attempt_at=اکنون
                )  # پایان values
            )  # پایان execute
            att = await database.fetch_one(sel_att)  # att=خواندن مجدد

    db_user = await database.fetch_one(  # db_user=گرفتن کاربر
        UserTable.__table__.select().where(UserTable.phone == phone_norm)  # select=بر اساس شماره نرمال
    )  # پایان fetch_one

    if not db_user:  # شرط=کاربر نبود
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})  # خطا=۴۰۴

    if not verify_password_secure(user.password, db_user["password_hash"]):  # شرط=رمز اشتباه
        cur_count = int(att["attempt_count"] or 0) + 1  # cur_count=تلاش جدید
        remaining = max(0, LOGIN_MAX_ATTEMPTS - cur_count)  # remaining=باقی‌مانده

        if cur_count >= LOGIN_MAX_ATTEMPTS:  # شرط=قفل
            locked_until_new = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # locked_until_new=زمان قفل
            lock_remaining = int((locked_until_new - now).total_seconds())  # lock_remaining=ثانیه قفل
            await database.execute(  # اجرا=ثبت قفل
                LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(  # update=by id
                    attempt_count=cur_count,  # attempt_count=تلاش
                    locked_until=locked_until_new,  # locked_until=قفل
                    last_attempt_at=now  # last_attempt_at=اکنون
                )  # پایان values
            )  # پایان execute
            raise HTTPException(  # خطا=۴۲۹
                status_code=429,  # کد=429
                detail={"code": "RATE_LIMITED", "lock_remaining": lock_remaining},  # detail=قفل
                headers={"Retry-After": str(lock_remaining), "X-Remaining-Attempts": "0"}  # headers=هدرها
            )  # پایان raise

        await database.execute(  # اجرا=ثبت تلاش ناموفق
            LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(  # update=by id
                attempt_count=cur_count,  # attempt_count=تلاش جدید
                last_attempt_at=now  # last_attempt_at=اکنون
            )  # پایان values
        )  # پایان execute

        raise HTTPException(  # خطا=۴۰۱
            status_code=401,  # کد=401
            detail={"code": "WRONG_PASSWORD", "remaining_attempts": int(remaining)},  # detail=رمز اشتباه
            headers={"X-Remaining-Attempts": str(int(remaining))}  # headers=باقی‌مانده
        )  # پایان raise

    await database.execute(  # اجرا=ریست تلاش‌ها در ورود موفق
        LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(  # update=by id
            attempt_count=0,  # attempt_count=۰
            window_start=now,  # window_start=اکنون
            locked_until=None,  # locked_until=پاک
            last_attempt_at=now  # last_attempt_at=اکنون
        )  # پایان values
    )  # پایان execute

    access_token = create_access_token(phone_norm)  # access_token=ساخت access
    refresh_token = create_refresh_token()  # refresh_token=ساخت refresh
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش refresh
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # refresh_exp=انقضا

    await database.execute(  # اجرا=درج refresh token
        RefreshTokenTable.__table__.insert().values(  # insert=values
            user_id=int(db_user["id"]),  # user_id=شناسه کاربر
            token_hash=refresh_hash,  # token_hash=هش
            expires_at=refresh_exp,  # expires_at=انقضا
            revoked=False  # revoked=ابطال نشده
        )  # پایان values
    )  # پایان execute

    return {  # پاسخ=فرمت مورد انتظار اپ‌ها
        "status": "ok",  # status=ok
        "access_token": access_token,  # access_token=توکن دسترسی
        "refresh_token": refresh_token,  # refresh_token=توکن رفرش
        "user": {  # user=اطلاعات کاربر
            "phone": phone_norm,  # phone=شماره
            "address": str(db_user["address"] or ""),  # address=آدرس
            "name": str(db_user["name"] or "")  # name=نام
        }  # پایان user
    }  # پایان پاسخ

# -------------------- Admin Login --------------------  # بخش=ورود مدیر

class AdminLoginRequest(BaseModel):  # کلاس=مدل ورودی ورود مدیر
    phone: str  # فیلد=شماره موبایل
    password: str  # فیلد=رمز عبور

@app.post("/admin/login")  # مسیر=ورود مدیر
async def admin_login(body: AdminLoginRequest, request: Request):  # تابع=ورود مدیر
    now = datetime.now(timezone.utc)  # now=زمان فعلی UTC
    client_ip = get_client_ip(request)  # client_ip=آی‌پی کلاینت

    raw_phone = str(body.phone or "").strip()  # raw_phone=شماره خام ورودی
    phone_norm = _normalize_phone(raw_phone)  # phone_norm=شماره نرمال‌شده
    if not phone_norm:  # شرط=شماره نامعتبر
        raise HTTPException(status_code=400, detail="invalid phone")  # خطا=شماره نامعتبر

    # ——— بررسی اینکه شماره در لیست مدیران هست یا نه ———  # توضیح=امنیت
    if phone_norm not in ADMIN_PHONES_SET:  # شرط=شماره مدیر نیست
        raise HTTPException(  # خطا=پیام عمومی برای امنیت
            status_code=401,  # کد=۴۰۱
            detail={"code": "WRONG_PASSWORD", "remaining_attempts": 0}  # detail=پیام امن
        )  # پایان خطا

    # ——— Rate Limiting (مشابه /login) ———  # توضیح=جلوگیری از حمله brute-force
    sel_att = LoginAttemptTable.__table__.select().where(  # sel_att=کوئری تلاش ورود
        (LoginAttemptTable.phone == phone_norm) &  # شرط=شماره
        (LoginAttemptTable.ip == client_ip)  # شرط=ip
    )  # پایان where
    att = await database.fetch_one(sel_att)  # att=ردیف تلاش

    if not att:  # شرط=نبود ردیف تلاش
        await database.execute(  # اجرا=ایجاد ردیف جدید
            LoginAttemptTable.__table__.insert().values(  # insert=مقادیر
                phone=phone_norm,  # phone=شماره
                ip=client_ip,  # ip=آی‌پی
                attempt_count=0,  # attempt_count=صفر
                window_start=now,  # window_start=اکنون
                locked_until=None,  # locked_until=بدون قفل
                last_attempt_at=now,  # last_attempt_at=اکنون
                created_at=now  # created_at=اکنون
            )  # پایان values
        )  # پایان execute
        att = await database.fetch_one(sel_att)  # att=خواندن مجدد
    else:  # حالت=ردیف موجود
        locked_until = att["locked_until"]  # locked_until=زمان قفل
        if locked_until is not None and locked_until > now:  # شرط=قفل فعال
            lock_remaining = int((locked_until - now).total_seconds())  # lock_remaining=ثانیه باقیمانده
            raise HTTPException(  # خطا=۴۲۹
                status_code=429,  # کد=429
                detail={"code": "RATE_LIMITED", "lock_remaining": lock_remaining},  # detail=قفل
                headers={"Retry-After": str(lock_remaining), "X-Remaining-Attempts": "0"}  # headers=هدرها
            )  # پایان raise

        window_start = att["window_start"] or now  # window_start=شروع پنجره
        window_age = (now - window_start).total_seconds()  # window_age=سن پنجره
        if window_age > LOGIN_WINDOW_SECONDS or (locked_until is not None and locked_until <= now):  # شرط=ریست پنجره
            await database.execute(  # اجرا=ریست شمارنده
                LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(  # update=by id
                    attempt_count=0,  # attempt_count=صفر
                    window_start=now,  # window_start=اکنون
                    locked_until=None,  # locked_until=پاک
                    last_attempt_at=now  # last_attempt_at=اکنون
                )  # پایان values
            )  # پایان execute
            att = await database.fetch_one(sel_att)  # att=خواندن مجدد

    # ——— جستجوی مدیر در دیتابیس ———  # توضیح=بررسی ثبت‌نام قبلی
    db_user = await database.fetch_one(  # db_user=کاربر از دیتابیس
        UserTable.__table__.select().where(UserTable.phone == phone_norm)  # select=بر اساس شماره
    )  # پایان fetch_one

    password_raw = str(body.password or "").strip()  # password_raw=رمز ورودی
    if not password_raw:  # شرط=رمز خالی
        raise HTTPException(status_code=400, detail="password required")  # خطا=رمز لازم

    if not db_user:  # شرط=مدیر هنوز ثبت‌نام نکرده (اولین ورود)
        # ——— ثبت‌نام خودکار مدیر ———  # توضیح=ذخیره رمز برای دفعات بعد
        password_hash = bcrypt_hash_password(password_raw)  # password_hash=هش رمز
        await database.execute(  # اجرا=درج کاربر جدید
            UserTable.__table__.insert().values(  # insert=مقادیر
                phone=phone_norm,  # phone=شماره نرمال
                password_hash=password_hash,  # password_hash=هش رمز
                address="",  # address=خالی
                name="Manager",  # name=نام پیش‌فرض
                car_list=[]  # car_list=لیست خالی
            )  # پایان values
        )  # پایان execute
        db_user = await database.fetch_one(  # db_user=خواندن کاربر جدید
            UserTable.__table__.select().where(UserTable.phone == phone_norm)  # select=شماره
        )  # پایان fetch_one
    else:  # حالت=مدیر قبلاً ثبت‌نام کرده
        # ——— بررسی رمز ———  # توضیح=چک رمز ذخیره‌شده
        if not verify_password_secure(password_raw, db_user["password_hash"]):  # شرط=رمز اشتباه
            cur_count = int(att["attempt_count"] or 0) + 1  # cur_count=تلاش جدید
            remaining = max(0, LOGIN_MAX_ATTEMPTS - cur_count)  # remaining=باقی‌مانده

            if cur_count >= LOGIN_MAX_ATTEMPTS:  # شرط=قفل
                locked_until_new = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # locked_until_new=زمان قفل
                lock_remaining = int((locked_until_new - now).total_seconds())  # lock_remaining=ثانیه
                await database.execute(  # اجرا=ثبت قفل
                    LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(  # update=by id
                        attempt_count=cur_count,  # attempt_count=تلاش
                        locked_until=locked_until_new,  # locked_until=قفل
                        last_attempt_at=now  # last_attempt_at=اکنون
                    )  # پایان values
                )  # پایان execute
                raise HTTPException(  # خطا=۴۲۹
                    status_code=429,  # کد=429
                    detail={"code": "RATE_LIMITED", "lock_remaining": lock_remaining},  # detail=قفل
                    headers={"Retry-After": str(lock_remaining), "X-Remaining-Attempts": "0"}  # headers=هدرها
                )  # پایان raise

            await database.execute(  # اجرا=ثبت تلاش ناموفق
                LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(  # update=by id
                    attempt_count=cur_count,  # attempt_count=تلاش جدید
                    last_attempt_at=now  # last_attempt_at=اکنون
                )  # پایان values
            )  # پایان execute

            raise HTTPException(  # خطا=۴۰۱
                status_code=401,  # کد=401
                detail={"code": "WRONG_PASSWORD", "remaining_attempts": int(remaining)},  # detail=رمز اشتباه
                headers={"X-Remaining-Attempts": str(int(remaining))}  # headers=باقی‌مانده
            )  # پایان raise

    # ——— ریست تلاش‌ها پس از ورود موفق ———  # توضیح=پاکسازی شمارنده
    await database.execute(  # اجرا=ریست
        LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == int(att["id"])).values(  # update=by id
            attempt_count=0,  # attempt_count=صفر
            window_start=now,  # window_start=اکنون
            locked_until=None,  # locked_until=پاک
            last_attempt_at=now  # last_attempt_at=اکنون
        )  # پایان values
    )  # پایان execute

    # ——— صدور توکن‌ها ———  # توضیح=ساخت access و refresh
    access_token = create_access_token(phone_norm)  # access_token=توکن دسترسی
    refresh_token = create_refresh_token()  # refresh_token=توکن رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش رفرش
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # refresh_exp=انقضای رفرش

    await database.execute(  # اجرا=درج رفرش توکن
        RefreshTokenTable.__table__.insert().values(  # insert=مقادیر
            user_id=int(db_user["id"]),  # user_id=شناسه کاربر
            token_hash=refresh_hash,  # token_hash=هش
            expires_at=refresh_exp,  # expires_at=انقضا
            revoked=False  # revoked=ابطال نشده
        )  # پایان values
    )  # پایان execute

    return {  # پاسخ=فرمت مورد انتظار اپ مدیر
        "status": "ok",  # status=ok
        "access_token": access_token,  # access_token=توکن دسترسی
        "refresh_token": refresh_token,  # refresh_token=توکن رفرش
        "user": {  # user=اطلاعات کاربر
            "phone": phone_norm,  # phone=شماره
            "address": str(db_user["address"] or ""),  # address=آدرس
            "name": str(db_user["name"] or "")  # name=نام
        }  # پایان user
    }  # پایان پاسخ
    
# -------------------- Admin: active requests --------------------  # بخش=ادمین لیست سفارش‌های فعال

@app.get("/admin/requests/active")  # مسیر=فعال‌ها بدون اسلش
@app.get("/admin/requests/active/")  # مسیر=فعال‌ها با اسلش
async def admin_active_requests(request: Request):  # تابع=لیست فعال
    require_admin(request)  # احراز=ادمین
    active = ["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]  # active=وضعیت‌ها
    sel = RequestTable.__table__.select().where(RequestTable.status.in_(active)).order_by(RequestTable.id.desc())  # sel=کوئری
    rows = await database.fetch_all(sel)  # rows=نتیجه
    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": [dict(r) for r in rows]})  # پاسخ=لیست
# -------------------- Cars --------------------  # بخش=ماشین‌ها

@app.get("/user_cars/{user_phone}")  # مسیر=گرفتن لیست ماشین‌های کاربر
async def get_user_cars(user_phone: str, request: Request):  # تابع=گرفتن ماشین‌ها
    norm = _normalize_phone(user_phone)  # norm=شماره نرمال از مسیر
    if not norm:  # شرط=شماره نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))  # user=کاربر از دیتابیس
    if not user:  # شرط=کاربر نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=۴۰۴

    cars = user["car_list"] or []  # cars=لیست خودروها یا خالی
    return unified_response("ok", "USER_CARS", "cars list", {"items": cars})  # پاسخ=لیست ماشین‌ها

@app.post("/user_cars")  # مسیر=آپدیت لیست ماشین‌ها (بدون اسلش)
@app.post("/user_cars/")  # مسیر=آپدیت لیست ماشین‌ها (با اسلش)
async def update_user_cars(body: CarListUpdateRequest, request: Request):  # تابع=آپدیت ماشین‌ها
    norm = _normalize_phone(body.user_phone)  # norm=شماره نرمال از بدنه
    if not norm:  # شرط=شماره نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))  # user=کاربر از دیتابیس
    if not user:  # شرط=نبود کاربر
        raise HTTPException(status_code=404, detail="User not found")  # خطا=۴۰۴

    cars_payload = [c.dict() for c in (body.car_list or [])]  # cars_payload=تبدیل لیست به dict
    await database.execute(  # اجرا=update car_list
        UserTable.__table__.update().where(UserTable.phone == norm).values(car_list=cars_payload)  # update=car_list
    )  # پایان execute

    return unified_response("ok", "USER_CARS_UPDATED", "cars updated", {"count": len(cars_payload)})  # پاسخ=تعداد

# -------------------- Profile --------------------  # بخش=پروفایل

@app.post("/user/profile")  # مسیر=ذخیره پروفایل
async def update_profile(body: UserProfileUpdate, request: Request):  # تابع=آپدیت پروفایل
    norm = _normalize_phone(body.phone)  # norm=شماره نرمال
    if not norm:  # شرط=شماره نامعتبر
        raise HTTPException(status_code=400, detail="invalid phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))  # user=کاربر
    if not user:  # شرط=نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=۴۰۴

    await database.execute(  # اجرا=آپدیت نام و آدرس
        UserTable.__table__.update().where(UserTable.phone == norm).values(  # update=users
            name=str(body.name or "").strip(),  # name=نام
            address=str(body.address or "").strip()  # address=آدرس
        )  # پایان values
    )  # پایان execute

    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": norm})  # پاسخ=موفق

@app.get("/user/profile/{phone}")  # مسیر=دریافت پروفایل
async def get_user_profile(phone: str, request: Request):  # تابع=گرفتن پروفایل
    norm = _normalize_phone(phone)  # norm=شماره نرمال
    if not norm:  # شرط=شماره نامعتبر
        raise HTTPException(status_code=400, detail="invalid phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))  # user=کاربر
    if not user:  # شرط=نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=۴۰۴

    return unified_response(  # پاسخ=پروفایل
        "ok",  # status=ok
        "PROFILE_FETCHED",  # code=کد
        "profile data",  # message=پیام
        {"phone": norm, "name": str(user["name"] or ""), "address": str(user["address"] or "")}  # data=پروفایل
    )  # پایان پاسخ

# -------------------- Orders --------------------  # بخش=سفارش‌ها

@app.post("/order")  # مسیر=ثبت سفارش
async def create_order(order: OrderRequest, request: Request):  # تابع=ایجاد سفارش
    norm = _normalize_phone(order.user_phone)  # norm=شماره نرمال
    if not norm:  # شرط=شماره نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    user = await database.fetch_one(UserTable.__table__.select().where(UserTable.phone == norm))  # user=کاربر
    if not user:  # شرط=کاربر نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=۴۰۴

    ins = RequestTable.__table__.insert().values(  # ins=insert سفارش
        user_phone=norm,  # user_phone=شماره کاربر
        latitude=float(order.location.latitude),  # latitude=عرض
        longitude=float(order.location.longitude),  # longitude=طول
        car_list=[car.dict() for car in (order.car_list or [])],  # car_list=لیست آیتم‌ها
        address=str(order.address or "").strip(),  # address=آدرس
        home_number=str(order.home_number or "").strip(),  # home_number=پلاک
        service_type=str(order.service_type or "").strip().lower(),  # service_type=کد سرویس
        price=int(order.price),  # price=قیمت
        request_datetime=str(order.request_datetime or "").strip(),  # request_datetime=زمان ثبت
        status="NEW",  # status=جدید
        payment_type=str(order.payment_type or "").strip().lower(),  # payment_type=پرداخت
        service_place=str(order.service_place or "client").strip().lower(),  # service_place=محل سرویس
        driver_phone="",  # driver_phone=خالی
        driver_name=""  # driver_name=خالی
    ).returning(RequestTable.id)  # returning=id

    row = await database.fetch_one(ins)  # row=نتیجه insert
    new_id = int(row["id"]) if row and row["id"] else 0  # new_id=شناسه جدید

    try:  # try=محافظ اعلان مدیر
        await notify_managers(  # اعلان=به مدیران
            title="سفارش جدید",  # title=عنوان
            body=f"سفارش جدید ثبت شد: {str(order.service_type or '')}",  # body=متن
            data={"order_id": str(new_id), "user_phone": norm, "service_type": str(order.service_type or ""), "status": "NEW"}  # data=اطلاعات
        )  # پایان notify
    except Exception as e:  # catch=خطا
        logger.error(f"notify_managers(create_order) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # پاسخ=شناسه

@app.post("/cancel_order")  # مسیر=لغو سفارش کاربر
async def cancel_order(cancel: CancelRequest, request: Request):  # تابع=لغو سفارش
    norm = _normalize_phone(cancel.user_phone)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    service = str(cancel.service_type or "").strip().lower()  # service=نوع سرویس
    if not service:  # شرط=خالی
        raise HTTPException(status_code=400, detail="service_type required")  # خطا=۴۰۰

    upd = (  # upd=کوئری آپدیت
        RequestTable.__table__.update()  # update=requests
        .where(  # where=شرایط لغو
            (RequestTable.user_phone == norm) &  # شرط=شماره کاربر
            (RequestTable.service_type == service) &  # شرط=سرویس
            (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED"])) &  # شرط=قابل لغو
            (RequestTable.execution_start.is_(None))  # شرط=بدون زمان اجرا
        )  # پایان where
        .values(status="CANCELED", scheduled_start=None, execution_start=None)  # values=لغو + پاکسازی زمان‌ها
        .returning(RequestTable.id, RequestTable.driver_phone)  # returning=شناسه و سرویس‌دهنده
    )  # پایان upd

    rows = await database.fetch_all(upd)  # rows=نتیجه
    if not rows:  # شرط=چیزی لغو نشد
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CANCEL", "message": "order cannot be canceled at this stage"})  # خطا=۴۰۹

    ids = [int(r["id"]) for r in rows]  # ids=شناسه‌های لغو شده
    driver_phones = list({str(r["driver_phone"] or "").strip() for r in rows if str(r["driver_phone"] or "").strip()})  # driver_phones=لیست سرویس‌دهنده‌ها

    await database.execute(  # اجرا=رد اسلات‌های فعال
        ScheduleSlotTable.__table__.update().where(  # update=schedule_slots
            (ScheduleSlotTable.request_id.in_(ids)) &  # شرط=این سفارش‌ها
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))  # شرط=فعال
        ).values(status="REJECTED")  # values=رد
    )  # پایان execute

    await database.execute(  # اجرا=لغو appointmentهای رزرو
        AppointmentTable.__table__.update().where(  # update=appointments
            (AppointmentTable.request_id.in_(ids)) &  # شرط=این سفارش‌ها
            (AppointmentTable.status == "BOOKED")  # شرط=رزرو
        ).values(status="CANCELED")  # values=لغو
    )  # پایان execute

    try:  # try=محافظ اعلان مدیر
        await notify_managers(  # اعلان=به مدیرها
            title="لغو سفارش",  # title=عنوان
            body=f"سفارش توسط کاربر لغو شد ({service})",  # body=متن
            data={"order_ids": ",".join(str(x) for x in ids), "user_phone": norm, "service_type": service, "status": "CANCELED"}  # data=اطلاعات
        )  # پایان notify
        for dp in driver_phones:  # حلقه=روی سرویس‌دهنده‌ها
            await notify_managers(  # اعلان=هدفمند
                title="لغو سفارش",  # title=عنوان
                body=f"سفارش شما لغو شد (id={ids[0]})",  # body=متن
                data={"order_ids": ",".join(str(x) for x in ids), "status": "CANCELED"},  # data=اطلاعات
                target_phone=_normalize_phone(dp)  # target_phone=شماره هدف
            )  # پایان notify
    except Exception as e:  # catch=خطا
        logger.error(f"notify_managers(cancel_order) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(ids)})  # پاسخ=تعداد

@app.get("/user_active_services/{user_phone}")  # مسیر=سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str, request: Request):  # تابع=فعال‌ها
    norm = _normalize_phone(user_phone)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    sel = RequestTable.__table__.select().where(  # sel=کوئری سفارش‌های فعال
        (RequestTable.user_phone == norm) &  # شرط=شماره
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))  # شرط=فعال
    )  # پایان where
    rows = await database.fetch_all(sel)  # rows=نتیجه
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": [dict(r) for r in rows]})  # پاسخ=لیست

@app.get("/user_orders/{user_phone}")  # مسیر=تمام سفارش‌های کاربر
async def get_user_orders(user_phone: str, request: Request):  # تابع=سفارش‌ها
    norm = _normalize_phone(user_phone)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid user_phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    sel = RequestTable.__table__.select().where(RequestTable.user_phone == norm).order_by(RequestTable.id.desc())  # sel=کوئری
    rows = await database.fetch_all(sel)  # rows=نتیجه
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": [dict(r) for r in rows]})  # پاسخ=لیست

# -------------------- Notifications (User) --------------------  # بخش=اعلان‌ها برای اپ کاربر

@app.get("/user/{phone}/notifications")  # مسیر=لیست اعلان‌ها
async def get_notifications(phone: str, request: Request, only_unread: bool = True, limit: int = 20, offset: int = 0):  # تابع=گرفتن اعلان‌ها
    norm = _normalize_phone(phone)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    lim = int(limit) if int(limit) > 0 else 20  # lim=حد
    off = int(offset) if int(offset) >= 0 else 0  # off=افست

    q = NotificationTable.__table__.select().where(NotificationTable.user_phone == norm)  # q=کوئری پایه
    if only_unread:  # شرط=فقط خوانده‌نشده
        q = q.where(NotificationTable.read == False)  # where=read false
    q = q.order_by(NotificationTable.created_at.desc()).limit(lim).offset(off)  # مرتب‌سازی و limit/offset

    rows = await database.fetch_all(q)  # rows=نتیجه

    items: List[dict] = []  # items=خروجی نهایی
    for r in rows:  # حلقه=روی اعلان‌ها
        items.append({  # افزودن=آیتم
            "id": int(r["id"]),  # id=شناسه
            "user_phone": str(r["user_phone"] or ""),  # user_phone=شماره
            "title": str(r["title"] or ""),  # title=عنوان
            "body": str(r["body"] or ""),  # body=متن
            "data": r["data"] or {},  # data=داده
            "read": bool(r["read"]),  # read=خوانده شده؟
            "created_at": (r["created_at"].astimezone(timezone.utc).isoformat() if r["created_at"] else None)  # created_at=ISO UTC
        })  # پایان append

    return unified_response("ok", "NOTIFICATIONS", "notifications", {"items": items})  # پاسخ=لیست اعلان‌ها

@app.post("/user/{phone}/notifications/{notif_id}/read")  # مسیر=خوانده‌شدن یک اعلان
async def mark_notification_read(phone: str, notif_id: int, request: Request):  # تابع=خوانده کردن اعلان
    norm = _normalize_phone(phone)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    now = datetime.now(timezone.utc)  # now=اکنون UTC
    upd = (  # upd=آپدیت اعلان
        NotificationTable.__table__.update()  # update=notifications
        .where((NotificationTable.id == int(notif_id)) & (NotificationTable.user_phone == norm))  # where=همان اعلان و همان کاربر
        .values(read=True, read_at=now)  # values=خوانده شده
    )  # پایان upd
    res = await database.execute(upd)  # res=اجرای update

    return unified_response("ok", "NOTIFICATION_READ", "notification marked read", {"id": int(notif_id)})  # پاسخ=موفق

@app.post("/user/{phone}/notifications/mark_all_read")  # مسیر=خوانده‌شدن همه اعلان‌ها
async def mark_all_notifications_read(phone: str, request: Request):  # تابع=خوانده کردن همه
    norm = _normalize_phone(phone)  # norm=شماره نرمال
    if not norm:  # شرط=نامعتبر
        raise HTTPException(status_code=400, detail="invalid phone")  # خطا=۴۰۰
    require_user_phone(request, norm)  # احراز=Bearer و تطبیق شماره

    now = datetime.now(timezone.utc)  # now=اکنون UTC
    await database.execute(  # اجرا=آپدیت همه اعلان‌های خوانده‌نشده
        NotificationTable.__table__.update().where(  # update=notifications
            (NotificationTable.user_phone == norm) & (NotificationTable.read == False)  # where=خوانده‌نشده‌ها
        ).values(read=True, read_at=now)  # values=خوانده شده
    )  # پایان execute

    return unified_response("ok", "ALL_NOTIFICATIONS_READ", "all notifications marked read", {})  # پاسخ=موفق
# -------------------- Utils: provider schedule --------------------  # بخش=ابزار بررسی زمان‌های مشغول

async def provider_is_free(provider_phone: str, start: datetime, end: datetime, exclude_order_id: Optional[int] = None) -> bool:  # تابع=بررسی آزاد بودن سرویس‌دهنده در بازه
    provider = _normalize_phone(provider_phone)  # provider=شماره نرمال سرویس‌دهنده
    if not provider:  # شرط=شماره نامعتبر
        return False  # خروجی=غیرآزاد

    one_hour = text("interval '1 hour'")  # one_hour=اینترول یک ساعت در PostgreSQL

    q_app = select(func.count()).select_from(AppointmentTable).where(  # q_app=شمارش تداخل رزروهای قطعی
        (AppointmentTable.provider_phone == provider) &  # شرط=سرویس‌دهنده
        (AppointmentTable.status == "BOOKED") &  # شرط=رزرو فعال
        (AppointmentTable.start_time < end) &  # شرط=شروع قبل از پایان
        (AppointmentTable.end_time > start)  # شرط=پایان بعد از شروع
    )  # پایان where
    if exclude_order_id is not None:  # شرط=نادیده گرفتن سفارش
        q_app = q_app.where(AppointmentTable.request_id != int(exclude_order_id))  # where=حذف سفارش
    app_count = await database.fetch_val(q_app)  # app_count=تعداد تداخل
    if app_count and int(app_count) > 0:  # شرط=تداخل
        return False  # خروجی=غیرآزاد

    slot_end = ScheduleSlotTable.slot_start + one_hour  # slot_end=پایان اسلات پیشنهادی
    q_slot = select(func.count()).select_from(ScheduleSlotTable).where(  # q_slot=شمارش تداخل اسلات‌های پیشنهادی/پذیرفته
        (ScheduleSlotTable.provider_phone == provider) &  # شرط=سرویس‌دهنده
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &  # شرط=اسلات فعال
        (ScheduleSlotTable.slot_start < end) &  # شرط=شروع قبل پایان
        (slot_end > start)  # شرط=پایان بعد شروع
    )  # پایان where
    if exclude_order_id is not None:  # شرط=نادیده گرفتن سفارش
        q_slot = q_slot.where(ScheduleSlotTable.request_id != int(exclude_order_id))  # where=حذف سفارش
    slot_count = await database.fetch_val(q_slot)  # slot_count=تعداد تداخل
    if slot_count and int(slot_count) > 0:  # شرط=تداخل
        return False  # خروجی=غیرآزاد

    exec_end = RequestTable.execution_start + one_hour  # exec_end=پایان بازه اجرا
    q_exec = select(func.count()).select_from(RequestTable).where(  # q_exec=شمارش اجرای فعال
        (RequestTable.driver_phone == provider) &  # شرط=سرویس‌دهنده
        (RequestTable.execution_start.is_not(None)) &  # شرط=زمان اجرا وجود دارد
        (RequestTable.status.in_(["IN_PROGRESS", "STARTED"])) &  # شرط=وضعیت اجرا
        (RequestTable.execution_start < end) &  # شرط=شروع قبل پایان
        (exec_end > start)  # شرط=پایان بعد شروع
    )  # پایان where
    if exclude_order_id is not None:  # شرط=نادیده گرفتن سفارش
        q_exec = q_exec.where(RequestTable.id != int(exclude_order_id))  # where=حذف سفارش
    exec_count = await database.fetch_val(q_exec)  # exec_count=تعداد تداخل
    if exec_count and int(exec_count) > 0:  # شرط=تداخل
        return False  # خروجی=غیرآزاد

    visit_end = RequestTable.scheduled_start + one_hour  # visit_end=پایان بازه بازدید
    q_visit = select(func.count()).select_from(RequestTable).where(  # q_visit=شمارش بازدیدهای قطعی
        (RequestTable.driver_phone == provider) &  # شرط=سرویس‌دهنده
        (RequestTable.scheduled_start.is_not(None)) &  # شرط=زمان بازدید وجود دارد
        (RequestTable.status.in_(["WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"])) &  # شرط=وضعیت‌های مرتبط
        (RequestTable.scheduled_start < end) &  # شرط=شروع قبل پایان
        (visit_end > start)  # شرط=پایان بعد شروع
    )  # پایان where
    if exclude_order_id is not None:  # شرط=نادیده گرفتن سفارش
        q_visit = q_visit.where(RequestTable.id != int(exclude_order_id))  # where=حذف سفارش
    visit_count = await database.fetch_val(q_visit)  # visit_count=تعداد تداخل
    if visit_count and int(visit_count) > 0:  # شرط=تداخل
        return False  # خروجی=غیرآزاد

    return True  # خروجی=آزاد

# -------------------- Scheduling (Manager) --------------------  # بخش=زمان‌بندی مدیر

@app.get("/busy_slots")  # مسیر=اسلات‌های مشغول مدیر
async def get_busy_slots(request: Request, date: str, exclude_order_id: Optional[int] = None):  # تابع=busy_slots
    require_admin(request)  # احراز=ادمین

    d = datetime.fromisoformat(str(date).strip()).date()  # d=تاریخ
    provider = get_admin_provider_phone(request)  # provider=شماره سرویس‌دهنده (شماره مدیر)

    day_start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)  # day_start=شروع روز UTC
    day_end = day_start + timedelta(days=1)  # day_end=پایان روز UTC

    sel_sched = ScheduleSlotTable.__table__.select().where(  # sel_sched=اسلات‌های فعال
        (ScheduleSlotTable.slot_start >= day_start) &  # شرط=از شروع روز
        (ScheduleSlotTable.slot_start < day_end) &  # شرط=تا پایان روز
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &  # شرط=فعال
        (ScheduleSlotTable.provider_phone == provider)  # شرط=سرویس‌دهنده
    )  # پایان where
    if exclude_order_id is not None:  # شرط=استثنا
        sel_sched = sel_sched.where(ScheduleSlotTable.request_id != int(exclude_order_id))  # where=حذف سفارش
    rows_sched = await database.fetch_all(sel_sched)  # rows_sched=نتیجه

    sel_app = AppointmentTable.__table__.select().where(  # sel_app=رزروهای قطعی
        (AppointmentTable.start_time >= day_start) &  # شرط=از شروع روز
        (AppointmentTable.start_time < day_end) &  # شرط=تا پایان روز
        (AppointmentTable.status == "BOOKED") &  # شرط=رزرو فعال
        (AppointmentTable.provider_phone == provider)  # شرط=سرویس‌دهنده
    )  # پایان where
    if exclude_order_id is not None:  # شرط=استثنا
        sel_app = sel_app.where(AppointmentTable.request_id != int(exclude_order_id))  # where=حذف سفارش
    rows_app = await database.fetch_all(sel_app)  # rows_app=نتیجه

    sel_exec = RequestTable.__table__.select().where(  # sel_exec=اجراهای فعال
        (RequestTable.execution_start >= day_start) &  # شرط=از شروع روز
        (RequestTable.execution_start < day_end) &  # شرط=تا پایان روز
        (RequestTable.execution_start.is_not(None)) &  # شرط=دارای اجرا
        (RequestTable.status.in_(["IN_PROGRESS", "STARTED"])) &  # شرط=وضعیت اجرا
        (RequestTable.driver_phone == provider)  # شرط=سرویس‌دهنده
    )  # پایان where
    if exclude_order_id is not None:  # شرط=استثنا
        sel_exec = sel_exec.where(RequestTable.id != int(exclude_order_id))  # where=حذف سفارش
    rows_exec = await database.fetch_all(sel_exec)  # rows_exec=نتیجه

    sel_visit = RequestTable.__table__.select().where(  # sel_visit=بازدیدهای قطعی
        (RequestTable.scheduled_start >= day_start) &  # شرط=از شروع روز
        (RequestTable.scheduled_start < day_end) &  # شرط=تا پایان روز
        (RequestTable.scheduled_start.is_not(None)) &  # شرط=دارای بازدید
        (RequestTable.status.in_(["ASSIGNED", "IN_PROGRESS", "STARTED", "WAITING"])) &  # شرط=وضعیت‌ها
        (RequestTable.driver_phone == provider)  # شرط=سرویس‌دهنده
    )  # پایان where
    if exclude_order_id is not None:  # شرط=استثنا
        sel_visit = sel_visit.where(RequestTable.id != int(exclude_order_id))  # where=حذف سفارش
    rows_visit = await database.fetch_all(sel_visit)  # rows_visit=نتیجه

    busy: set[str] = set()  # busy=ست زمان‌های مشغول
    for r in rows_sched:  # حلقه=اسلات‌ها
        busy.add(r["slot_start"].astimezone(timezone.utc).isoformat())  # افزودن=ISO UTC
    for r in rows_app:  # حلقه=رزروها
        busy.add(r["start_time"].astimezone(timezone.utc).isoformat())  # افزودن=ISO UTC
    for r in rows_exec:  # حلقه=اجراها
        busy.add(r["execution_start"].astimezone(timezone.utc).isoformat())  # افزودن=ISO UTC
    for r in rows_visit:  # حلقه=بازدیدها
        busy.add(r["scheduled_start"].astimezone(timezone.utc).isoformat())  # افزودن=ISO UTC

    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": sorted(list(busy))})  # پاسخ=لیست

@app.post("/order/{order_id}/propose_slots")  # مسیر=پیشنهاد زمان‌ها
@app.post("/order/{order_id}/propose_slots/")  # مسیر=پیشنهاد زمان‌ها با اسلش
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):  # تابع=ثبت پیشنهاد زمان توسط مدیر
    require_admin(request)  # احراز=ادمین

    provider = get_admin_provider_phone(request)  # provider=شماره سرویس‌دهنده (مدیر)
    sel_req = RequestTable.__table__.select().where(RequestTable.id == int(order_id))  # sel_req=کوئری سفارش
    req_row = await database.fetch_one(sel_req)  # req_row=سفارش
    if not req_row:  # شرط=نبود سفارش
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    cur_status = str(req_row["status"] or "").strip().upper()  # cur_status=وضعیت
    if cur_status in ["FINISH", "CANCELED"]:  # شرط=بسته
        raise HTTPException(status_code=409, detail="order cannot accept new proposed slots")  # خطا=۴۰۹
    if req_row["execution_start"] is not None:  # شرط=بعد از زمان اجرا
        raise HTTPException(status_code=409, detail="order cannot accept new proposed slots after execution_time")  # خطا=۴۰۹

    raw_slots = body.slots or []  # raw_slots=لیست ورودی
    cleaned: List[str] = []  # cleaned=لیست پاکسازی‌شده
    seen: set[str] = set()  # seen=برای حذف تکرار
    for s in raw_slots:  # حلقه=روی اسلات‌ها
        ss = str(s or "").strip()  # ss=trim
        if not ss:  # شرط=خالی
            continue  # ادامه
        if ss in seen:  # شرط=تکراری
            continue  # ادامه
        seen.add(ss)  # افزودن=به seen
        cleaned.append(ss)  # افزودن=به لیست
        if len(cleaned) >= 3:  # شرط=حداکثر ۳
            break  # خروج از حلقه
    if not cleaned:  # شرط=بدون زمان
        raise HTTPException(status_code=400, detail="slots required")  # خطا=۴۰۰

    slot_dts = [parse_iso(x) for x in cleaned]  # slot_dts=پارس زمان‌ها
    slot_dts.sort()  # sort=مرتب‌سازی

    accepted: List[str] = []  # accepted=لیست ثبت‌شده

    async with database.transaction():  # تراکنش=اتمیک
        await database.execute(  # اجرا=رد اسلات‌های قبلی این سفارش
            ScheduleSlotTable.__table__.update().where(
                (ScheduleSlotTable.request_id == int(order_id)) &  # شرط=همین سفارش
                (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))  # شرط=فعال
            ).values(status="REJECTED")  # values=رد
        )  # پایان execute

        await database.execute(  # اجرا=لغو رزروهای قبلی همین سفارش
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &  # شرط=همین سفارش
                (AppointmentTable.status == "BOOKED")  # شرط=رزرو فعال
            ).values(status="CANCELED")  # values=لغو
        )  # پایان execute

        await database.execute(  # اجرا=آپدیت سفارش به WAITING و ثبت سرویس‌دهنده
            RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
                driver_phone=provider,  # driver_phone=ثبت سرویس‌دهنده
                status="WAITING",  # status=WAITING
                scheduled_start=None  # scheduled_start=پاکسازی
            )  # پایان values
        )  # پایان execute

        for dt in slot_dts:  # حلقه=روی زمان‌ها
            end_dt = dt + timedelta(hours=1)  # end_dt=پایان یک ساعت
            free = await provider_is_free(provider, dt, end_dt, exclude_order_id=int(order_id))  # free=آزاد بودن
            if not free:  # شرط=تداخل
                raise HTTPException(status_code=409, detail="slot overlaps with existing schedule")  # خطا=۴۰۹

            try:  # try=محافظ برخورد یکتا
                await database.execute(  # اجرا=درج اسلات پیشنهادی
                    ScheduleSlotTable.__table__.insert().values(
                        request_id=int(order_id),  # request_id=سفارش
                        provider_phone=provider,  # provider_phone=سرویس‌دهنده
                        slot_start=dt,  # slot_start=شروع
                        status="PROPOSED",  # status=پیشنهادی
                        created_at=datetime.now(timezone.utc)  # created_at=اکنون
                    )  # پایان values
                )  # پایان execute
            except Exception as e:  # catch=خطا
                msg = str(e)  # msg=متن خطا
                if ("uq_schedule_slots_provider_start_active" in msg) or ("duplicate key value" in msg):  # شرط=تداخل یکتا
                    raise HTTPException(status_code=409, detail="slot already reserved for another order")  # خطا=۴۰۹
                raise  # raise=پرتاب مجدد

            accepted.append(dt.isoformat())  # افزودن=خروجی

    try:  # try=ارسال اعلان به کاربر
        await notify_user(  # اعلان=به کاربر
            phone=str(req_row["user_phone"]),  # phone=شماره کاربر
            title="پیشنهاد زمان بازدید",  # title=عنوان
            body="زمان‌های پیشنهادی برای بازدید ارسال شد.",  # body=متن
            data={  # data=اطلاعات
                "type": "visit_slots",  # type=نوع پیام
                "order_id": int(order_id),  # order_id=شناسه
                "status": "WAITING",  # status=WAITING
                "service_type": str(req_row["service_type"] or "")  # service_type=نوع سرویس
            }  # پایان data
        )  # پایان notify_user
    except Exception as e:  # catch=خطا
        logger.error(f"notify_user(propose_slots) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # پاسخ=لیست زمان‌ها

# -------------------- Proposed slots (User) --------------------  # بخش=گرفتن اسلات‌های پیشنهادی برای کاربر

@app.get("/order/{order_id}/proposed_slots")  # مسیر=اسلات‌های پیشنهادی
async def get_proposed_slots(order_id: int, request: Request):  # تابع=گرفتن اسلات‌ها
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))  # req=سفارش
    if not req:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴
    require_user_phone(request, str(req["user_phone"]))  # احراز=کاربر همان سفارش

    sel = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == int(order_id)) &  # شرط=همین سفارش
        (ScheduleSlotTable.status == "PROPOSED")  # شرط=پیشنهادی
    ).order_by(ScheduleSlotTable.slot_start.asc())  # order_by=زمان صعودی
    rows = await database.fetch_all(sel)  # rows=نتیجه
    items = [r["slot_start"].astimezone(timezone.utc).isoformat() for r in rows]  # items=لیست ISO
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})  # پاسخ=لیست

# -------------------- Confirm slot (User) --------------------  # بخش=تأیید زمان بازدید توسط کاربر (فقط یک نسخه)

@app.post("/order/{order_id}/confirm_slot")  # مسیر=تأیید زمان
@app.post("/order/{order_id}/confirm_slot/")  # مسیر=تأیید زمان با اسلش
async def confirm_slot(order_id: int, body: ConfirmSlotRequest, request: Request):  # تابع=تأیید اسلات
    req_row = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))  # req_row=سفارش
    if not req_row:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    require_user_phone(request, str(req_row["user_phone"]))  # احراز=کاربر همان سفارش

    if req_row["execution_start"] is not None:  # شرط=بعد از تعیین زمان اجرا
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CONFIRM", "message": "cannot confirm slot after execution time is set"})  # خطا=۴۰۹

    st = str(req_row["status"] or "").strip().upper()  # st=وضعیت
    if st not in ["WAITING", "ASSIGNED", "NEW"]:  # شرط=وضعیت نامعتبر
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CONFIRM", "message": "order is not in schedulable state"})  # خطا=۴۰۹

    slot_dt = parse_iso(body.slot)  # slot_dt=زمان انتخابی UTC
    end_dt = slot_dt + timedelta(hours=1)  # end_dt=پایان یک ساعت

    async with database.transaction():  # تراکنش=اتمیک
        slot_row = await database.fetch_one(  # slot_row=اسلات انتخابی
            ScheduleSlotTable.__table__.select().where(
                (ScheduleSlotTable.request_id == int(order_id)) &  # شرط=همین سفارش
                (ScheduleSlotTable.slot_start == slot_dt) &  # شرط=همین زمان
                (ScheduleSlotTable.status == "PROPOSED")  # شرط=پیشنهادی
            )  # پایان where
        )  # پایان fetch_one
        if not slot_row:  # شرط=نبود اسلات
            raise HTTPException(status_code=404, detail="slot not found for this order")  # خطا=۴۰۴

        provider = _normalize_phone(str(slot_row["provider_phone"] or ""))  # provider=شماره سرویس‌دهنده
        if not provider:  # شرط=نبود سرویس‌دهنده
            raise HTTPException(status_code=400, detail="provider_phone missing on slot")  # خطا=۴۰۰

        free = await provider_is_free(provider, slot_dt, end_dt, exclude_order_id=int(order_id))  # free=بررسی تداخل
        if not free:  # شرط=تداخل
            raise HTTPException(status_code=409, detail="selected slot overlaps with existing schedule")  # خطا=۴۰۹

        await database.execute(  # اجرا=لغو رزروهای BOOKED قبلی این سفارش غیر از بازه جدید
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &  # شرط=همین سفارش
                (AppointmentTable.status == "BOOKED") &  # شرط=رزرو فعال
                ((AppointmentTable.start_time != slot_dt) | (AppointmentTable.end_time != end_dt))  # شرط=غیر از بازه جدید
            ).values(status="CANCELED")  # values=لغو
        )  # پایان execute

        await database.execute(  # اجرا=رد سایر اسلات‌های فعال این سفارش
            ScheduleSlotTable.__table__.update().where(
                (ScheduleSlotTable.request_id == int(order_id)) &  # شرط=همین سفارش
                (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &  # شرط=فعال
                (ScheduleSlotTable.slot_start != slot_dt)  # شرط=غیر از انتخابی
            ).values(status="REJECTED")  # values=رد
        )  # پایان execute

        await database.execute(  # اجرا=پذیرفتن اسلات انتخابی
            ScheduleSlotTable.__table__.update().where(
                (ScheduleSlotTable.request_id == int(order_id)) &  # شرط=همین سفارش
                (ScheduleSlotTable.slot_start == slot_dt)  # شرط=همین زمان
            ).values(status="ACCEPTED")  # values=پذیرفته
        )  # پایان execute

        any_row = await database.fetch_one(  # any_row=رزرو موجود با همین بازه
            AppointmentTable.__table__.select().where(
                (AppointmentTable.provider_phone == provider) &  # شرط=سرویس‌دهنده
                (AppointmentTable.start_time == slot_dt) &  # شرط=شروع
                (AppointmentTable.end_time == end_dt)  # شرط=پایان
            ).limit(1)  # limit=۱
        )  # پایان fetch_one

        if any_row:  # شرط=رزرو موجود
            if (str(any_row["status"] or "").strip().upper() == "BOOKED") and (int(any_row["request_id"] or 0) != int(order_id)):  # شرط=BOOKED برای سفارش دیگر
                raise HTTPException(status_code=409, detail="selected slot overlaps with existing schedule")  # خطا=۴۰۹
            await database.execute(  # اجرا=آپدیت رزرو موجود برای این سفارش
                AppointmentTable.__table__.update().where(AppointmentTable.id == int(any_row["id"])).values(
                    request_id=int(order_id),  # request_id=این سفارش
                    status="BOOKED"  # status=رزرو
                )  # پایان values
            )  # پایان execute
        else:  # حالت=رزرو وجود ندارد
            try:  # try=محافظ یکتا
                await database.execute(  # اجرا=insert رزرو جدید
                    AppointmentTable.__table__.insert().values(
                        provider_phone=provider,  # provider_phone=سرویس‌دهنده
                        request_id=int(order_id),  # request_id=سفارش
                        start_time=slot_dt,  # start_time=شروع
                        end_time=end_dt,  # end_time=پایان
                        status="BOOKED",  # status=رزرو
                        created_at=datetime.now(timezone.utc)  # created_at=اکنون
                    )  # پایان values
                )  # پایان execute
            except Exception as e:  # catch=خطا
                msg = str(e)  # msg=متن خطا
                if ("uq_provider_slot" in msg) or ("duplicate key value" in msg):  # شرط=برخورد یکتا
                    any_row2 = await database.fetch_one(  # any_row2=خواندن مجدد
                        AppointmentTable.__table__.select().where(
                            (AppointmentTable.provider_phone == provider) &  # شرط=سرویس‌دهنده
                            (AppointmentTable.start_time == slot_dt) &  # شرط=شروع
                            (AppointmentTable.end_time == end_dt)  # شرط=پایان
                        ).limit(1)  # limit=۱
                    )  # پایان fetch_one
                    if any_row2 and (str(any_row2["status"] or "").strip().upper() == "BOOKED") and (int(any_row2["request_id"] or 0) != int(order_id)):  # شرط=BOOKED برای سفارش دیگر
                        raise HTTPException(status_code=409, detail="selected slot overlaps with existing schedule")  # خطا=۴۰۹
                    if any_row2:  # شرط=پیدا شد
                        await database.execute(  # اجرا=آپدیت رزرو موجود
                            AppointmentTable.__table__.update().where(AppointmentTable.id == int(any_row2["id"])).values(
                                request_id=int(order_id),  # request_id=این سفارش
                                status="BOOKED"  # status=رزرو
                            )  # پایان values
                        )  # پایان execute
                    else:  # حالت=پیدا نشد
                        raise  # raise=پرتاب مجدد
                else:  # حالت=خطای دیگر
                    raise  # raise=پرتاب مجدد

        await database.execute(  # اجرا=آپدیت سفارش با زمان قطعی
            RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
                scheduled_start=slot_dt,  # scheduled_start=زمان قطعی
                status="ASSIGNED",  # status=ASSIGNED
                driver_phone=provider  # driver_phone=سرویس‌دهنده
            )  # پایان values
        )  # پایان execute

    try:  # try=اعلان فقط به مدیر/سرویس‌دهنده
        await notify_managers(  # اعلان=به مدیر
            title="تأیید زمان بازدید",  # title=عنوان
            body=f"کاربر زمان بازدید را تأیید کرد (order_id={int(order_id)}).",  # body=متن
            data=order_push_data(  # data=داده استاندارد
                msg_type="time_confirm",  # msg_type=نوع پیام
                order_id=int(order_id),  # order_id=شناسه
                status="ASSIGNED",  # status=وضعیت
                service_type=str(req_row["service_type"] or ""),  # service_type=نوع سرویس
                scheduled_start=slot_dt  # scheduled_start=زمان بازدید
            ),  # پایان data
            target_phone=provider  # target_phone=هدف
        )  # پایان notify
    except Exception as e:  # catch=خطا
        logger.error(f"notify(confirm_slot->manager_only) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": slot_dt.isoformat(), "end": end_dt.isoformat()})  # پاسخ=تأیید شد

# -------------------- User: reject all and cancel --------------------  # بخش=رد همه اسلات‌ها و لغو سفارش

@app.post("/order/{order_id}/reject_all_and_cancel")  # مسیر=لغو توسط کاربر (رد همه)
async def reject_all_and_cancel(order_id: int, request: Request):  # تابع=لغو و رد
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))  # req=سفارش
    if not req:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴
    require_user_phone(request, str(req["user_phone"]))  # احراز=کاربر همان سفارش

    if req["execution_start"] is not None:  # شرط=بعد از زمان اجرا
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CANCEL", "message": "order cannot be canceled at this stage"})  # خطا=۴۰۹

    st = str(req["status"] or "").strip().upper()  # st=وضعیت
    if st not in ["NEW", "WAITING", "ASSIGNED"]:  # شرط=قابل لغو بودن
        raise HTTPException(status_code=409, detail={"code": "CANNOT_CANCEL", "message": "order cannot be canceled at this stage"})  # خطا=۴۰۹

    await database.execute(  # اجرا=رد اسلات‌های فعال
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == int(order_id)) &  # شرط=سفارش
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))  # شرط=فعال
        ).values(status="REJECTED")  # values=رد
    )  # پایان execute

    await database.execute(  # اجرا=لغو رزروهای BOOKED
        AppointmentTable.__table__.update().where(
            (AppointmentTable.request_id == int(order_id)) &  # شرط=سفارش
            (AppointmentTable.status == "BOOKED")  # شرط=رزرو
        ).values(status="CANCELED")  # values=لغو
    )  # پایان execute

    await database.execute(  # اجرا=لغو سفارش
        RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
            status="CANCELED",  # status=لغو
            scheduled_start=None,  # scheduled_start=پاک
            execution_start=None  # execution_start=پاک
        )  # پایان values
    )  # پایان execute

    try:  # try=اعلان مدیر
        await notify_managers(  # اعلان=به مدیرها
            title="لغو سفارش",  # title=عنوان
            body=f"سفارش {int(order_id)} توسط کاربر لغو شد.",  # body=متن
            data={"order_id": int(order_id), "status": "CANCELED", "user_phone": _normalize_phone(str(req["user_phone"]))}  # data=اطلاعات
        )  # پایان notify
    except Exception as e:  # catch=خطا
        logger.error(f"notify_managers(reject_all_and_cancel) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "ORDER_CANCELED", "order canceled", {"order_id": int(order_id)})  # پاسخ=لغو شد

# -------------------- Admin: set price / finish / cancel --------------------  # بخش=اکشن‌های مدیر

@app.post("/admin/order/{order_id}/price")  # مسیر=ثبت قیمت و زمان اجرا
async def admin_set_price(order_id: int, body: PriceBody, request: Request):  # تابع=ثبت قیمت/زمان اجرا
    require_admin(request)  # احراز=ادمین

    req_row = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))  # req_row=سفارش
    if not req_row:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    provider = _normalize_phone(str(req_row["driver_phone"] or ""))  # provider=سرویس‌دهنده
    service_type = str(req_row["service_type"] or "")  # service_type=نوع سرویس
    now = datetime.now(timezone.utc)  # now=اکنون

    exec_dt: Optional[datetime] = None  # exec_dt=زمان اجرا
    new_status = "PRICE_REJECTED"  # new_status=پیش‌فرض

    async with database.transaction():  # تراکنش=اتمیک
        if bool(body.agree):  # شرط=توافق
            if not body.exec_time or not str(body.exec_time).strip():  # شرط=نیاز به زمان اجرا
                raise HTTPException(status_code=400, detail="exec_time required when agree=true")  # خطا=۴۰۰
            if not provider:  # شرط=نبود سرویس‌دهنده
                raise HTTPException(status_code=400, detail="driver_phone(provider) not set for this order")  # خطا=۴۰۰

            exec_dt = parse_iso(str(body.exec_time))  # exec_dt=پارس UTC
            end_dt = exec_dt + timedelta(hours=1)  # end_dt=پایان یک ساعت

            free = await provider_is_free(provider, exec_dt, end_dt, exclude_order_id=int(order_id))  # free=آزاد بودن
            if not free:  # شرط=تداخل
                raise HTTPException(status_code=409, detail="execution time overlaps with existing schedule")  # خطا=۴۰۹

            any_row = await database.fetch_one(  # any_row=رزرو موجود با همین بازه
                AppointmentTable.__table__.select().where(
                    (AppointmentTable.provider_phone == provider) &  # شرط=سرویس‌دهنده
                    (AppointmentTable.start_time == exec_dt) &  # شرط=شروع
                    (AppointmentTable.end_time == end_dt)  # شرط=پایان
                ).limit(1)  # limit=۱
            )  # پایان fetch_one

            if any_row:  # شرط=رزرو وجود دارد
                if (str(any_row["status"] or "").strip().upper() == "BOOKED") and (int(any_row["request_id"] or 0) != int(order_id)):  # شرط=BOOKED برای سفارش دیگر
                    raise HTTPException(status_code=409, detail="execution time overlaps with existing schedule")  # خطا=۴۰۹
                await database.execute(  # اجرا=آپدیت رزرو موجود
                    AppointmentTable.__table__.update().where(AppointmentTable.id == int(any_row["id"])).values(
                        request_id=int(order_id),  # request_id=این سفارش
                        status="BOOKED"  # status=رزرو
                    )  # پایان values
                )  # پایان execute
            else:  # حالت=رزرو وجود ندارد
                try:  # try=محافظ یکتا
                    await database.execute(  # اجرا=insert رزرو جدید
                        AppointmentTable.__table__.insert().values(
                            provider_phone=provider,  # provider_phone=سرویس‌دهنده
                            request_id=int(order_id),  # request_id=سفارش
                            start_time=exec_dt,  # start_time=شروع
                            end_time=end_dt,  # end_time=پایان
                            status="BOOKED",  # status=رزرو
                            created_at=now  # created_at=اکنون
                        )  # پایان values
                    )  # پایان execute
                except Exception as e:  # catch=خطا
                    msg = str(e)  # msg=متن خطا
                    if ("uq_provider_slot" in msg) or ("duplicate key value" in msg):  # شرط=برخورد یکتا
                        any_row2 = await database.fetch_one(  # any_row2=خواندن مجدد
                            AppointmentTable.__table__.select().where(
                                (AppointmentTable.provider_phone == provider) &  # شرط=سرویس‌دهنده
                                (AppointmentTable.start_time == exec_dt) &  # شرط=شروع
                                (AppointmentTable.end_time == end_dt)  # شرط=پایان
                            ).limit(1)  # limit=۱
                        )  # پایان fetch_one
                        if any_row2 and (str(any_row2["status"] or "").strip().upper() == "BOOKED") and (int(any_row2["request_id"] or 0) != int(order_id)):  # شرط=BOOKED برای سفارش دیگر
                            raise HTTPException(status_code=409, detail="execution time overlaps with existing schedule")  # خطا=۴۰۹
                        if any_row2:  # شرط=پیدا شد
                            await database.execute(  # اجرا=آپدیت رزرو موجود
                                AppointmentTable.__table__.update().where(AppointmentTable.id == int(any_row2["id"])).values(
                                    request_id=int(order_id),  # request_id=این سفارش
                                    status="BOOKED"  # status=رزرو
                                )  # پایان values
                            )  # پایان execute
                        else:  # حالت=پیدا نشد
                            raise  # raise=پرتاب مجدد
                    else:  # حالت=خطای دیگر
                        raise  # raise=پرتاب مجدد

            new_status = "IN_PROGRESS"  # new_status=در حال انجام

        saved = await database.fetch_one(  # saved=آپدیت سفارش و گرفتن خروجی
            RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
                price=int(body.price),  # price=قیمت
                status=new_status,  # status=وضعیت
                execution_start=exec_dt  # execution_start=زمان اجرا
            ).returning(RequestTable.id, RequestTable.price, RequestTable.status, RequestTable.execution_start)  # returning=فیلدها
        )  # پایان fetch_one

    try:  # try=اعلان کاربر
        if bool(body.agree):  # شرط=توافق
            await notify_user(  # اعلان=به کاربر
                phone=str(req_row["user_phone"]),  # phone=کاربر
                title="توافق قیمت",  # title=عنوان
                body=f"قیمت {int(body.price)} ثبت شد.",  # body=متن
                data=order_push_data(  # data=داده استاندارد
                    msg_type="execution_time",  # msg_type=زمان اجرا
                    order_id=int(order_id),  # order_id=شناسه
                    status=str(new_status),  # status=وضعیت
                    service_type=service_type,  # service_type=نوع سرویس
                    scheduled_start=req_row["scheduled_start"],  # scheduled_start=اگر موجود
                    execution_start=exec_dt,  # execution_start=زمان اجرا
                    price=int(body.price)  # price=قیمت
                )  # پایان data
            )  # پایان notify
        else:  # حالت=عدم توافق
            await notify_user(  # اعلان=به کاربر
                phone=str(req_row["user_phone"]),  # phone=کاربر
                title="عدم توافق قیمت",  # title=عنوان
                body="قیمت مورد توافق قرار نگرفت.",  # body=متن
                data=order_push_data(  # data=داده استاندارد
                    msg_type="price_set",  # msg_type=قیمت
                    order_id=int(order_id),  # order_id=شناسه
                    status=str(new_status),  # status=وضعیت
                    service_type=service_type,  # service_type=نوع سرویس
                    scheduled_start=req_row["scheduled_start"],  # scheduled_start=اگر موجود
                    execution_start=None,  # execution_start=ندارد
                    price=int(body.price)  # price=قیمت
                )  # پایان data
            )  # پایان notify
    except Exception as e:  # catch=خطا
        logger.error(f"notify_user(admin_set_price) failed: {e}")  # لاگ=خطا

    return unified_response(  # پاسخ=نتیجه
        "ok",  # status=ok
        "PRICE_SET",  # code=کد
        "price/status updated",  # message=پیام
        {  # data=خروجی
            "order_id": int(saved["id"]) if saved else int(order_id),  # order_id=شناسه
            "price": int(saved["price"]) if saved else int(body.price),  # price=قیمت
            "status": str(saved["status"]) if saved else str(new_status),  # status=وضعیت
            "execution_start": (saved["execution_start"].astimezone(timezone.utc).isoformat() if (saved and saved["execution_start"]) else None)  # execution_start=ISO
        }  # پایان data
    )  # پایان پاسخ

@app.post("/order/{order_id}/finish")  # مسیر=اتمام کار
async def finish_order(order_id: int, request: Request):  # تابع=finish
    require_admin(request)  # احراز=ادمین

    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))  # req=سفارش
    if not req:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    now_iso = datetime.now(timezone.utc).isoformat()  # now_iso=زمان پایان

    async with database.transaction():  # تراکنش=اتمیک
        await database.execute(  # اجرا=آپدیت سفارش
            RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
                status="FINISH",  # status=FINISH
                finish_datetime=now_iso  # finish_datetime=اکنون
            )  # پایان values
        )  # پایان execute

        await database.execute(  # اجرا=آزادسازی appointmentها
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &  # شرط=سفارش
                (AppointmentTable.status == "BOOKED")  # شرط=رزرو فعال
            ).values(status="DONE")  # values=DONE
        )  # پایان execute

    try:  # try=اعلان‌ها
        await notify_user(  # اعلان=به کاربر
            phone=str(req["user_phone"]),  # phone=کاربر
            title="اتمام کار",  # title=عنوان
            body="سفارش شما انجام شد.",  # body=متن
            data={"type": "work_finished", "order_id": int(order_id), "status": "FINISH", "service_type": str(req["service_type"] or "")}  # data=اطلاعات
        )  # پایان notify_user
    except Exception as e:  # catch=خطا
        logger.error(f"notify(finish_order) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "ORDER_FINISHED", "order finished", {"order_id": int(order_id), "status": "FINISH"})  # پاسخ=موفق

@app.post("/admin/order/{order_id}/cancel")  # مسیر=لغو توسط مدیر
async def admin_cancel_order(order_id: int, request: Request):  # تابع=لغو مدیر
    require_admin(request)  # احراز=ادمین

    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == int(order_id)))  # req=سفارش
    if not req:  # شرط=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=۴۰۴

    await database.execute(  # اجرا=لغو سفارش
        RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
            status="CANCELED",  # status=لغو
            scheduled_start=None,  # scheduled_start=پاک
            execution_start=None  # execution_start=پاک
        )  # پایان values
    )  # پایان execute

    await database.execute(  # اجرا=رد اسلات‌ها
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == int(order_id)) &  # شرط=سفارش
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))  # شرط=فعال
        ).values(status="REJECTED")  # values=رد
    )  # پایان execute

    await database.execute(  # اجرا=لغو appointmentها
        AppointmentTable.__table__.update().where(
            (AppointmentTable.request_id == int(order_id)) &  # شرط=سفارش
            (AppointmentTable.status == "BOOKED")  # شرط=رزرو فعال
        ).values(status="CANCELED")  # values=لغو
    )  # پایان execute

    try:  # try=اعلان کاربر
        await notify_user(  # اعلان=به کاربر
            phone=str(req["user_phone"]),  # phone=کاربر
            title="لغو سفارش",  # title=عنوان
            body="سفارش شما توسط مدیر لغو شد.",  # body=متن
            data={"type": "order_canceled", "order_id": int(order_id), "status": "CANCELED", "service_type": str(req["service_type"] or ""), "canceled_by": "manager"}  # data=اطلاعات
        )  # پایان notify_user
    except Exception as e:  # catch=خطا
        logger.error(f"notify(admin_cancel_order) failed: {e}")  # لاگ=خطا

    return unified_response("ok", "ORDER_CANCELED", "order canceled by admin", {"order_id": int(order_id), "status": "CANCELED"})  # پاسخ=موفق

# -------------------- Debug --------------------  # بخش=دیباگ

@app.get("/debug/routes")  # مسیر=لیست routeها
def debug_routes():  # تابع=برگرداندن routeها
    out: List[dict] = []  # out=لیست خروجی
    for r in app.router.routes:  # حلقه=روی routeها
        path = getattr(r, "path", "")  # path=مسیر
        methods = sorted(list(getattr(r, "methods", []) or []))  # methods=متدها
        name = getattr(r, "name", "")  # name=نام
        out.append({"path": path, "methods": methods, "name": name})  # افزودن=به خروجی
    return {"items": out}  # پاسخ=لیست

@app.get("/debug/users")  # مسیر=دیباگ کاربران
async def debug_users():  # تابع=لیست کاربران
    rows = await database.fetch_all(UserTable.__table__.select().order_by(UserTable.id.asc()))  # rows=همه کاربران
    out: List[dict] = []  # out=خروجی
    for r in rows:  # حلقه=روی کاربران
        out.append({"id": int(r["id"]), "phone": str(r["phone"] or ""), "name": str(r["name"] or ""), "address": str(r["address"] or "")})  # افزودن=آیتم
    return {"items": out}  # پاسخ=لیست

