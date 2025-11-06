# FILE: server/main.py  # FastAPI server with JWT + FCM HTTP v1 push  # فایل=سرور کامل (تأیید زمان پایدار با date_trunc + لاگ؛ رفع باگ logout و trim→strip)

# -*- coding: utf-8 -*-  # کدگذاری فایل

import os  # خواندن Env
import re  # Regex برای استخراج errorCode از پاسخ FCM
import hashlib  # هش refresh token
import secrets  # تولید توکن امن
from datetime import datetime, timedelta, timezone  # تاریخ/زمان
from typing import Optional, List, Dict  # تایپ‌ها

import bcrypt  # هش رمز
import jwt  # PyJWT (برای JWT داخلی و امضای سرویس‌اکانت)
from fastapi import FastAPI, HTTPException, Request  # FastAPI
from fastapi.middleware.cors import CORSMiddleware  # CORS
from pydantic import BaseModel  # بدنه‌ها

from sqlalchemy import (  # ORM
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_, text, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import JSONB  # JSONB
from sqlalchemy.ext.declarative import declarative_base  # Base ORM
import sqlalchemy  # Engine
from databases import Database  # async DB
from dotenv import load_dotenv  # بارگذاری .env
import httpx  # HTTP async

import json  # JSON سرویس‌اکانت
import base64  # Base64 سرویس‌اکانت
import time  # کش توکن OAuth2
import logging  # لاگ

# -------------------- Config --------------------
load_dotenv()  # بارگذاری .env

DATABASE_URL = os.getenv("DATABASE_URL")  # URL دیتابیس
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # کلید JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # پپر رمز
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # مدت اعتبار دسترسی
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # مدت اعتبار رفرش
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # دور هش
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # مبداهای مجاز CORS

# Legacy (پشتیبان)
FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "").strip()  # کلید Legacy FCM

# FCM HTTP v1
FCM_PROJECT_ID = os.getenv("FCM_PROJECT_ID", "").strip()  # شناسه پروژه (Fallback)
GOOGLE_APPLICATION_CREDENTIALS_JSON = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "").strip()  # JSON سرویس‌اکانت
GOOGLE_APPLICATION_CREDENTIALS_JSON_B64 = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON_B64", "").strip()  # JSON سرویس‌اکانت (Base64)

ADMIN_KEY = os.getenv("ADMIN_KEY", "CHANGE_ME_ADMIN")  # کلید ادمین

AUTH_COMPAT = os.getenv("AUTH_COMPAT", "1").strip()  # سازگاری قدیمی

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "600"))  # پنجره لاگین
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # حداکثر تلاش
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "1800"))  # قفل موقت

PUSH_BACKEND = os.getenv("PUSH_BACKEND", "fcm").strip().lower()  # بک‌اند پوش
NTFY_BASE_URL = os.getenv("NTFY_BASE_URL", "https://ntfy.sh").strip()  # آدرس ntfy
NTFY_AUTH = os.getenv("NTFY_AUTH", "").strip()  # توکن ntfy

# لاگر پوش
logger = logging.getLogger("putz.push")  # لاگر اختصاصی پوش
if not logger.handlers:  # درصورت نبود هندلر
    h = logging.StreamHandler()  # استریم هندلر
    fmt = logging.Formatter("[PUSH] %(levelname)s: %(message)s")  # فرمت
    h.setFormatter(fmt)  # اعمال فرمت
    logger.addHandler(h)  # افزودن هندلر
logger.setLevel(logging.INFO)  # سطح لاگ

database = Database(DATABASE_URL)  # اتصال async دیتابیس
Base = declarative_base()  # Base ORM

# -------------------- ORM models --------------------
class UserTable(Base):  # مدل جدول کاربران
    __tablename__ = "users"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # کلید
    phone = Column(String, unique=True, index=True)  # شماره
    password_hash = Column(String)  # هش رمز
    address = Column(String)  # آدرس
    name = Column(String, default="")  # نام
    car_list = Column(JSONB, default=list)  # لیست ماشین‌ها

class DriverTable(Base):  # مدل راننده (استفاده احتمالی)
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

class RequestTable(Base):  # جدول سفارش
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)  # کلید
    user_phone = Column(String, index=True)  # شماره کاربر
    latitude = Column(Float)  # عرض
    longitude = Column(Float)  # طول
    car_list = Column(JSONB)  # لیست خودرو/آیتم‌ها
    address = Column(String)  # آدرس
    home_number = Column(String, default="")  # پلاک
    service_type = Column(String, index=True)  # نوع سرویس
    price = Column(Integer)  # قیمت
    request_datetime = Column(String)  # زمان ثبت
    status = Column(String)  # وضعیت
    driver_name = Column(String)  # نام راننده
    driver_phone = Column(String)  # شماره راننده
    finish_datetime = Column(String)  # زمان پایان
    payment_type = Column(String)  # روش پرداخت
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # زمان تأیید شده
    service_place = Column(String, default="client")  # محل سرویس
    execution_start = Column(DateTime(timezone=True), nullable=True)  # شروع اجرا

class RefreshTokenTable(Base):  # جدول رفرش توکن
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    token_hash = Column(String, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), index=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)

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
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)

class ScheduleSlotTable(Base):  # جدول اسلات‌های پیشنهادی
    __tablename__ = "schedule_slots"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)
    provider_phone = Column(String, index=True)
    slot_start = Column(DateTime(timezone=True), index=True)
    status = Column(String, default="PROPOSED")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)

class AppointmentTable(Base):  # جدول رزرو نهایی
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
    __table_args__ = (Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),)

class DeviceTokenTable(Base):  # جدول توکن‌های دستگاه
    __tablename__ = "device_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    role = Column(String, index=True)
    platform = Column(String, default="android", index=True)
    user_phone = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_tokens_role_platform", "role", "platform"),)

# -------------------- Pydantic models --------------------
class CarInfo(BaseModel):  # مدل ورودی ماشین
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک

class Location(BaseModel):  # مدل مکان
    latitude: float  # عرض
    longitude: float  # طول

class CarOrderItem(BaseModel):  # آیتم سفارش کارواش
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک
    wash_outside: bool = False  # روشویی
    wash_inside: bool = False  # توشویی
    polish: bool = False  # پولیش

class OrderRequest(BaseModel):  # بدنه ثبت سفارش
    user_phone: str  # شماره کاربر
    location: Location  # مکان
    car_list: List[CarOrderItem]  # آیتم‌ها
    address: str  # آدرس
    home_number: Optional[str] = ""  # پلاک
    service_type: str  # نوع سرویس
    price: int  # قیمت
    request_datetime: str  # زمان ثبت
    payment_type: str  # پرداخت
    service_place: str  # محل سرویس

class CarListUpdateRequest(BaseModel):  # بدنه ذخیره لیست خودرو
    user_phone: str  # شماره
    car_list: List[CarInfo]  # لیست خودرو

class CancelRequest(BaseModel):  # بدنه لغو سفارش
    user_phone: str  # شماره
    service_type: str  # سرویس

class UserRegisterRequest(BaseModel):  # بدنه ثبت‌نام
    phone: str  # شماره
    password: str  # رمز
    address: Optional[str] = None  # آدرس

class UserLoginRequest(BaseModel):  # بدنه ورود
    phone: str  # شماره
    password: str  # رمز

class UserProfileUpdate(BaseModel):  # بدنه ذخیره پروفایل
    phone: str  # شماره
    name: str = ""  # نام
    address: str = ""  # آدرس

class ProposedSlotsRequest(BaseModel):  # بدنه پیشنهاد اسلات‌ها
    provider_phone: str  # شماره سرویس‌دهنده
    slots: List[str]  # لیست اسلات‌ها

class ConfirmSlotRequest(BaseModel):  # بدنه تایید اسلات
    slot: str  # زمان ISO

class PriceBody(BaseModel):  # بدنه تعیین قیمت
    price: int  # قیمت
    agree: bool  # موافقت
    exec_time: Optional[str] = None  # زمان اجرا

class PushRegister(BaseModel):  # بدنه ثبت توکن
    role: str  # نقش
    token: str  # توکن
    platform: str = "android"  # پلتفرم
    user_phone: Optional[str] = None  # شماره

class PushUnregister(BaseModel):  # بدنه لغو ثبت توکن
    token: str  # توکن دستگاه

class LogoutRequest(BaseModel):  # بدنه خروج
    refresh_token: str  # رفرش توکن
    device_token: Optional[str] = None  # توکن دستگاه (اختیاری؛ برای حذف دقیق‌تر)

# -------------------- Security helpers --------------------
def bcrypt_hash_password(password: str) -> str:  # تابع هش رمز
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # تولید نمک
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب با پپر
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # هش و بازگشت

def verify_password_secure(password: str, stored_hash: str) -> bool:  # بررسی رمز
    try:
        if stored_hash.startswith("$2"):  # اگر bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # بررسی
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # سازگاری قدیمی
        return old == stored_hash  # مقایسه
    except Exception:
        return False  # خطا → نادرست

def create_access_token(phone: str) -> str:  # ساخت توکن دسترسی
    now = datetime.now(timezone.utc)  # اکنون
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # بدنه
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # امضاء

def create_refresh_token() -> str:  # ساخت رفرش
    return secrets.token_urlsafe(48)  # توکن امن

def hash_refresh_token(token: str) -> str:  # هش رفرش با پپر
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # هش

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # پاسخ واحد
    return {"status": status, "code": code, "message": message, "data": (data or {})}  # قالب

def extract_bearer_token(request: Request) -> Optional[str]:  # استخراج Bearer
    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""  # هدر
    if not auth.lower().startswith("bearer "):  # اگر Bearer نبود
        return None  # خروج
    return auth.split(" ", 1)[1].strip()  # برگرداندن توکن

def decode_access_token(token: str) -> Optional[dict]:  # دیکود JWT
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # دیکود
        if payload.get("type") != "access":  # نوع نادرست
            return None  # خروج
        return payload  # payload
    except Exception:
        return None  # خطا

def get_auth_phone(request: Request, fallback_phone: Optional[str] = None, enforce: bool = False) -> str:  # گرفتن شماره احراز
    token = extract_bearer_token(request)  # استخراج توکن
    if token:
        payload = decode_access_token(token)  # دیکود
        if not payload or not payload.get("sub"):  # نامعتبر
            raise HTTPException(status_code=401, detail="invalid token")  # 401
        sub = str(payload["sub"])  # شماره
        if fallback_phone and sub != fallback_phone:  # اختلاف شماره
            raise HTTPException(status_code=403, detail="forbidden")  # 403
        return sub  # بازگشت شماره
    if AUTH_COMPAT == "1" and fallback_phone:  # سازگاری
        return fallback_phone  # بازگشت
    if enforce:  # الزام
        raise HTTPException(status_code=401, detail="missing bearer token")  # 401
    return fallback_phone or ""  # بازگشت

def require_admin(request: Request):  # اعتبارسنجی ادمین
    key = request.headers.get("x-admin-key", "")  # دریافت کلید
    if not key or key != ADMIN_KEY:  # مقایسه
        raise HTTPException(status_code=401, detail="admin auth required")  # 401

# -------------------- Utils --------------------
def get_client_ip(request: Request) -> str:  # IP کلاینت
    xff = request.headers.get("x-forwarded-for", "")  # هدر XFF
    if xff:
        return xff.split(",")[0].strip()  # اولین IP
    return request.client.host or "unknown"  # IP مستقیم

def parse_iso(ts: str) -> datetime:  # پارس ISO به datetime
    try:
        raw = ts.strip()  # رشته
        if "T" not in raw:
            raise ValueError("no T in ISO")  # اعتبارسنجی
        date_part, time_part = raw.split("T", 1)  # جداسازی
        time_part = time_part.replace("Z", "")  # حذف Z
        for sign in ["+", "-"]:  # حذف آفست نهایی
            idx = time_part.find(sign)
            if idx > 0:
                time_part = time_part[:idx]
                break
        if time_part.count(":") == 1:
            time_part = f"{time_part}:00"  # افزودن ثانیه
        y, m, d = map(int, date_part.split("-"))  # تاریخ
        hh, mm, ss = map(int, time_part.split(":"))  # زمان
        dt = datetime(y, m, d, hh, mm, ss, tzinfo=timezone.utc)  # datetime UTC
        return dt  # بازگشت
    except Exception:
        raise HTTPException(status_code=400, detail=f"invalid datetime: {ts}")  # 400

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:  # بررسی اشغال بودن
    q = AppointmentTable.__table__.select().where(  # کوئری
        (AppointmentTable.provider_phone == provider_phone) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.end_time > start)
    )
    rows = await database.fetch_all(q)  # اجرا
    return len(rows) == 0  # آزاد بودن

async def notify_user(phone: str, title: str, body: str, data: Optional[dict] = None):  # درج اعلان در DB
    ins = NotificationTable.__table__.insert().values(  # درج
        user_phone=phone, title=title, body=body, data=(data or {}), read=False, created_at=datetime.now(timezone.utc)
    )
    await database.execute(ins)  # اجرا

# -------------------- Push helpers (FCM v1 + Legacy) --------------------
_FCM_OAUTH_TOKEN = ""  # کش توکن OAuth2
_FCM_OAUTH_EXP = 0.0  # انقضای کش

def _load_service_account() -> Optional[dict]:  # بارگذاری سرویس‌اکانت
    raw = GOOGLE_APPLICATION_CREDENTIALS_JSON  # خواندن ENV متنی
    if not raw and GOOGLE_APPLICATION_CREDENTIALS_JSON_B64:  # اگر Base64 موجود است
        try:
            raw = base64.b64decode(GOOGLE_APPLICATION_CREDENTIALS_JSON_B64).decode("utf-8")  # دیکد Base64
        except Exception as e:
            logger.error(f"decode service account b64 failed: {e}")  # لاگ خطا
            raw = ""  # خالی
    if not raw:
        return None  # نبود JSON
    try:
        data = json.loads(raw)  # پارس JSON
        if "client_email" in data and "private_key" in data:  # کلیدها موجود
            pk = data.get("private_key", "")  # کلید خصوصی
            if "\\n" in pk:
                data["private_key"] = pk.replace("\\n", "\n")  # تبدیل \n
            return data  # بازگشت
    except Exception as e:
        logger.error(f"parse service account JSON failed: {e}")  # لاگ خطا
        return None  # خطا
    return None  # پیش‌فرض

def _get_oauth2_token_for_fcm() -> Optional[str]:  # دریافت OAuth2 برای FCM
    global _FCM_OAUTH_TOKEN, _FCM_OAUTH_EXP  # استفاده از کش
    now = time.time()  # اکنون
    if _FCM_OAUTH_TOKEN and (_FCM_OAUTH_EXP - 60) > now:  # هنوز معتبر؟
        return _FCM_OAUTH_TOKEN  # بازگشت کش
    sa = _load_service_account()  # سرویس‌اکانت
    if not sa:
        logger.warning("service account JSON not loaded; skip FCM v1")  # هشدار
        return None  # خروج
    client_email = sa.get("client_email", "")  # ایمیل
    private_key = sa.get("private_key", "")  # کلید
    if not client_email or not private_key:
        logger.warning("service account missing client_email/private_key")  # هشدار
        return None  # خروج
    issued = int(now)  # زمان صدور
    expires = issued + 3600  # انقضا
    payload = {  # payload=JWT assertion برای OAuth2
        "iss": client_email,  # iss=ایمیل سرویس‌اکانت
        "scope": "https://www.googleapis.com/auth/firebase.messaging",  # scope=دسترسی FCM
        "aud": "https://oauth2.googleapis.com/token",  # aud=گیرنده
        "iat": issued,  # iat=زمان صدور
        "exp": expires  # exp=انقضا
    }
    try:
        assertion = jwt.encode(payload, private_key, algorithm="RS256")  # ساخت/امضای assertion
    except Exception as e:
        logger.error(f"build assertion failed: {e}")  # خطای ساخت assertion
        return None  # خروج
    try:
        resp = httpx.post(  # درخواست توکن
            "https://oauth2.googleapis.com/token",  # URL=اندپوینت توکن
            data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion},  # فرم=نوع گرنت + assertion
            timeout=10.0  # timeout=۱۰ ثانیه
        )
        if resp.status_code != 200:  # بررسی=کد پاسخ
            logger.error(f"oauth token http {resp.status_code} {resp.text}")  # لاگ=خطا
            return None  # خروج
        data = resp.json()  # JSON=پاسخ
        token = data.get("access_token", "")  # استخراج=access_token
        expires_in = int(data.get("expires_in", 3600))  # استخراج=انقضا
        if token:  # اگر=توکن وجود دارد
            _FCM_OAUTH_TOKEN = token  # ذخیره در کش
            _FCM_OAUTH_EXP = now + expires_in  # ذخیره زمان انقضا
            logger.info("fcm v1 access_token acquired")  # لاگ=گرفتن موفق
            return token  # بازگشت=توکن
        logger.error("oauth token missing access_token")  # لاگ=نبود access_token
    except Exception as e:
        logger.error(f"oauth token request failed: {e}")  # لاگ=خطای شبکه
    return None  # خروج

async def get_manager_tokens() -> List[str]:  # توکن‌های مدیر
    sel = DeviceTokenTable.__table__.select().where(
        (DeviceTokenTable.role == "manager") & (DeviceTokenTable.platform == "android")
    )
    rows = await database.fetch_all(sel)
    tokens, seen = [], set()
    for r in rows:
        t = r["token"]
        if t and t not in seen:
            seen.add(t); tokens.append(t)
    return tokens

async def get_user_tokens(phone: str) -> List[str]:  # توکن‌های کاربر
    sel = DeviceTokenTable.__table__.select().where(
        (DeviceTokenTable.role == "client") & (DeviceTokenTable.user_phone == phone)
    )
    rows = await database.fetch_all(sel)
    tokens, seen = [], set()
    for r in rows:
        t = r["token"]
        if t and t not in seen:
            seen.add(t); tokens.append(t)
    return tokens

async def _send_fcm_legacy(tokens: List[str], title: str, body: str, data: Optional[dict], channel_id: str):  # ارسال Legacy
    if not FCM_SERVER_KEY or not tokens:
        logger.info("legacy skipped (no server key or no tokens)")
        return
    url = "https://fcm.googleapis.com/fcm/send"
    headers = {"Authorization": f"key={FCM_SERVER_KEY}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        for t in tokens:
            payload = {
                "to": t,
                "priority": "high",
                "notification": {"title": title, "body": body, "android_channel_id": channel_id},
                "data": data or {}
            }
            try:
                resp = await client.post(url, headers=headers, json=payload)
                logger.info(f"legacy send {resp.status_code} token_tail={t[-8:]} resp={resp.text[:200]}")
            except Exception as e:
                logger.error(f"legacy send failed: {e}")

async def remove_device_token(token: str):  # حذف توکن نامعتبر/خروج
    try:
        delq = DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == token)
        await database.execute(delq)
        logger.info(f"token removed (UNREGISTERED) token_tail={token[-8:]}")
    except Exception as e:
        logger.error(f"remove token failed: {e}")

async def _send_fcm_v1(tokens: List[str], title: str, body: str, data: Optional[dict], channel_id: str):  # ارسال v1
    sa = _load_service_account()  # سرویس‌اکانت
    project_id = (sa or {}).get("project_id") or FCM_PROJECT_ID  # project_id معتبر
    if not tokens or not project_id:
        logger.info("v1 skipped (no tokens or no project id)")  # لاگ=بدون توکن یا project_id
        return  # خروج
    access_token = _get_oauth2_token_for_fcm()  # توکن OAuth2
    if not access_token:  # بررسی=توکن
        logger.error("v1 access_token not available")  # لاگ=عدم دسترسی توکن
        return  # خروج
    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"  # URL=اندپوینت FCM v1
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json; charset=utf-8"}  # هدر=Authorization+JSON
    async with httpx.AsyncClient(timeout=10.0) as client:  # کلاینت=Async
        for t in tokens:  # حلقه=هر توکن
            message = {  # message=ساخت پیام
                "message": {
                    "token": t,
                    "notification": {"title": title, "body": body},
                    "android": {"priority": "HIGH", "notification": {"channel_id": channel_id}},
                    "data": {k: str(v) for (k, v) in (data or {}).items()}
                }
            }
            try:
                resp = await client.post(url, headers=headers, json=message)  # POST=ارسال
                if resp.status_code == 200:  # اگر=موفق
                    logger.info(f"v1 send 200 token_tail={t[-8:]}")  # لاگ=200
                    continue  # ادامه
                text = resp.text  # متن=بدنه
                err_code = ""  # err_code=کد خطا
                try:
                    j = resp.json()  # j=JSON
                    details = (((j or {}).get("error") or {}).get("details") or [])  # details=لیست جزئیات
                    if isinstance(details, list) and len(details) > 0:  # اگر=لیست معتبر
                        err_code = (details[0] or {}).get("errorCode") or ""  # استخراج=errorCode
                except Exception:
                    m = re.search(r'"errorCode"\s*:\s*"([A-Z_]+)"', text or "")  # تلاش=Regex
                    if m:
                        err_code = m.group(1)  # استخراج=errorCode
                logger.info(f"v1 send {resp.status_code} token_tail={t[-8:]} err_code={err_code} resp={text[:300]}")  # لاگ=وضعیت و خطا
                if err_code == "UNREGISTERED" or resp.status_code == 404:  # تشخیص=توکن نامعتبر
                    await remove_device_token(t)  # حذف=توکن
                    if FCM_SERVER_KEY:  # اگر=Legacy موجود
                        await _send_fcm_legacy([t], title, body, data, channel_id)  # ارسال=Legacy
                if err_code == "SENDER_ID_MISMATCH":  # تشخیص=عدم تطابق پروژه
                    logger.error(f"SENDER_ID_MISMATCH: check google-services.json/app project and service account project_id={project_id}")  # لاگ=راهنما
            except Exception as e:
                logger.error(f"v1 send failed: {e}")  # لاگ=شکست ارسال

async def _send_ntfy(topics: List[str], title: str, body: str, data: Optional[dict]):  # ارسال ntfy (درصورت انتخاب)
    if not topics:
        return
    base = NTFY_BASE_URL.rstrip("/")  # base=آدرس پایه
    async with httpx.AsyncClient(timeout=10.0) as client:  # کلاینت=Async
        for topic in topics:  # حلقه=هر تاپیک
            url = f"{base}/{topic}"  # url=آدرس
            headers = {"Title": title, "Priority": "5"}  # headers=هدرها
            if NTFY_AUTH:  # اگر=توکن دارد
                headers["Authorization"] = NTFY_AUTH  # افزودن=هدر احراز
            try:
                resp = await client.post(url, headers=headers, content=(body or ""))  # POST=ارسال
                logger.info(f"ntfy send {resp.status_code} topic={topic}")  # لاگ=نتیجه
            except Exception as e:
                logger.error(f"ntfy send failed: {e}")  # لاگ=شکست

async def send_push_to_tokens(tokens: List[str], title: str, body: str, data: Optional[dict] = None, channel_id: str = "order_status_channel"):  # هاب ارسال پوش
    if PUSH_BACKEND == "ntfy":  # انتخاب=ntfy
        await _send_ntfy(tokens, title, body, data); return  # ارسال=ntfy و خروج
    if (FCM_PROJECT_ID or _load_service_account()) and _get_oauth2_token_for_fcm():  # آماده=FCM v1
        await _send_fcm_v1(tokens, title, body, data, channel_id); return  # ارسال=v1 و خروج
    await _send_fcm_legacy(tokens, title, body, data, channel_id)  # ارسال=Legacy

async def send_push_to_managers(title: str, body: str, data: Optional[dict] = None):  # پوش=به مدیرها
    tokens = await get_manager_tokens()  # جمع‌آوری=توکن‌ها
    logger.info(f"send_to_managers count={len(tokens)} title={title}")  # لاگ=تعداد
    await send_push_to_tokens(tokens, title, body, data, channel_id="putz_manager_general")  # ارسال

async def send_push_to_user(phone: str, title: str, body: str, data: Optional[dict] = None):  # پوش=به کاربر
    tokens = await get_user_tokens(phone)  # جمع‌آوری=توکن‌ها
    logger.info(f"send_to_user phone={phone} tokens={len(tokens)} title={title}")  # لاگ=تعداد
    await send_push_to_tokens(tokens, title, body, data, channel_id="order_status_channel")  # ارسال

# -------------------- App & CORS --------------------
app = FastAPI()  # اپ FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # تنظیم CORS
app.add_middleware(  # افزودن=میان‌افزار CORS
    CORSMiddleware,  # کلاس=CORS
    allow_origins=allow_origins,  # مبداها=مجاز
    allow_credentials=True,  # کوکی=مجاز
    allow_methods=["*"],  # متدها=همه
    allow_headers=["*"],  # هدرها=همه
)

# -------------------- Startup/Shutdown --------------------
@app.on_event("startup")
async def startup():  # شروع برنامه
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # Engine sync برای create_all
    Base.metadata.create_all(engine)  # ساخت جداول
    with engine.begin() as conn:  # تغییر ستون‌های جدید (در صورت نبود)
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # افزودن=scheduled_start
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place TEXT DEFAULT 'client';"))  # افزودن=service_place
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS execution_start TIMESTAMPTZ NULL;"))  # افزودن=execution_start
    await database.connect()  # اتصال async
    ready_v1 = bool((FCM_PROJECT_ID or _load_service_account()) and _get_oauth2_token_for_fcm())  # آماده بودن v1
    logger.info(f"startup FCM_BACKEND={PUSH_BACKEND} v1_ready={ready_v1} project_id={FCM_PROJECT_ID}")  # لاگ وضعیت

@app.on_event("shutdown")
async def shutdown():  # خاموشی
    await database.disconnect()  # قطع اتصال

# -------------------- Health --------------------
@app.get("/")
def read_root():  # سلامت
    return {"message": "Putzfee FastAPI Server is running!"}  # پیام

# -------------------- Auth helpers endpoints --------------------
@app.get("/verify_token")
def verify_token(request: Request):  # بررسی توکن
    token = extract_bearer_token(request)  # استخراج=توکن
    if not token:  # حالت=نبود توکن
        return {"status": "ok", "valid": False}  # خروجی=نامعتبر
    payload = decode_access_token(token)  # دیکود=توکن
    return {"status": "ok", "valid": bool(payload and payload.get("sub"))}  # نتیجه=اعتبار

@app.post("/logout")
async def logout_user(body: LogoutRequest):  # خروج کاربر (حذف توکن دستگاه + ابطال رفرش)
    if not body.refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token required")  # اعتبارسنجی=وجود رفرش
    token_hash = hash_refresh_token(body.refresh_token)  # هش رفرش

    sel_rt = RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash)  # انتخاب=ردیف رفرش
    rt_row = await database.fetch_one(sel_rt)  # دریافت=Record

    upd = RefreshTokenTable.__table__.update().where(  # آپدیت=ابطال رفرش
        RefreshTokenTable.token_hash == token_hash
    ).values(revoked=True)  # مقداردهی=revoked True
    await database.execute(upd)  # اجرا

    if body.device_token and body.device_token.strip():  # حالت=حذف تک‌توکن
        delq = DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == body.device_token.strip())  # کوئری=حذف
        await database.execute(delq)  # اجرا
    else:  # حالت=حذف همه توکن‌های کاربر
        user_id_val = None  # user_id_val=شناسه کاربر
        if rt_row:  # اگر=ردیف وجود دارد
            mapping = getattr(rt_row, "_mapping", {})  # mapping=نگاشت امن ستون‌ها
            user_id_val = mapping["user_id"] if "user_id" in mapping else None  # استخراج=user_id از mapping
            if user_id_val is None:  # تلاش=ایندکس مستقیم
                try:
                    user_id_val = rt_row["user_id"]  # استخراج مستقیم
                except Exception:
                    user_id_val = None  # عدم دسترسی
        if user_id_val is not None:  # ادامه=با user_id
            sel_user = UserTable.__table__.select().where(UserTable.id == user_id_val)  # انتخاب=کاربر
            user = await database.fetch_one(sel_user)  # دریافت=کاربر
            if user:  # اگر=کاربر یافت شد
                phone = user["phone"]  # phone=شماره
                del_all = DeviceTokenTable.__table__.delete().where(DeviceTokenTable.user_phone == phone)  # حذف=همه توکن‌های منتسب
                await database.execute(del_all)  # اجرا

    return unified_response("ok", "LOGOUT", "refresh token revoked and device tokens removed", {})  # خروجی=موفق

# -------------------- Push endpoints --------------------
@app.post("/push/register")
async def register_push_token(body: PushRegister, request: Request):  # ثبت توکن پوش
    now = datetime.now(timezone.utc)  # now=اکنون
    sel = DeviceTokenTable.__table__.select().where(DeviceTokenTable.token == body.token)  # انتخاب=توکن
    row = await database.fetch_one(sel)  # دریافت=ردیف
    if row is None:  # اگر=جدید
        ins = DeviceTokenTable.__table__.insert().values(  # درج=توکن جدید
            token=body.token, role=body.role, platform=body.platform, user_phone=body.user_phone, created_at=now, updated_at=now
        )
        await database.execute(ins)  # اجرا
    else:  # اگر=موجود
        upd = DeviceTokenTable.__table__.update().where(DeviceTokenTable.id == row["id"]).values(  # آپدیت=اطلاعات
            role=body.role, platform=body.platform, user_phone=body.user_phone or row["user_phone"], updated_at=now
        )
        await database.execute(upd)  # اجرا
    logger.info(f"push/register role={body.role} platform={body.platform} phone={body.user_phone}")  # لاگ=ثبت
    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": body.role})  # خروجی

@app.post("/push/unregister")
async def unregister_push_token(body: PushUnregister):  # لغو ثبت توکن پوش (قطع نوتیف پس از خروج)
    delq = DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == body.token)  # حذف=توکن
    await database.execute(delq)  # اجرا
    logger.info(f"push/unregister token_tail={body.token[-8:]}")  # لاگ=حذف
    return unified_response("ok", "TOKEN_UNREGISTERED", "unregistered", {})  # خروجی

# -------------------- Auth/User --------------------
@app.get("/users/exists")
async def user_exists(phone: str):  # بررسی=وجود کاربر
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # کوئری=شمارش
    count = await database.fetch_val(q)  # اجرای=شمارش
    exists = bool(count and int(count) > 0)  # exists=بولین نتیجه
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # خروجی

@app.post("/register_user")
async def register_user(user: UserRegisterRequest):  # ثبت‌نام=کاربر
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # کوئری=وجود
    count = await database.fetch_val(q)  # اجرا
    if count and int(count) > 0:  # بررسی=تکراری
        raise HTTPException(status_code=400, detail="User already exists")  # خطا=تکراری
    password_hash = bcrypt_hash_password(user.password)  # هش=رمز
    ins = UserTable.__table__.insert().values(  # درج=کاربر
        phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[]
    )
    await database.execute(ins)  # اجرا
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # خروجی

@app.post("/login")
async def login_user(user: UserLoginRequest, request: Request):  # ورود=کاربر
    now = datetime.now(timezone.utc)  # now=اکنون
    client_ip = get_client_ip(request)  # client_ip=IP کلاینت

    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))  # انتخاب=ردیف تلاش
    attempt_row = await database.fetch_one(sel_attempt)  # دریافت=ردیف

    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:  # بررسی=قفل
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())  # محاسبه=زمان باقی‌مانده
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after}, headers={"Retry-After": str(retry_after)})  # خطا=429

    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # انتخاب=کاربر
    db_user = await database.fetch_one(sel_user)  # دریافت=کاربر
    if not db_user:  # اگر=یافت نشد
        await _register_login_failure(user.phone, client_ip)  # ثبت=شکست
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})  # خطا=404
    if not verify_password_secure(user.password, db_user["password_hash"]):  # اگر=رمز غلط
        await _register_login_failure(user.phone, client_ip)  # ثبت=شکست
        updated = await database.fetch_one(sel_attempt)  # خواندن=وضعیت جدید تلاش
        attempts = int(updated["attempt_count"]) if updated and updated["attempt_count"] is not None else 1  # attempts=تعداد
        remaining = max(0, LOGIN_MAX_ATTEMPTS - attempts)  # remaining=باقیمانده
        headers = {"X-Remaining-Attempts": str(remaining)}  # هدر=باقیمانده
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": remaining}, headers=headers)  # خطا=401

    await _register_login_success(user.phone, client_ip)  # ثبت=موفقیت

    if not db_user["password_hash"].startswith("$2"):  # اگر=هش قدیمی
        new_hash = bcrypt_hash_password(user.password)  # new_hash=هش جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # آپدیت=فیلد
        await database.execute(upd)  # اجرا

    access_token = create_access_token(db_user["phone"])  # ساخت=توکن دسترسی
    refresh_token = create_refresh_token()  # ساخت=رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # محاسبه=انقضا
    ins_rt = RefreshTokenTable.__table__.insert().values(user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False)  # درج=ردیف رفرش
    await database.execute(ins_rt)  # اجرا

    mapping = getattr(db_user, "_mapping", {})  # mapping=نگاشت امن
    name_val = mapping["name"] if "name" in mapping else ""  # name_val=نام
    address_val = mapping["address"] if "address" in mapping else ""  # address_val=آدرس

    return {"status": "ok", "access_token": access_token, "refresh_token": refresh_token, "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}}  # خروجی

async def _register_login_failure(phone: str, ip: str):  # ثبت=شکست ورود
    now = datetime.now(timezone.utc)  # now=اکنون
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # انتخاب=ردیف
    row = await database.fetch_one(sel)  # دریافت=ردیف
    if row is None:  # اگر=اولین تلاش
        ins = LoginAttemptTable.__table__.insert().values(phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now)  # درج=اولین
        await database.execute(ins); return  # اجرا و خروج
    window_start = row["window_start"] or now  # window_start=شروع پنجره
    within = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS  # within=داخل پنجره
    new_count = (row["attempt_count"] + 1) if within else 1  # new_count=تعداد جدید
    new_window_start = window_start if within else now  # new_window_start=شروع جدید
    locked_until = row["locked_until"]  # locked_until=قفل تا
    if new_count >= LOGIN_MAX_ATTEMPTS:  # اگر=بیش از حد
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # محاسبه=قفل
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now)  # آپدیت=ردیف
    await database.execute(upd)  # اجرا

async def _register_login_success(phone: str, ip: str):  # ثبت=موفقیت ورود
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # انتخاب=ردیف
    row = await database.fetch_one(sel)  # دریافت=ردیف
    if row:  # اگر=وجود دارد
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None)  # ریست=شمارنده/قفل
        await database.execute(upd)  # اجرا

@app.post("/auth/refresh")
async def refresh_access_token(req: Dict):  # رفرش=دسترسی
    refresh_token = req.get("refresh_token", "")  # دریافت=رفرش
    if not refresh_token:  # بررسی=خالی
        raise HTTPException(status_code=400, detail="refresh_token required")  # خطا=400
    token_hash = hash_refresh_token(refresh_token)  # محاسبه=هش
    now = datetime.now(timezone.utc)  # now=اکنون
    sel = RefreshTokenTable.__table__.select().where((RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now))  # انتخاب=رفرش معتبر
    rt = await database.fetch_one(sel)  # دریافت=ردیف
    if not rt:  # اگر=یافت نشد
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا=401
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # انتخاب=کاربر
    db_user = await database.fetch_one(sel_user)  # دریافت=کاربر
    if not db_user:  # اگر=کاربر نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا=401
    new_access = create_access_token(db_user["phone"])  # ساخت=توکن جدید
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # خروجی

# -------------------- Notifications --------------------
@app.get("/user/{phone}/notifications")
async def get_notifications(phone: str, request: Request, only_unread: bool = True, limit: int = 50, offset: int = 0):  # لیست=اعلان‌ها
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)  # احراز=شماره
    if auth_phone != phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    base_sel = NotificationTable.__table__.select().where(NotificationTable.user_phone == phone)  # انتخاب=اعلان‌ها
    if only_unread:  # فیلتر=نخوانده‌ها
        base_sel = base_sel.where(NotificationTable.read == False)  # شرط=read=False
    base_sel = base_sel.order_by(NotificationTable.created_at.desc()).limit(limit).offset(offset)  # مرتب‌سازی/صفحه‌بندی
    rows = await database.fetch_all(base_sel)  # دریافت=لیست
    items = [dict(r) for r in rows]  # تبدیل=dict
    return unified_response("ok", "NOTIFICATIONS", "user notifications", {"items": items})  # خروجی

@app.post("/user/{phone}/notifications/{notif_id}/read")
async def mark_notification_read(phone: str, notif_id: int, request: Request):  # علامت=خوانده‌شدن
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)  # احراز=شماره
    if auth_phone != phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    now = datetime.now(timezone.utc)  # now=اکنون
    upd = NotificationTable.__table__.update().where((NotificationTable.id == notif_id) & (NotificationTable.user_phone == phone)).values(read=True, read_at=now)  # آپدیت=read
    await database.execute(upd)  # اجرا
    return unified_response("ok", "NOTIF_READ", "notification marked as read", {"id": notif_id})  # خروجی

@app.post("/user/{phone}/notifications/mark_all_read")
async def mark_all_notifications_read(phone: str, request: Request):  # علامت=خوانده‌شدن همه
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)  # احراز=شماره
    if auth_phone != phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    now = datetime.now(timezone.utc)  # now=اکنون
    upd = NotificationTable.__table__.update().where((NotificationTable.user_phone == phone) & (NotificationTable.read == False)).values(read=True, read_at=now)  # آپدیت=جمعی
    await database.execute(upd)  # اجرا
    return unified_response("ok", "NOTIFS_READ_ALL", "all notifications marked as read", {})  # خروجی

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str, request: Request):  # دریافت=ماشین‌های کاربر
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)  # احراز
    if auth_phone != user_phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # انتخاب=کاربر
    user = await database.fetch_one(query)  # دریافت=کاربر
    if not user:  # بررسی=نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=404
    items = user["car_list"] or []  # items=لیست
    return unified_response("ok", "USER_CARS", "user cars", {"items": items})  # خروجی

@app.post("/user_cars")
async def update_user_cars(data: CarListUpdateRequest, request: Request):  # ذخیره=لیست ماشین‌ها
    auth_phone = get_auth_phone(request, fallback_phone=data.user_phone, enforce=False)  # احراز
    if auth_phone != data.user_phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # انتخاب=کاربر
    user = await database.fetch_one(sel)  # دریافت=کاربر
    if not user:  # بررسی=نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=404
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(car_list=[car.dict() for car in data.car_list])  # آپدیت=car_list
    await database.execute(upd)  # اجرا
    return unified_response("ok", "CARS_SAVED", "cars saved", {"count": len(data.car_list)})  # خروجی

# -------------------- Orders --------------------
@app.post("/order")
async def create_order(order: OrderRequest, request: Request):  # ایجاد=سفارش
    auth_phone = get_auth_phone(request, fallback_phone=order.user_phone, enforce=False)  # احراز
    if auth_phone != order.user_phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    ins = RequestTable.__table__.insert().values(  # درج=سفارش
        user_phone=order.user_phone,  # شماره=کاربر
        latitude=order.location.latitude,  # عرض
        longitude=order.location.longitude,  # طول
        car_list=[car.dict() for car in order.car_list],  # آیتم‌ها
        address=order.address.strip(),  # آدرس
        home_number=(order.home_number or "").strip(),  # پلاک
        service_type=order.service_type,  # سرویس
        price=order.price,  # قیمت
        request_datetime=order.request_datetime,  # زمان ثبت
        status="NEW",  # وضعیت
        payment_type=order.payment_type.strip().lower(),  # پرداخت
        service_place=order.service_place.strip().lower()  # محل سرویس
    ).returning(RequestTable.id)  # بازگشت=id
    row = await database.fetch_one(ins)  # اجرا و دریافت
    new_id = row[0] if isinstance(row, (tuple, list)) else (row["id"] if row else None)  # استخراج=id
    try:
        await send_push_to_managers("درخواست جدید", "درخواست جدید ثبت شد.", {"type": "new_request", "order_id": str(new_id)})  # پوش=به مدیر
    except Exception as e:
        logger.error(f"push to managers failed: {e}")  # لاگ=خطا
    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # خروجی

@app.post("/cancel_order")
async def cancel_order(cancel: CancelRequest, request: Request):  # لغو=سفارش
    auth_phone = get_auth_phone(request, fallback_phone=cancel.user_phone, enforce=False)  # احراز
    if auth_phone != cancel.user_phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    upd = (RequestTable.__table__.update().where(  # آپدیت=سفارش‌های فعال
        (RequestTable.user_phone == cancel.user_phone) &
        (RequestTable.service_type == cancel.service_type) &
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))
    ).values(status="CANCELED", scheduled_start=None).returning(RequestTable.id))  # مقداردهی=لغو
    rows = await database.fetch_all(upd)  # اجرا و دریافت
    if rows and len(rows) > 0:  # اگر=سفارش لغو شد
        try:
            for r in rows:  # برای=هر id
                mapping = getattr(r, "_mapping", None)  # mapping=نگاشت امن
                oid = mapping["id"] if (mapping and "id" in mapping) else (r[0] if isinstance(r, (tuple, list)) and len(r) > 0 else None)  # استخراج=id
                await send_push_to_managers("لغو درخواست", "کاربر سفارش را لغو کرد.", {"type": "order_canceled", "order_id": str(oid) if oid is not None else ""})  # پوش=به مدیر
        except Exception as e:
            logger.error(f"push to managers failed: {e}")  # لاگ=خطا
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # خروجی
    raise HTTPException(status_code=404, detail="active order not found")  # خطا=404

@app.get("/user_active_services/{user_phone}")
async def get_user_active_services(user_phone: str, request: Request):  # سرویس‌های فعال کاربر
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)  # احراز
    if auth_phone != user_phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    sel = RequestTable.__table__.select().where((RequestTable.user_phone == user_phone) & (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"])))  # انتخاب=فعال‌ها
    result = await database.fetch_all(sel)  # دریافت
    items = [dict(r) for r in result]  # تبدیل=dict
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # خروجی

@app.get("/user_orders/{user_phone}")
async def get_user_orders(user_phone: str, request: Request):  # لیست=سفارش‌ها
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)  # احراز
    if auth_phone != user_phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # انتخاب=سفارش‌ها
    result = await database.fetch_all(sel)  # دریافت
    items = [dict(r) for r in result]  # تبدیل=dict
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # خروجی

# -------------------- Scheduling --------------------
@app.get("/provider/{provider_phone}/free_hours")
async def get_free_hours(provider_phone: str, date: str, work_start: int = 8, work_end: int = 20, limit: int = 24):  # محاسبه=ساعت‌های آزاد
    try:
        d = datetime.fromisoformat(date).date()  # پارس=date
    except Exception:
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # خطا=400
    if not (0 <= work_start < 24 and 0 <= work_end <= 24 and work_start < work_end):  # اعتبارسنجی=بازه کار
        raise HTTPException(status_code=400, detail="invalid work hours")  # خطا=400
    provider = provider_phone.strip()  # provider=تمیز
    if not provider or provider.lower() == "any":  # اعتبارسنجی=شماره سرویس‌دهنده
        raise HTTPException(status_code=400, detail="invalid provider_phone")  # خطا=400
    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)  # day_start=شروع روز
    day_end = datetime(d.year, d.month, d.day, work_end, 0, tzinfo=timezone.utc)  # day_end=پایان روز
    results: List[str] = []  # results=خروجی
    cur = day_start  # cur=نقطه جاری
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:  # حلقه=ساعتی
        s, e = cur, cur + timedelta(hours=1)  # s/e=شروع/پایان اسلات
        if await provider_is_free(provider, s, e):  # بررسی=آزاد
            results.append(s.isoformat())  # افزودن=ایزو
        cur = cur + timedelta(hours=1)  # حرکت=بعدی
    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})  # خروجی

@app.get("/busy_slots")
async def get_busy_slots(provider_phone: str, date: str, exclude_order_id: Optional[int] = None):  # دریافت=اسلات‌های مشغول
    try:
        d = datetime.fromisoformat(date).date()  # پارس=date
    except Exception:
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # خطا=400
    provider = provider_phone.strip()  # provider=تمیز
    if not provider or provider.lower() == "any":  # اعتبارسنجی=شماره سرویس‌دهنده
        raise HTTPException(status_code=400, detail="invalid provider_phone")  # خطا=400
    day_start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)  # day_start=شروع روز
    day_end = day_start + timedelta(days=1)  # day_end=فردا
    sel_sched = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.slot_start >= day_start) & (ScheduleSlotTable.slot_start < day_end) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) & (ScheduleSlotTable.provider_phone == provider))  # انتخاب=اسلات‌ها
    if exclude_order_id is not None:  # فیلتر=استثنا
        sel_sched = sel_sched.where(ScheduleSlotTable.request_id != exclude_order_id)  # شرط
    rows_sched = await database.fetch_all(sel_sched)  # دریافت=اسلات‌ها
    sel_app = AppointmentTable.__table__.select().where((AppointmentTable.start_time >= day_start) & (AppointmentTable.start_time < day_end) & (AppointmentTable.status == "BOOKED") & (AppointmentTable.provider_phone == provider))  # انتخاب=قرارها
    rows_app = await database.fetch_all(sel_app)  # دریافت=قرارها
    busy: set[str] = set()  # busy=مجموعه زمان‌های مشغول
    for r in rows_sched:  # حلقه=پیشنهادی
        busy.add(r["slot_start"].isoformat())  # افزودن=slot_start
    for r in rows_app:  # حلقه=قرارها
        busy.add(r["start_time"].isoformat())  # افزودن=start_time
    items = sorted(busy)  # مرتب‌سازی=صعودی
    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": items})  # خروجی

@app.post("/order/{order_id}/propose_slots")
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):  # پیشنهاد=اسلات‌ها
    require_admin(request)  # احراز=ادمین
    provider = (body.provider_phone or "").strip()  # provider=تمیز
    if not provider or provider.lower() == "any":  # اعتبارسنجی=شماره
        raise HTTPException(status_code=400, detail="invalid provider_phone")  # خطا=400
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == order_id))  # دریافت=سفارش
    if not req:  # بررسی=نبود سفارش
        raise HTTPException(status_code=404, detail="order not found")  # خطا=404
    accepted: List[str] = []  # accepted=لیست پذیرفته‌ها
    for s in body.slots[:3]:  # حلقه=تا ۳ اسلات
        start = parse_iso(s)  # start=پارس زمان
        end = start + timedelta(hours=1)  # end=یک ساعت بعد
        if await provider_is_free(provider, start, end):  # بررسی=آزاد
            await database.execute(ScheduleSlotTable.__table__.insert().values(request_id=order_id, provider_phone=provider, slot_start=start, status="PROPOSED", created_at=datetime.now(timezone.utc)))  # درج=اسلات
            accepted.append(start.isoformat())  # افزودن=لیست
    if accepted:  # اگر=پیشنهاد شد
        await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="WAITING", driver_phone=provider, scheduled_start=None))  # آپدیت=سفارش
        try:
            await notify_user(req["user_phone"], "زمان‌بندی بازدید", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.", data={"type": "visit_slots", "order_id": order_id, "slots": accepted})  # درج=اعلان
            await send_push_to_user(req["user_phone"], "زمان‌بندی بازدید", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.", data={"type": "visit_slots", "order_id": str(order_id)})  # پوش=به کاربر
        except Exception as e:
            logger.error(f"push to user failed: {e}")  # لاگ=خطا
    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # خروجی

@app.get("/order/{order_id}/proposed_slots")
async def get_proposed_slots(order_id: int):  # دریافت=اسلات‌های پیشنهادی
    sel = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")).order_by(ScheduleSlotTable.slot_start.asc())  # انتخاب/مرتب‌سازی
    rows = await database.fetch_all(sel)  # دریافت
    items = [r["slot_start"].isoformat() for r in rows]  # تبدیل=رشته‌های ISO
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})  # خروجی

@app.post("/order/{order_id}/confirm_slot")
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):  # تأیید=اسلات انتخابی
    chosen_start = parse_iso(body.slot)  # chosen_start=زمان انتخابی به UTC
    logger.info(f"confirm_slot begin order_id={order_id} raw='{body.slot}' chosen_utc={chosen_start.isoformat()}")  # لاگ=شروع تایید

    # تطبیق زمان به دقت «ثانیه» با date_trunc برای حذف اختلافات ریز قالب/آفست  # توضیح=پایدارسازی تطبیق
    sel_slot = ScheduleSlotTable.__table__.select().where(  # sel_slot=کوئری انتخاب اسلات
        (ScheduleSlotTable.request_id == order_id) &  # شرط=شناسه سفارش
        (ScheduleSlotTable.status == "PROPOSED") &  # شرط=در وضعیت پیشنهادی
        (func.date_trunc('second', ScheduleSlotTable.slot_start) == func.date_trunc('second', chosen_start))  # شرط=برابر تا ثانیه
    )
    slot = await database.fetch_one(sel_slot)  # slot=دریافت اسلات

    if not slot:  # اگر=یافت نشد
        logger.info(f"confirm_slot not_found order_id={order_id} chosen_utc={chosen_start.isoformat()}")  # لاگ=عدم یافتن
        raise HTTPException(status_code=404, detail="slot not found or not proposed")  # خطا=404

    provider_phone = slot["provider_phone"]  # provider_phone=شماره سرویس‌دهنده
    start = slot["slot_start"]  # start=زمان شروع
    end = start + timedelta(hours=1)  # end=یک ساعت بعد

    if not await provider_is_free(provider_phone, start, end):  # بررسی=آزاد بودن
        await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="REJECTED"))  # رد=اسلات پر شده
        raise HTTPException(status_code=409, detail="slot no longer available")  # خطا=409

    await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="ACCEPTED"))  # آپدیت=پذیرفته شد
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED") & (ScheduleSlotTable.id != slot["id"])).values(status="REJECTED"))  # رد=سایر پیشنهادها
    await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)))  # درج=قرار
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(scheduled_start=start, status="ASSIGNED", driver_phone=provider_phone))  # آپدیت=سفارش

    logger.info(f"confirm_slot ok order_id={order_id} provider={provider_phone} start={start.isoformat()} end={end.isoformat()}")  # لاگ=موفقیت
    try:
        await send_push_to_managers("تأیید زمان بازدید", "کاربر زمان بازدید را تأیید کرد.", {"type": "time_confirm", "order_id": str(order_id)})  # پوش=به مدیران
    except Exception as e:
        logger.error(f"push to managers failed: {e}")  # لاگ=خطای پوش
    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})  # خروجی=موفق

@app.post("/order/{order_id}/reject_all_and_cancel")
async def reject_all_and_cancel(order_id: int):  # رد=همه و لغو سفارش
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")).values(status="REJECTED"))  # رد=پیشنهادها
    upd = RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="CANCELED", scheduled_start=None).returning(RequestTable.id)  # آپدیت=لغو
    await database.fetch_all(upd)  # اجرا
    try:
        await send_push_to_managers("لغو درخواست", "کاربر سفارش را لغو کرد.", {"type": "order_canceled", "order_id": str(order_id)})  # پوش=به مدیر
    except Exception as e:
        logger.error(f"push to managers failed: {e}")  # لاگ=خطا
    return unified_response("ok", "ORDER_CANCELED", "order canceled after rejecting proposals", {"id": order_id})  # خروجی

# -------------------- Admin/Workflow --------------------
@app.get("/admin/requests/active")
async def admin_active_requests(request: Request):  # لیست=درخواست‌های فعال
    require_admin(request)  # احراز=ادمین
    active = ["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]  # active=وضعیت‌های فعال
    sel = RequestTable.__table__.select().where(RequestTable.status.in_(active)).order_by(RequestTable.id.desc())  # انتخاب/مرتب‌سازی
    rows = await database.fetch_all(sel)  # دریافت
    items = [dict(r) for r in rows]  # تبدیل=dict
    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": items})  # خروجی

@app.post("/admin/order/{order_id}/price")
async def admin_set_price_and_status(order_id: int, body: PriceBody, request: Request):  # تعیین=قیمت/وضعیت
    require_admin(request)  # احراز=ادمین
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # انتخاب=سفارش
    req = await database.fetch_one(sel)  # دریافت=سفارش
    if not req:  # بررسی=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=404

    new_status = "IN_PROGRESS" if body.agree else "CANCELED"  # new_status=وضعیت جدید
    values = {"price": body.price, "status": new_status}  # values=مقادیر پایه

    exec_iso = (body.exec_time or "").strip()  # exec_iso=زمان اجرا (رشته)
    if body.agree and exec_iso:  # مسیر=با زمان اجرا
        start = parse_iso(exec_iso)  # start=پارس زمان
        end = start + timedelta(hours=1)  # end=یک ساعت
        provider_phone = (req["driver_phone"] or "").strip()  # provider_phone=راننده
        if not provider_phone:  # بررسی=نبود راننده
            raise HTTPException(status_code=400, detail="driver_phone required for execution")  # خطا=400
        free = await provider_is_free(provider_phone, start, end)  # free=آزاد بودن
        if not free:  # بررسی=اشغال
            raise HTTPException(status_code=409, detail="execution slot busy")  # خطا=409
        await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)))  # درج=قرار
        values["execution_start"] = start  # مقداردهی=execution_start
        try:
            await notify_user(req["user_phone"], "تعیین قیمت و زمان اجرا", "قیمت و زمان اجرای کار تعیین شد.", data={"type": "execution_time", "order_id": order_id, "start": start.isoformat(), "price": body.price})  # درج=اعلان
            await send_push_to_user(req["user_phone"], "تعیین قیمت و زمان اجرا", "قیمت و زمان اجرای کار تعیین شد.", data={"type": "execution_time", "order_id": str(order_id)})  # پوش=به کاربر
        except Exception as e:
            logger.error(f"push to user failed: {e}")  # لاگ=خطا
    elif body.agree:  # مسیر=فقط قیمت
        try:
            await notify_user(req["user_phone"], "تعیین قیمت", "قیمت سرویس تعیین شد.", data={"type": "price_set", "order_id": order_id, "price": body.price})  # اعلان=قیمت
            await send_push_to_user(req["user_phone"], "تعیین قیمت", "قیمت سرویس تعیین شد.", data={"type": "price_set", "order_id": str(order_id)})  # پوش=به کاربر
        except Exception as e:
            logger.error(f"push to user failed: {e}")  # لاگ=خطا

    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(**values))  # آپدیت=سفارش
    resp = {"order_id": order_id, "price": body.price, "status": new_status, "execution_start": values.get("execution_start").isoformat() if values.get("execution_start") else None}  # resp=خروجی
    return unified_response("ok", "PRICE_SET", "price and status updated", resp)  # خروجی

@app.post("/order/{order_id}/start")
async def start_order(order_id: int, request: Request):  # شروع=سفارش
    require_admin(request)  # احراز=ادمین
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # انتخاب=سفارش
    req = await database.fetch_one(sel)  # دریافت=سفارش
    if not req:  # بررسی=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=404
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="STARTED"))  # آپدیت=STARTED
    return unified_response("ok", "ORDER_STARTED", "order started", {"order_id": order_id, "status": "STARTED"})  # خروجی

@app.post("/order/{order_id}/finish")
async def finish_order(order_id: int, request: Request):  # پایان=سفارش
    require_admin(request)  # احراز=ادمین
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # انتخاب=سفارش
    req = await database.fetch_one(sel)  # دریافت=سفارش
    if not req:  # بررسی=نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا=404
    now_iso = datetime.now(timezone.utc).isoformat()  # now_iso=اکنون ISO
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="FINISH", finish_datetime=now_iso))  # آپدیت=FINISH
    try:
        await notify_user(req["user_phone"], "اتمام کار", "کار با موفقیت به پایان رسید.", data={"type": "work_finished", "order_id": order_id})  # اعلان=اتمام
        await send_push_to_user(req["user_phone"], "اتمام کار", "کار با موفقیت به پایان رسید.", data={"type": "work_finished", "order_id": str(order_id)})  # پوش=به کاربر
    except Exception as e:
        logger.error(f"push to user failed: {e}")  # لاگ=خطا
    return unified_response("ok", "ORDER_FINISHED", "order finished", {"order_id": order_id, "status": "FINISH"})  # خروجی

# -------------------- Profile --------------------
@app.post("/user/profile")
async def update_profile(body: UserProfileUpdate, request: Request):  # ذخیره=پروفایل
    if not body.phone.strip():  # اعتبارسنجی=شماره
        raise HTTPException(status_code=400, detail="phone_required")  # خطا=400
    auth_phone = get_auth_phone(request, fallback_phone=body.phone, enforce=False)  # احراز=شماره
    if auth_phone != body.phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # انتخاب=کاربر
    user = await database.fetch_one(sel)  # دریافت=کاربر
    if user is None:  # بررسی=نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=404
    await database.execute(UserTable.__table__.update().where(UserTable.phone == body.phone).values(name=body.name.strip(), address=body.address.strip()))  # آپدیت=نام/آدرس
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # خروجی

@app.get("/user/profile/{phone}")
async def get_user_profile(phone: str, request: Request):  # دریافت=پروفایل
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)  # احراز=شماره
    if auth_phone != phone:  # بررسی=اجازه
        raise HTTPException(status_code=403, detail="forbidden")  # خطا=403
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # انتخاب=کاربر
    db_user = await database.fetch_one(sel)  # دریافت=کاربر
    if db_user is None:  # بررسی=نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا=404
    mapping = getattr(db_user, "_mapping", {})  # mapping=نگاشت امن
    name_val = mapping["name"] if "name" in mapping else ""  # name_val=نام
    address_val = mapping["address"] if "address" in mapping else ""  # address_val=آدرس
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {"phone": db_user["phone"], "name": name_val or "", "address": address_val or ""})  # خروجی

@app.get("/debug/users")
async def debug_users():  # دیباگ=کاربران
    rows = await database.fetch_all(UserTable.__table__.select())  # دریافت=همه کاربران
    out = []  # out=لیست خروجی
    for r in rows:  # حلقه=هر کاربر
        mapping = getattr(r, "_mapping", {})  # mapping=نگاشت امن
        name_val = mapping["name"] if "name" in mapping else ""  # name_val=نام
        address_val = mapping["address"] if "address" in mapping else ""  # address_val=آدرس
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})  # افزودن=آیتم
    return out  # بازگشت
