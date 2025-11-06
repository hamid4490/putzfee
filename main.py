# FILE: server/main.py  # FastAPI server with JWT + FCM HTTP v1 push  # فایل=سرور کامل (تأیید زمان پایدار با بازه ۱ ثانیه‌ای؛ رفع باگ logout و trim→strip)

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
    AUTH_COMPAT == "1" and fallback_phone  # سازگاری
    if AUTH_COMPAT == "1" and fallback_phone:
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
    issued = int(now)  # زمان صدور
    expires = issued + 3600  # انقضا
    payload = {"iss": client_email, "scope": "https://www.googleapis.com/auth/firebase.messaging", "aud": "https://oauth2.googleapis.com/token", "iat": issued, "exp": expires}  # بدنه JWT
    try:
        assertion = jwt.encode(payload, private_key, algorithm="RS256")  # امضاء JWT
    except Exception as e:
        logger.error(f"build assertion failed: {e}")  # خطا
        return None  # خروج
    try:
        resp = httpx.post("https://oauth2.googleapis.com/token", data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}, timeout=10.0)  # درخواست توکن
        if resp.status_code != 200:
            logger.error(f"oauth token http {resp.status_code} {resp.text}")  # خطا HTTP
            return None
        data = resp.json()  # JSON
        token = data.get("access_token", "")  # توکن
        expires_in = int(data.get("expires_in", 3600))  # انقضا
        if token:
            _FCM_OAUTH_TOKEN = token  # کش
            _FCM_OAUTH_EXP = now + expires_in  # انقضا
            logger.info("fcm v1 access_token acquired")  # لاگ
            return token  # بازگشت
        logger.error("oauth token missing access_token")  # خطا
    except Exception as e:
        logger.error(f"oauth token request failed: {e}")  # خطای شبکه
    return None  # خروج

async def get_manager_tokens() -> List[str]:  # توکن‌های مدیر
    sel = DeviceTokenTable.__table__.select().where((DeviceTokenTable.role == "manager") & (DeviceTokenTable.platform == "android"))  # انتخاب
    rows = await database.fetch_all(sel)  # دریافت
    tokens, seen = [], set()  # لیست/مجموعه برای حذف تکراری
    for r in rows:
        t = r["token"]
        if t and t not in seen:
            seen.add(t); tokens.append(t)
    return tokens

async def get_user_tokens(phone: str) -> List[str]:  # توکن‌های کاربر
    sel = DeviceTokenTable.__table__.select().where((DeviceTokenTable.role == "client") & (DeviceTokenTable.user_phone == phone))  # انتخاب
    rows = await database.fetch_all(sel)  # دریافت
    tokens, seen = [], set()  # ساختارها برای یکتا
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
            payload = {"to": t, "priority": "high", "notification": {"title": title, "body": body, "android_channel_id": channel_id}, "data": data or {}}
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
        logger.info("v1 skipped (no tokens or no project id)")
        return
    access_token = _get_oauth2_token_for_fcm()  # توکن OAuth2
    if not access_token:
        logger.error("v1 access_token not available")
        return
    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"  # URL با project_id صحیح
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json; charset=utf-8"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        for t in tokens:
            message = {"message": {"token": t, "notification": {"title": title, "body": body}, "android": {"priority": "HIGH", "notification": {"channel_id": channel_id}}, "data": {k: str(v) for (k, v) in (data or {}).items()}}}
            try:
                resp = await client.post(url, headers=headers, json=message)
                if resp.status_code == 200:
                    logger.info(f"v1 send 200 token_tail={t[-8:]}")
                    continue
                text = resp.text
                err_code = ""
                try:
                    j = resp.json()
                    details = (((j or {}).get("error") or {}).get("details") or [])
                    if isinstance(details, list) and len(details) > 0:
                        err_code = (details[0] or {}).get("errorCode") or ""
                except Exception:
                    m = re.search(r'"errorCode"\s*:\s*"([A-Z_]+)"', text or "")
                    if m:
                        err_code = m.group(1)
                logger.info(f"v1 send {resp.status_code} token_tail={t[-8:]} err_code={err_code} resp={text[:300]}")
                if err_code == "UNREGISTERED" or resp.status_code == 404:
                    await remove_device_token(t)
                    if FCM_SERVER_KEY:
                        await _send_fcm_legacy([t], title, body, data, channel_id)
                if err_code == "SENDER_ID_MISMATCH":
                    logger.error(f"SENDER_ID_MISMATCH: check google-services.json/app project and service account project_id={project_id}")
            except Exception as e:
                logger.error(f"v1 send failed: {e}")

async def _send_ntfy(topics: List[str], title: str, body: str, data: Optional[dict]):
    if not topics:
        return
    base = NTFY_BASE_URL.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0) as client:
        for topic in topics:
            url = f"{base}/{topic}"
            headers = {"Title": title, "Priority": "5"}
            if NTFY_AUTH:
                headers["Authorization"] = NTFY_AUTH
            try:
                resp = await client.post(url, headers=headers, content=(body or ""))
                logger.info(f"ntfy send {resp.status_code} topic={topic}")
            except Exception as e:
                logger.error(f"ntfy send failed: {e}")

async def send_push_to_tokens(tokens: List[str], title: str, body: str, data: Optional[dict] = None, channel_id: str = "order_status_channel"):
    if PUSH_BACKEND == "ntfy":
        await _send_ntfy(tokens, title, body, data); return
    if (FCM_PROJECT_ID or _load_service_account()) and _get_oauth2_token_for_fcm():
        await _send_fcm_v1(tokens, title, body, data, channel_id); return
    await _send_fcm_legacy(tokens, title, body, data, channel_id)

async def send_push_to_managers(title: str, body: str, data: Optional[dict] = None):
    tokens = await get_manager_tokens()
    logger.info(f"send_to_managers count={len(tokens)} title={title}")
    await send_push_to_tokens(tokens, title, body, data, channel_id="putz_manager_general")

async def send_push_to_user(phone: str, title: str, body: str, data: Optional[dict] = None):
    tokens = await get_user_tokens(phone)
    logger.info(f"send_to_user phone={phone} tokens={len(tokens)} title={title}")
    await send_push_to_tokens(tokens, title, body, data, channel_id="order_status_channel")

# -------------------- App & CORS --------------------
app = FastAPI()  # اپ FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # تنظیم CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Startup/Shutdown --------------------
@app.on_event("startup")
async def startup():  # شروع برنامه
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # Engine sync برای create_all
    Base.metadata.create_all(engine)  # ساخت جداول
    with engine.begin() as conn:  # تغییر ستون‌های جدید (در صورت نبود)
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place TEXT DEFAULT 'client';"))
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS execution_start TIMESTAMPTZ NULL;"))
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
    token = extract_bearer_token(request)
    if not token:
        return {"status": "ok", "valid": False}
    payload = decode_access_token(token)
    return {"status": "ok", "valid": bool(payload and payload.get("sub"))}

@app.post("/logout")
async def logout_user(body: LogoutRequest):  # خروج کاربر (حذف توکن دستگاه + ابطال رفرش)
    if not body.refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token required")
    token_hash = hash_refresh_token(body.refresh_token)  # هش رفرش

    sel_rt = RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash)  # انتخاب
    rt_row = await database.fetch_one(sel_rt)  # دریافت

    upd = RefreshTokenTable.__table__.update().where(
        RefreshTokenTable.token_hash == token_hash
    ).values(revoked=True)
    await database.execute(upd)

    if body.device_token and body.device_token.strip():
        delq = DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == body.device_token.strip())
        await database.execute(delq)
    else:
        user_id_val = None
        if rt_row:
            mapping = getattr(rt_row, "_mapping", {})
            user_id_val = mapping["user_id"] if "user_id" in mapping else None
            if user_id_val is None:
                try:
                    user_id_val = rt_row["user_id"]
                except Exception:
                    user_id_val = None
        if user_id_val is not None:
            sel_user = UserTable.__table__.select().where(UserTable.id == user_id_val)
            user = await database.fetch_one(sel_user)
            if user:
                phone = user["phone"]
                del_all = DeviceTokenTable.__table__.delete().where(DeviceTokenTable.user_phone == phone)
                await database.execute(del_all)

    return unified_response("ok", "LOGOUT", "refresh token revoked and device tokens removed", {})

# -------------------- Push endpoints --------------------
@app.post("/push/register")
async def register_push_token(body: PushRegister, request: Request):  # ثبت توکن پوش
    now = datetime.now(timezone.utc)
    sel = DeviceTokenTable.__table__.select().where(DeviceTokenTable.token == body.token)
    row = await database.fetch_one(sel)
    if row is None:
        ins = DeviceTokenTable.__table__.insert().values(
            token=body.token, role=body.role, platform=body.platform, user_phone=body.user_phone, created_at=now, updated_at=now
        )
        await database.execute(ins)
    else:
        upd = DeviceTokenTable.__table__.update().where(DeviceTokenTable.id == row["id"]).values(
            role=body.role, platform=body.platform, user_phone=body.user_phone or row["user_phone"], updated_at=now
        )
        await database.execute(upd)
    logger.info(f"push/register role={body.role} platform={body.platform} phone={body.user_phone}")
    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": body.role})

@app.post("/push/unregister")
async def unregister_push_token(body: PushUnregister):  # لغو ثبت توکن پوش (قطع نوتیف پس از خروج)
    delq = DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == body.token)
    await database.execute(delq)
    logger.info(f"push/unregister token_tail={body.token[-8:]}")
    return unified_response("ok", "TOKEN_UNREGISTERED", "unregistered", {})

# -------------------- Auth/User --------------------
@app.get("/users/exists")
async def user_exists(phone: str):
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)
    count = await database.fetch_val(q)
    exists = bool(count and int(count) > 0)
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})

@app.post("/register_user")
async def register_user(user: UserRegisterRequest):
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)
    count = await database.fetch_val(q)
    if count and int(count) > 0:
        raise HTTPException(status_code=400, detail="User already exists")
    password_hash = bcrypt_hash_password(user.password)
    ins = UserTable.__table__.insert().values(
        phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[]
    )
    await database.execute(ins)
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})

@app.post("/login")
async def login_user(user: UserLoginRequest, request: Request):
    now = datetime.now(timezone.utc)
    client_ip = get_client_ip(request)

    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))
    attempt_row = await database.fetch_one(sel_attempt)

    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after}, headers={"Retry-After": str(retry_after)})

    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)
    db_user = await database.fetch_one(sel_user)
    if not db_user:
        await _register_login_failure(user.phone, client_ip)
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})
    if not verify_password_secure(user.password, db_user["password_hash"]):
        await _register_login_failure(user.phone, client_ip)
        updated = await database.fetch_one(sel_attempt)
        attempts = int(updated["attempt_count"]) if updated and updated["attempt_count"] is not None else 1
        remaining = max(0, LOGIN_MAX_ATTEMPTS - attempts)
        headers = {"X-Remaining-Attempts": str(remaining)}
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": remaining}, headers=headers)

    await _register_login_success(user.phone, client_ip)

    if not db_user["password_hash"].startswith("$2"):
        new_hash = bcrypt_hash_password(user.password)
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)
        await database.execute(upd)

    access_token = create_access_token(db_user["phone"])
    refresh_token = create_refresh_token()
    refresh_hash = hash_refresh_token(refresh_token)
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    ins_rt = RefreshTokenTable.__table__.insert().values(user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False)
    await database.execute(ins_rt)

    mapping = getattr(db_user, "_mapping", {})
    name_val = mapping["name"] if "name" in mapping else ""
    address_val = mapping["address"] if "address" in mapping else ""

    return {"status": "ok", "access_token": access_token, "refresh_token": refresh_token, "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}}

async def _register_login_failure(phone: str, ip: str):
    now = datetime.now(timezone.utc)
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))
    row = await database.fetch_one(sel)
    if row is None:
        ins = LoginAttemptTable.__table__.insert().values(phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now)
        await database.execute(ins); return
    window_start = row["window_start"] or now
    within = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS
    new_count = (row["attempt_count"] + 1) if within else 1
    new_window_start = window_start if within else now
    locked_until = row["locked_until"]
    if new_count >= LOGIN_MAX_ATTEMPTS:
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now)
    await database.execute(upd)

async def _register_login_success(phone: str, ip: str):
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))
    row = await database.fetch_one(sel)
    if row:
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None)
        await database.execute(upd)

@app.post("/auth/refresh")
async def refresh_access_token(req: Dict):
    refresh_token = req.get("refresh_token", "")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token required")
    token_hash = hash_refresh_token(refresh_token)
    now = datetime.now(timezone.utc)
    sel = RefreshTokenTable.__table__.select().where((RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now))
    rt = await database.fetch_one(sel)
    if not rt:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])
    db_user = await database.fetch_one(sel_user)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    new_access = create_access_token(db_user["phone"])
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})

# -------------------- Notifications --------------------
@app.get("/user/{phone}/notifications")
async def get_notifications(phone: str, request: Request, only_unread: bool = True, limit: int = 50, offset: int = 0):
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)
    if auth_phone != phone:
        raise HTTPException(status_code=403, detail="forbidden")
    base_sel = NotificationTable.__table__.select().where(NotificationTable.user_phone == phone)
    if only_unread:
        base_sel = base_sel.where(NotificationTable.read == False)
    base_sel = base_sel.order_by(NotificationTable.created_at.desc()).limit(limit).offset(offset)
    rows = await database.fetch_all(base_sel)
    items = [dict(r) for r in rows]
    return unified_response("ok", "NOTIFICATIONS", "user notifications", {"items": items})

@app.post("/user/{phone}/notifications/{notif_id}/read")
async def mark_notification_read(phone: str, notif_id: int, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)
    if auth_phone != phone:
        raise HTTPException(status_code=403, detail="forbidden")
    now = datetime.now(timezone.utc)
    upd = NotificationTable.__table__.update().where((NotificationTable.id == notif_id) & (NotificationTable.user_phone == phone)).values(read=True, read_at=now)
    await database.execute(upd)
    return unified_response("ok", "NOTIF_READ", "notification marked as read", {"id": notif_id})

@app.post("/user/{phone}/notifications/mark_all_read")
async def mark_all_notifications_read(phone: str, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)
    if auth_phone != phone:
        raise HTTPException(status_code=403, detail="forbidden")
    now = datetime.now(timezone.utc)
    upd = NotificationTable.__table__.update().where((NotificationTable.user_phone == phone) & (NotificationTable.read == False)).values(read=True, read_at=now)
    await database.execute(upd)
    return unified_response("ok", "NOTIFS_READ_ALL", "all notifications marked as read", {})

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)
    if auth_phone != user_phone:
        raise HTTPException(status_code=403, detail="forbidden")
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)
    user = await database.fetch_one(query)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    items = user["car_list"] or []
    return unified_response("ok", "USER_CARS", "user cars", {"items": items})

@app.post("/user_cars")
async def update_user_cars(data: CarListUpdateRequest, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=data.user_phone, enforce=False)
    if auth_phone != data.user_phone:
        raise HTTPException(status_code=403, detail="forbidden")
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)
    user = await database.fetch_one(sel)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(car_list=[car.dict() for car in data.car_list])
    await database.execute(upd)
    return unified_response("ok", "CARS_SAVED", "cars saved", {"count": len(data.car_list)})

# -------------------- Orders --------------------
@app.post("/order")
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
    new_id = row[0] if isinstance(row, (tuple, list)) else (row["id"] if row else None)
    try:
        await send_push_to_managers("درخواست جدید", "درخواست جدید ثبت شد.", {"type": "new_request", "order_id": str(new_id)})
    except Exception as e:
        logger.error(f"push to managers failed: {e}")
    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})

@app.post("/cancel_order")
async def cancel_order(cancel: CancelRequest, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=cancel.user_phone, enforce=False)
    if auth_phone != cancel.user_phone:
        raise HTTPException(status_code=403, detail="forbidden")
    upd = (RequestTable.__table__.update().where(
        (RequestTable.user_phone == cancel.user_phone) &
        (RequestTable.service_type == cancel.service_type) &
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))
    ).values(status="CANCELED", scheduled_start=None).returning(RequestTable.id))
    rows = await database.fetch_all(upd)
    if rows and len(rows) > 0:
        try:
            for r in rows:
                mapping = getattr(r, "_mapping", None)
                oid = mapping["id"] if (mapping and "id" in mapping) else (r[0] if isinstance(r, (tuple, list)) and len(r) > 0 else None)
                await send_push_to_managers("لغو درخواست", "کاربر سفارش را لغو کرد.", {"type": "order_canceled", "order_id": str(oid) if oid is not None else ""})
        except Exception as e:
            logger.error(f"push to managers failed: {e}")
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})
    raise HTTPException(status_code=404, detail="active order not found")

@app.get("/user_active_services/{user_phone}")
async def get_user_active_services(user_phone: str, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)
    if auth_phone != user_phone:
        raise HTTPException(status_code=403, detail="forbidden")
    sel = RequestTable.__table__.select().where((RequestTable.user_phone == user_phone) & (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"])))
    result = await database.fetch_all(sel)
    items = [dict(r) for r in result]
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})

@app.get("/user_orders/{user_phone}")
async def get_user_orders(user_phone: str, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=user_phone, enforce=False)
    if auth_phone != user_phone:
        raise HTTPException(status_code=403, detail="forbidden")
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)
    result = await database.fetch_all(sel)
    items = [dict(r) for r in result]
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})

# -------------------- Scheduling --------------------
@app.get("/provider/{provider_phone}/free_hours")
async def get_free_hours(provider_phone: str, date: str, work_start: int = 8, work_end: int = 20, limit: int = 24):
    try:
        d = datetime.fromisoformat(date).date()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")
    if not (0 <= work_start < 24 and 0 <= work_end <= 24 and work_start < work_end):
        raise HTTPException(status_code=400, detail="invalid work hours")
    provider = provider_phone.strip()
    if not provider or provider.lower() == "any":
        raise HTTPException(status_code=400, detail="invalid provider_phone")
    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)
    day_end = datetime(d.year, d.month, d.day, work_end, 0, tzinfo=timezone.utc)
    results: List[str] = []
    cur = day_start
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:
        s, e = cur, cur + timedelta(hours=1)
        if await provider_is_free(provider, s, e):
            results.append(s.isoformat())
        cur = cur + timedelta(hours=1)
    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})

@app.get("/busy_slots")
async def get_busy_slots(provider_phone: str, date: str, exclude_order_id: Optional[int] = None):
    try:
        d = datetime.fromisoformat(date).date()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")
    provider = provider_phone.strip()
    if not provider or provider.lower() == "any":
        raise HTTPException(status_code=400, detail="invalid provider_phone")
    day_start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)
    day_end = day_start + timedelta(days=1)
    sel_sched = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.slot_start >= day_start) & (ScheduleSlotTable.slot_start < day_end) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) & (ScheduleSlotTable.provider_phone == provider))
    if exclude_order_id is not None:
        sel_sched = sel_sched.where(ScheduleSlotTable.request_id != exclude_order_id)
    rows_sched = await database.fetch_all(sel_sched)
    sel_app = AppointmentTable.__table__.select().where((AppointmentTable.start_time >= day_start) & (AppointmentTable.start_time < day_end) & (AppointmentTable.status == "BOOKED") & (AppointmentTable.provider_phone == provider))
    rows_app = await database.fetch_all(sel_app)
    busy: set[str] = set()
    for r in rows_sched:
        busy.add(r["slot_start"].isoformat())
    for r in rows_app:
        busy.add(r["start_time"].isoformat())
    items = sorted(busy)
    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": items})

@app.post("/order/{order_id}/propose_slots")
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):
    require_admin(request)
    provider = (body.provider_phone or "").strip()
    if not provider or provider.lower() == "any":
        raise HTTPException(status_code=400, detail="invalid provider_phone")
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == order_id))
    if not req:
        raise HTTPException(status_code=404, detail="order not found")
    accepted: List[str] = []
    for s in body.slots[:3]:
        start = parse_iso(s)
        end = start + timedelta(hours=1)
        if await provider_is_free(provider, start, end):
            await database.execute(ScheduleSlotTable.__table__.insert().values(request_id=order_id, provider_phone=provider, slot_start=start, status="PROPOSED", created_at=datetime.now(timezone.utc)))
            accepted.append(start.isoformat())
    if accepted:
        await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="WAITING", driver_phone=provider, scheduled_start=None))
        try:
            await notify_user(req["user_phone"], "زمان‌بندی بازدید", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.", data={"type": "visit_slots", "order_id": order_id, "slots": accepted})
            await send_push_to_user(req["user_phone"], "زمان‌بندی بازدید", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.", data={"type": "visit_slots", "order_id": str(order_id)})
        except Exception as e:
            logger.error(f"push to user failed: {e}")
    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})

@app.get("/order/{order_id}/proposed_slots")
async def get_proposed_slots(order_id: int):
    sel = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")).order_by(ScheduleSlotTable.slot_start.asc())
    rows = await database.fetch_all(sel)
    items = [r["slot_start"].isoformat() for r in rows]
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})

@app.post("/order/{order_id}/confirm_slot")
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):
    chosen_start = parse_iso(body.slot)  # زمان انتخابی به UTC (aware)
    logger.info(f"confirm_slot begin order_id={order_id} raw='{body.slot}' chosen_utc={chosen_start.isoformat()}")  # لاگ شروع

    chosen_floor = chosen_start.replace(microsecond=0)  # کف ثانیه (حذف میکروثانیه)
    next_sec = chosen_floor + timedelta(seconds=1)  # مرز بالایی بازه ۱ ثانیه

    sel_slot = ScheduleSlotTable.__table__.select().where(  # انتخاب اسلات در بازه [کف، کف+۱s)
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.status == "PROPOSED") &
        (ScheduleSlotTable.slot_start >= chosen_floor) &
        (ScheduleSlotTable.slot_start < next_sec)
    )
    slot = await database.fetch_one(sel_slot)  # دریافت اسلات تطبیق‌داده‌شده

    if not slot:
        logger.info(f"confirm_slot not_found order_id={order_id} chosen_floor={chosen_floor.isoformat()} next_sec={next_sec.isoformat()}")  # لاگ عدم تطبیق
        raise HTTPException(status_code=404, detail="slot not found or not proposed")  # خطا: عدم وجود اسلات

    provider_phone = slot["provider_phone"]  # سرویس‌دهنده
    start = slot["slot_start"]  # زمان شروع واقعی ذخیره‌شده
    end = start + timedelta(hours=1)  # پایان یک‌ساعت بعد

    free = await provider_is_free(provider_phone, start, end)  # بررسی آزاد بودن
    if not free:
        await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="REJECTED"))  # رد اسلات پرشده
        raise HTTPException(status_code=409, detail="slot no longer available")  # تعارض

    await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="ACCEPTED"))  # پذیرش
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED") & (ScheduleSlotTable.id != slot["id"])).values(status="REJECTED"))  # رد سایر پیشنهادها
    await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)))  # درج قرار
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(scheduled_start=start, status="ASSIGNED", driver_phone=provider_phone))  # آپدیت سفارش
    logger.info(f"confirm_slot ok order_id={order_id} provider={provider_phone} start={start.isoformat()} end={end.isoformat()}")  # لاگ موفقیت

    try:
        await send_push_to_managers("تأیید زمان بازدید", "کاربر زمان بازدید را تأیید کرد.", {"type": "time_confirm", "order_id": str(order_id)})
    except Exception as e:
        logger.error(f"push to managers failed: {e}")
    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})

@app.post("/order/{order_id}/reject_all_and_cancel")
async def reject_all_and_cancel(order_id: int):
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")).values(status="REJECTED"))
    upd = RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="CANCELED", scheduled_start=None).returning(RequestTable.id)
    await database.fetch_all(upd)
    try:
        await send_push_to_managers("لغو درخواست", "کاربر سفارش را لغو کرد.", {"type": "order_canceled", "order_id": str(order_id)})
    except Exception as e:
        logger.error(f"push to managers failed: {e}")
    return unified_response("ok", "ORDER_CANCELED", "order canceled after rejecting proposals", {"id": order_id})

# -------------------- Admin/Workflow --------------------
@app.get("/admin/requests/active")
async def admin_active_requests(request: Request):
    require_admin(request)
    active = ["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]
    sel = RequestTable.__table__.select().where(RequestTable.status.in_(active)).order_by(RequestTable.id.desc())
    rows = await database.fetch_all(sel)
    items = [dict(r) for r in rows]
    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": items})

@app.post("/admin/order/{order_id}/price")
async def admin_set_price_and_status(order_id: int, body: PriceBody, request: Request):
    require_admin(request)
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)
    req = await database.fetch_one(sel)
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    new_status = "IN_PROGRESS" if body.agree else "CANCELED"
    values = {"price": body.price, "status": new_status}

    exec_iso = (body.exec_time or "").strip()
    if body.agree and exec_iso:
        start = parse_iso(exec_iso)
        end = start + timedelta(hours=1)
        provider_phone = (req["driver_phone"] or "").strip()
        if not provider_phone:
            raise HTTPException(status_code=400, detail="driver_phone required for execution")
        free = await provider_is_free(provider_phone, start, end)
        if not free:
            raise HTTPException(status_code=409, detail="execution slot busy")
        await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)))
        values["execution_start"] = start
        try:
            await notify_user(req["user_phone"], "تعیین قیمت و زمان اجرا", "قیمت و زمان اجرای کار تعیین شد.", data={"type": "execution_time", "order_id": order_id, "start": start.isoformat(), "price": body.price})
            await send_push_to_user(req["user_phone"], "تعیین قیمت و زمان اجرا", "قیمت و زمان اجرای کار تعیین شد.", data={"type": "execution_time", "order_id": str(order_id)})
        except Exception as e:
            logger.error(f"push to user failed: {e}")
    elif body.agree:
        try:
            await notify_user(req["user_phone"], "تعیین قیمت", "قیمت سرویس تعیین شد.", data={"type": "price_set", "order_id": order_id, "price": body.price})
            await send_push_to_user(req["user_phone"], "تعیین قیمت", "قیمت سرویس تعیین شد.", data={"type": "price_set", "order_id": str(order_id)})
        except Exception as e:
            logger.error(f"push to user failed: {e}")

    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(**values))
    resp = {"order_id": order_id, "price": body.price, "status": new_status, "execution_start": values.get("execution_start").isoformat() if values.get("execution_start") else None}
    return unified_response("ok", "PRICE_SET", "price and status updated", resp)

@app.post("/order/{order_id}/start")
async def start_order(order_id: int, request: Request):
    require_admin(request)
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)
    req = await database.fetch_one(sel)
    if not req:
        raise HTTPException(status_code=404, detail="order not found")
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="STARTED"))
    return unified_response("ok", "ORDER_STARTED", "order started", {"order_id": order_id, "status": "STARTED"})

@app.post("/order/{order_id}/finish")
async def finish_order(order_id: int, request: Request):
    require_admin(request)
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)
    req = await database.fetch_one(sel)
    if not req:
        raise HTTPException(status_code=404, detail="order not found")
    now_iso = datetime.now(timezone.utc).isoformat()
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="FINISH", finish_datetime=now_iso))
    try:
        await notify_user(req["user_phone"], "اتمام کار", "کار با موفقیت به پایان رسید.", data={"type": "work_finished", "order_id": order_id})
        await send_push_to_user(req["user_phone"], "اتمام کار", "کار با موفقیت به پایان رسید.", data={"type": "work_finished", "order_id": str(order_id)})
    except Exception as e:
        logger.error(f"push to user failed: {e}")
    return unified_response("ok", "ORDER_FINISHED", "order finished", {"order_id": order_id, "status": "FINISH"})

# -------------------- Profile --------------------
@app.post("/user/profile")
async def update_profile(body: UserProfileUpdate, request: Request):
    if not body.phone.strip():
        raise HTTPException(status_code=400, detail="phone_required")
    auth_phone = get_auth_phone(request, fallback_phone=body.phone, enforce=False)
    if auth_phone != body.phone:
        raise HTTPException(status_code=403, detail="forbidden")
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)
    user = await database.fetch_one(sel)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    await database.execute(UserTable.__table__.update().where(UserTable.phone == body.phone).values(name=body.name.strip(), address=body.address.strip()))
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})

@app.get("/user/profile/{phone}")
async def get_user_profile(phone: str, request: Request):
    auth_phone = get_auth_phone(request, fallback_phone=phone, enforce=False)
    if auth_phone != phone:
        raise HTTPException(status_code=403, detail="forbidden")
    sel = UserTable.__table__.select().where(UserTable.phone == phone)
    db_user = await database.fetch_one(sel)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    mapping = getattr(db_user, "_mapping", {})
    name_val = mapping["name"] if "name" in mapping else ""
    address_val = mapping["address"] if "address" in mapping else ""
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {"phone": db_user["phone"], "name": name_val or "", "address": address_val or ""})

@app.get("/debug/users")
async def debug_users():
    rows = await database.fetch_all(UserTable.__table__.select())
    out = []
    for r in rows:
        mapping = getattr(r, "_mapping", {})
        name_val = mapping["name"] if "name" in mapping else ""
        address_val = mapping["address"] if "address" in mapping else ""
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})
    return out
