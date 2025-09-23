# -*- coding: utf-8 -*-  # کدینگ فایل=یونیکد
# FastAPI server (orders + hourly scheduling + DB notifications + Push backend switch FCM/NTFY + AdminKey + execution_time + user push)  # توضیح=سرور با پوش مدیر/کاربر و بک‌اند قابل سوئیچ

import os  # ماژول=سیستم
import hashlib  # ماژول=هش
import secrets  # ماژول=توکن تصادفی
from datetime import datetime, timedelta, timezone  # کلاس‌های زمان
from typing import Optional, List, Dict  # نوع‌دهی

import bcrypt  # کتابخانه=bcrypt برای هش امن
import jwt  # کتابخانه=JWT برای توکن دسترسی
from fastapi import FastAPI, HTTPException, Request  # FastAPI=چارچوب | HTTPException=خطا | Request=درخواست
from fastapi.middleware.cors import CORSMiddleware  # CORS=میان‌افزار CORS
from pydantic import BaseModel  # BaseModel=مدل‌های بدنه JSON

from sqlalchemy import (  # SQLAlchemy=ORM/SQL
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_, text, UniqueConstraint  # اجزاء ORM
)
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON در PostgreSQL
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه ORM
import sqlalchemy  # sqlalchemy=پکیج اصلی
from databases import Database  # databases=اتصال async به DB
from dotenv import load_dotenv  # load_dotenv=خواندن متغیرهای محیطی از .env
import httpx  # httpx=کلاینت HTTP Async

# -------------------- Config --------------------
load_dotenv()  # بارگذاری .env → متغیرهای محیطی
DATABASE_URL = os.getenv("DATABASE_URL")  # DATABASE_URL=آدرس اتصال دیتابیس
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # JWT_SECRET=کلید امضای JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # PASSWORD_PEPPER=pepper برای هش رمز
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # ACCESS_TOKEN_EXPIRE_MINUTES=انقضای توکن دسترسی (دقیقه)
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # REFRESH_TOKEN_EXPIRE_DAYS=انقضای توکن رفرش (روز)
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # BCRYPT_ROUNDS=تعداد دورهای bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # ALLOW_ORIGINS=مبداهای مجاز CORS به صورت CSV یا *
FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "")  # FCM_SERVER_KEY=کلید سرور FCM (وقتی PUSH_BACKEND=fcm)
ADMIN_KEY = os.getenv("ADMIN_KEY", "CHANGE_ME_ADMIN")  # ADMIN_KEY=کلید ادمین برای مسیرهای مدیریتی

# —— بک‌اند پوش قابل سوئیچ (بدون وابستگی به گوگل) ——
PUSH_BACKEND = os.getenv("PUSH_BACKEND", "fcm").strip().lower()  # PUSH_BACKEND=انتخاب بک‌اند («fcm» یا «ntfy»)
NTFY_BASE_URL = os.getenv("NTFY_BASE_URL", "https://ntfy.sh").strip()  # NTFY_BASE_URL=آدرس پایه ntfy (پیش‌فرض ntfy.sh)
NTFY_AUTH = os.getenv("NTFY_AUTH", "").strip()  # NTFY_AUTH=هدر Authorization برای ntfy (اختیاری: Bearer/Basic ...)

database = Database(DATABASE_URL)  # database=نمونه اتصال Async به DB
Base = declarative_base()  # Base=کلاس پایه ORM

# -------------------- ORM models --------------------
class UserTable(Base):  # مدل=کاربران
    __tablename__ = "users"  # __tablename__=نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی + ایندکس
    phone = Column(String, unique=True, index=True)  # phone=شماره یکتا + ایندکس
    password_hash = Column(String)  # password_hash=هش رمز
    address = Column(String)  # address=آدرس
    name = Column(String, default="")  # name=نام
    car_list = Column(JSONB, default=list)  # car_list=لیست ماشین‌ها (JSONB)

class DriverTable(Base):  # مدل=سرویس‌گیرنده‌ها
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    first_name = Column(String)  # first_name
    last_name = Column(String)  # last_name
    photo_url = Column(String)  # photo_url
    id_card_number = Column(String)  # id_card_number
    phone = Column(String, unique=True, index=True)  # phone
    phone_verified = Column(Boolean, default=False)  # phone_verified
    is_online = Column(Boolean, default=False)  # is_online
    status = Column(String, default="فعال")  # status

class RequestTable(Base):  # مدل=سفارش‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    user_phone = Column(String, index=True)  # user_phone
    latitude = Column(Float)  # latitude
    longitude = Column(Float)  # longitude
    car_list = Column(JSONB)  # car_list
    address = Column(String)  # address
    home_number = Column(String, default="")  # home_number
    service_type = Column(String, index=True)  # service_type
    price = Column(Integer)  # price
    request_datetime = Column(String)  # request_datetime
    status = Column(String)  # status
    driver_name = Column(String)  # driver_name
    driver_phone = Column(String)  # driver_phone
    finish_datetime = Column(String)  # finish_datetime
    payment_type = Column(String)  # payment_type
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # scheduled_start
    service_place = Column(String, default="client")  # service_place
    execution_start = Column(DateTime(timezone=True), nullable=True)  # execution_start

class RefreshTokenTable(Base):  # مدل=رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع به users
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش‌توکن
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=انقضا
    revoked = Column(Boolean, default=False)  # revoked=باطل؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # __table_args__=ایندکس مرکب

class LoginAttemptTable(Base):  # مدل=تلاش‌های ورود
    __tablename__ = "login_attempts"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    phone = Column(String, index=True)  # phone
    ip = Column(String, index=True)  # ip
    attempt_count = Column(Integer, default=0)  # attempt_count=تعداد تلاش
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # window_start
    locked_until = Column(DateTime(timezone=True), nullable=True)  # locked_until
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # last_attempt_at
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)  # ایندکس مرکب

class ScheduleSlotTable(Base):  # مدل=اسلات‌های پیشنهادی
    __tablename__ = "schedule_slots"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id
    provider_phone = Column(String, index=True)  # provider_phone
    slot_start = Column(DateTime(timezone=True), index=True)  # slot_start
    status = Column(String, default="PROPOSED")  # status
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)  # ایندکس مرکب

class AppointmentTable(Base):  # مدل=نوبت‌های قطعی
    __tablename__ = "appointments"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    provider_phone = Column(String, index=True)  # provider_phone
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id
    start_time = Column(DateTime(timezone=True), index=True)  # start_time
    end_time = Column(DateTime(timezone=True), index=True)  # end_time
    status = Column(String, default="BOOKED")  # status
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),  # UniqueConstraint=جلوگیری از تداخل
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),  # ایندکس مرکب
    )

class NotificationTable(Base):  # مدل=اعلان‌ها
    __tablename__ = "notifications"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    user_phone = Column(String, index=True)  # user_phone
    title = Column(String)  # title
    body = Column(String)  # body
    data = Column(JSONB, default=dict)  # data=داده اضافی (JSONB)
    read = Column(Boolean, default=False, index=True)  # read
    read_at = Column(DateTime(timezone=True), nullable=True)  # read_at
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)  # created_at
    __table_args__ = (Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),)  # ایندکس مرکب

class DeviceTokenTable(Base):  # مدل=توکن‌های/تاپیک‌های پوش
    __tablename__ = "device_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    token = Column(String, unique=True, index=True)  # token=برای FCM=توکن | برای NTFY=نام topic
    role = Column(String, index=True)  # role=client/manager
    platform = Column(String, default="android", index=True)  # platform=android
    user_phone = Column(String, nullable=True)  # user_phone=شماره پذیرنده (اختیاری)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # updated_at
    __table_args__ = (Index("ix_tokens_role_platform", "role", "platform"),)  # ایندکس مرکب

# -------------------- Pydantic models --------------------
class CarInfo(BaseModel):  # مدل=ماشین ساده
    brand: str  # brand
    model: str  # model
    plate: str  # plate

class Location(BaseModel):  # مدل=مختصات
    latitude: float  # latitude
    longitude: float  # longitude

class CarOrderItem(BaseModel):  # مدل=گزینه‌های سفارش
    brand: str  # brand
    model: str  # model
    plate: str  # plate
    wash_outside: bool = False  # wash_outside
    wash_inside: bool = False  # wash_inside
    polish: bool = False  # polish

class OrderRequest(BaseModel):  # مدل=ثبت سفارش
    user_phone: str  # user_phone
    location: Location  # location
    car_list: List[CarOrderItem]  # car_list
    address: str  # address
    home_number: Optional[str] = ""  # home_number
    service_type: str  # service_type
    price: int  # price
    request_datetime: str  # request_datetime
    payment_type: str  # payment_type
    service_place: str  # service_place

class CarListUpdateRequest(BaseModel):  # مدل=آپدیت ماشین‌ها
    user_phone: str  # user_phone
    car_list: List[CarInfo]  # car_list

class CancelRequest(BaseModel):  # مدل=لغو سفارش
    user_phone: str  # user_phone
    service_type: str  # service_type

class UserRegisterRequest(BaseModel):  # مدل=ثبت‌نام
    phone: str  # phone
    password: str  # password
    address: Optional[str] = None  # address

class UserLoginRequest(BaseModel):  # مدل=ورود
    phone: str  # phone
    password: str  # password

class UserProfileUpdate(BaseModel):  # مدل=آپدیت پروفایل
    phone: str  # phone
    name: str = ""  # name
    address: str = ""  # address

class ProposedSlotsRequest(BaseModel):  # مدل=ارسال اسلات‌ها
    provider_phone: str  # provider_phone
    slots: List[str]  # slots (ISO)

class ConfirmSlotRequest(BaseModel):  # مدل=تأیید اسلات
    slot: str  # slot (ISO)

class PriceBody(BaseModel):  # مدل=ثبت قیمت/توافق
    price: int  # price
    agree: bool  # agree
    exec_time: Optional[str] = None  # exec_time (ISO)

class PushRegister(BaseModel):  # مدل=ثبت پوش
    role: str  # role
    token: str  # token یا topic
    platform: str = "android"  # platform
    user_phone: Optional[str] = None  # user_phone

# -------------------- Security helpers --------------------
def bcrypt_hash_password(password: str) -> str:  # تابع=هش bcrypt
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # salt=نمک با تعداد دور تنظیم‌شده
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=ترکیب رمز با pepper
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی=رشته هش

def verify_password_secure(password: str, stored_hash: str) -> bool:  # تابع=اعتبارسنجی رمز
    try:  # try=محافظت از خطا
        if stored_hash.startswith("$2"):  # if=فرمت bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=ترکیب رمز+pepper
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # return=نتیجه بررسی bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # old=هش قدیمی sha256 بدون pepper
        return old == stored_hash  # return=مقایسه هش‌ها
    except Exception:  # خطا=هر استثناء
        return False  # return=false

def create_access_token(phone: str) -> str:  # تابع=ساخت JWT دسترسی
    now = datetime.now(timezone.utc)  # now=اکنون
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # exp=زمان انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload=داده JWT
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # return=توکن امضاشده

def create_refresh_token() -> str:  # تابع=ساخت رفرش‌توکن
    return secrets.token_urlsafe(48)  # return=توکن امن تصادفی

def hash_refresh_token(token: str) -> str:  # تابع=هش رفرش‌توکن
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # return=هش sha256 با pepper

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # تابع=قالب پاسخ واحد
    return {"status": status, "code": code, "message": message, "data": data or {}}  # return=دیکشنری استاندارد

# -------------------- Admin helper --------------------
def require_admin(request: Request):  # تابع=بررسی هدر ادمین
    key = request.headers.get("x-admin-key", "")  # key=خواندن هدر X-Admin-Key
    if not key or key != ADMIN_KEY:  # if=نبود/عدم انطباق
        raise HTTPException(status_code=401, detail="admin auth required")  # raise=401 عدم مجوز

# -------------------- Utils --------------------
def get_client_ip(request: Request) -> str:  # تابع=IP کلاینت
    xff = request.headers.get("x-forwarded-for", "")  # xff=هدر XFF از پراکسی
    if xff:  # if=وجود XFF
        return xff.split(",")[0].strip()  # return=اولین IP در لیست
    return request.client.host or "unknown"  # return=IP مستقیم کلاینت

def parse_iso(ts: str) -> datetime:  # تابع=پارس ISO ساده (UTC)
    try:  # try=محافظ
        raw = ts.strip()  # raw=تمیز کردن رشته
        if "T" not in raw:  # if=فاقد T
            raise ValueError("no T in ISO")  # raise=خطای قالب
        date_part, time_part = raw.split("T", 1)  # جداسازی تاریخ و زمان
        time_part = time_part.replace("Z", "")  # حذف Z انتهایی
        for sign in ["+", "-"]:  # حلقه روی علائم آفست
            idx = time_part.find(sign)  # idx=موقعیت علامت
            if idx > 0:  # if=یافت شد
                time_part = time_part[:idx]  # برش بخش آفست
                break  # خروج حلقه
        if time_part.count(":") == 1:  # if=فقط HH:MM
            time_part = f"{time_part}:00"  # افزودن ثانیه
        y, m, d = map(int, date_part.split("-"))  # پارس تاریخ
        hh, mm, ss = map(int, time_part.split(":"))  # پارس زمان
        dt = datetime(y, m, d, hh, mm, ss, tzinfo=timezone.utc)  # dt=datetime با منطقه UTC
        return dt  # return=خروجی
    except Exception:  # catch=خطا
        raise HTTPException(status_code=400, detail=f"invalid datetime: {ts}")  # raise=400 ورودی نامعتبر

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:  # تابع=آزاد بودن بازه
    q = AppointmentTable.__table__.select().where(  # q=انتخاب رزروهای BOOKED متداخل
        (AppointmentTable.provider_phone == provider_phone) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.end_time > start)
    )  # پایان شرط
    rows = await database.fetch_all(q)  # rows=اجرای کوئری
    return len(rows) == 0  # return=True اگر هیچ تداخلی نبود

async def notify_user(phone: str, title: str, body: str, data: Optional[dict] = None):  # تابع=ثبت اعلان در DB
    ins = NotificationTable.__table__.insert().values(  # ins=عبارت درج
        user_phone=phone, title=title, body=body, data=(data or {}), read=False, created_at=datetime.now(timezone.utc)
    )  # پایان values
    await database.execute(ins)  # اجرا

# -------------------- Push helpers (Pluggable: FCM or NTFY) --------------------
async def get_manager_tokens() -> List[str]:  # تابع=خواندن توکن‌های نقش مدیر
    sel = DeviceTokenTable.__table__.select().where(  # sel=انتخاب از device_tokens
        (DeviceTokenTable.role == "manager") & (DeviceTokenTable.platform == "android")
    )  # شرط نقش/پلتفرم
    rows = await database.fetch_all(sel)  # rows=نتیجه
    tokens, seen = [], set()  # tokens=لیست خروجی | seen=برای حذف تکراری
    for r in rows:  # حلقه روی ردیف‌ها
        t = r["token"]  # t=توکن/تاپیک
        if t and t not in seen:  # اگر غیرخالی و تکراری نبود
            seen.add(t)  # ثبت در مجموعه
            tokens.append(t)  # افزودن به خروجی
    return tokens  # بازگشت لیست

async def get_user_tokens(phone: str) -> List[str]:  # تابع=خواندن توکن‌های نقش کاربر برای یک شماره
    sel = DeviceTokenTable.__table__.select().where(  # sel=انتخاب از device_tokens
        (DeviceTokenTable.role == "client") & (DeviceTokenTable.user_phone == phone)
    )  # شرط نقش=client و phone=شماره
    rows = await database.fetch_all(sel)  # rows=نتیجه
    tokens, seen = [], set()  # tokens/seen=لیست/مجموعه
    for r in rows:  # حلقه
        t = r["token"]  # t=توکن/تاپیک
        if t and t not in seen:  # غیرخالی و یکتا
            seen.add(t)  # ثبت
            tokens.append(t)  # افزودن
    return tokens  # بازگشت

async def _send_fcm(tokens: List[str], title: str, body: str, data: Optional[dict], channel_id: str):  # تابع داخلی=ارسال FCM
    if not FCM_SERVER_KEY or not tokens:  # اگر=کلید FCM یا لیست توکن خالی
        return  # خروج
    url = "https://fcm.googleapis.com/fcm/send"  # url=آدرس legacy FCM
    headers = {"Authorization": f"key={FCM_SERVER_KEY}", "Content-Type": "application/json"}  # headers=هدر احراز و نوع محتوا
    async with httpx.AsyncClient(timeout=10.0) as client:  # AsyncClient=کلاینت HTTP async
        for t in tokens:  # حلقه روی هر توکن
            payload = {  # payload=بدنه JSON
                "to": t,  # to=توکن مقصد
                "priority": "high",  # priority=اولویت بالا
                "notification": {"title": title, "body": body, "android_channel_id": channel_id},  # notification=عنوان/متن/کانال اندروید
                "data": data or {}  # data=داده سفارشی (اختیاری)
            }  # پایان payload
            try:  # try=محافظ ارسال
                await client.post(url, headers=headers, json=payload)  # POST=ارسال به FCM
            except Exception:  # خطا=نادیده
                pass  # pass

async def _send_ntfy(topics: List[str], title: str, body: str, data: Optional[dict]):  # تابع داخلی=ارسال به ntfy
    if not topics:  # اگر=لیست خالی
        return  # خروج
    base = NTFY_BASE_URL.rstrip("/")  # base=حذف اسلش انتهایی
    async with httpx.AsyncClient(timeout=10.0) as client:  # AsyncClient=کلاینت HTTP
        for topic in topics:  # حلقه روی هر topic
            url = f"{base}/{topic}"  # url=نشانی تاپیک ntfy (POST به این مسیر)
            headers = {"Title": title, "Priority": "5"}  # headers=عنوان و اولویت (۵=بالا)
            if NTFY_AUTH:  # اگر=توکن/احراز تعریف شده
                headers["Authorization"] = NTFY_AUTH  # Authorization=قرار دادن مقدار کامل (Bearer/Basic ...)
            content = body  # content=متن اعلان (بدنه ساده)
            try:  # try=ارسال
                await client.post(url, headers=headers, content=content)  # POST=ارسال به ntfy
            except Exception:  # خطا=نادیده
                pass  # pass

async def send_push_to_tokens(tokens: List[str], title: str, body: str, data: Optional[dict] = None, channel_id: str = "order_status_channel"):  # تابع=ارسال پوش با بک‌اند قابل سوئیچ
    if PUSH_BACKEND == "ntfy":  # اگر=بک‌اند ntfy
        await _send_ntfy(tokens, title, body, data)  # ارسال با ntfy (tokens=topics)
    else:  # else=پیش‌فرض fcm
        await _send_fcm(tokens, title, body, data, channel_id)  # ارسال با FCM

async def send_push_to_managers(title: str, body: str, data: Optional[dict] = None):  # تابع=ارسال پوش به همه مدیرها
    tokens = await get_manager_tokens()  # tokens=توکن/تاپیک‌های مدیر
    await send_push_to_tokens(tokens, title, body, data, channel_id="putz_manager_general")  # ارسال با کانال مدیر

async def send_push_to_user(phone: str, title: str, body: str, data: Optional[dict] = None):  # تابع=ارسال پوش به کاربر با شماره
    tokens = await get_user_tokens(phone)  # tokens=توکن/تاپیک‌های کاربر
    await send_push_to_tokens(tokens, title, body, data, channel_id="order_status_channel")  # ارسال با کانال کاربر

# -------------------- App & CORS --------------------
app = FastAPI()  # app=نمونه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # allow_origins=تحلیل رشته مبداها
app.add_middleware(  # add_middleware=افزودن CORS
    CORSMiddleware,  # CORSMiddleware=میان‌افزار CORS
    allow_origins=allow_origins,  # allow_origins=مبداها
    allow_credentials=True,  # allow_credentials=اجازه کوکی/احراز
    allow_methods=["*"],  # allow_methods=همه متدها
    allow_headers=["*"],  # allow_headers=همه هدرها
)

# -------------------- Startup/Shutdown --------------------
@app.on_event("startup")  # دکوراتور=رویداد شروع
async def startup():  # تابع=راه‌اندازی
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # engine=موتور sync (برای create_all)
    Base.metadata.create_all(engine)  # ایجاد جداول
    with engine.begin() as conn:  # with=تراکنش
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # تضمین ستون scheduled_start
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place TEXT DEFAULT 'client';"))  # تضمین ستون service_place
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS execution_start TIMESTAMPTZ NULL;"))  # تضمین ستون execution_start
    await database.connect()  # اتصال Async به DB

@app.on_event("shutdown")  # دکوراتور=رویداد خاموشی
async def shutdown():  # تابع=خاموشی
    await database.disconnect()  # قطع اتصال DB

# -------------------- Health --------------------
@app.get("/")  # مسیر=ریشه
def read_root():  # تابع=سلامتی
    return {"message": "Putzfee FastAPI Server is running!"}  # پاسخ=پیام ساده سلامتی

# -------------------- Push endpoints --------------------
@app.post("/push/register")  # مسیر=ثبت/به‌روزرسانی توکن/تاپیک پوش
async def register_push_token(body: PushRegister, request: Request):  # تابع=ثبت توکن
    now = datetime.now(timezone.utc)  # now=اکنون
    sel = DeviceTokenTable.__table__.select().where(DeviceTokenTable.token == body.token)  # sel=انتخاب براساس token/topic
    row = await database.fetch_one(sel)  # row=نتیجه یک ردیف (یا None)
    if row is None:  # اگر=موجود نیست
        ins = DeviceTokenTable.__table__.insert().values(  # ins=درج ردیف جدید
            token=body.token, role=body.role, platform=body.platform, user_phone=body.user_phone, created_at=now, updated_at=now
        )  # پایان values
        await database.execute(ins)  # اجرا
    else:  # else=وجود دارد → به‌روزرسانی نقش/پلتفرم/شماره
        upd = DeviceTokenTable.__table__.update().where(DeviceTokenTable.id == row["id"]).values(
            role=body.role, platform=body.platform, user_phone=body.user_phone or row["user_phone"], updated_at=now
        )  # پایان values
        await database.execute(upd)  # اجرا
    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": body.role})  # پاسخ=ok

# -------------------- Auth/User --------------------
@app.get("/users/exists")  # مسیر=بررسی وجود کاربر
async def user_exists(phone: str):  # تابع=exists
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # q=کوئری شمارش
    count = await database.fetch_val(q)  # count=مقدار
    exists = bool(count and int(count) > 0)  # exists=بولین
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ

@app.post("/register_user")  # مسیر=ثبت‌نام
async def register_user(user: UserRegisterRequest):  # تابع=ثبت‌نام
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # q=بررسی تکرار
    count = await database.fetch_val(q)  # count=نتیجه
    if count and int(count) > 0:  # اگر=کاربر موجود
        raise HTTPException(status_code=400, detail="User already exists")  # خطا=400
    password_hash = bcrypt_hash_password(user.password)  # password_hash=هش bcrypt
    ins = UserTable.__table__.insert().values(  # ins=درج کاربر
        phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[]
    )  # پایان values
    await database.execute(ins)  # اجرا
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ=ok

@app.post("/login")  # مسیر=ورود
async def login_user(user: UserLoginRequest, request: Request):  # تابع=ورود
    now = datetime.now(timezone.utc)  # now=اکنون
    client_ip = get_client_ip(request)  # client_ip=IP کلاینت
    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))  # sel=کوئری رکورد تلاش
    attempt_row = await database.fetch_one(sel_attempt)  # attempt_row=ردیف موجود یا None
    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:  # اگر=قفل فعال
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())  # retry_after=زمان باقی
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after})  # raise=429
    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # sel_user=یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # db_user=نتیجه
    if not db_user:  # اگر=کاربر نبود
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})  # raise=404
    if not verify_password_secure(user.password, db_user["password_hash"]):  # اگر=رمز غلط
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD"})  # raise=401
    await _register_login_success(user.phone, client_ip)  # ثبت موفق
    if not db_user["password_hash"].startswith("$2"):  # اگر=هش قدیمی
        new_hash = bcrypt_hash_password(user.password)  # new_hash=هش جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # upd=به‌روزرسانی
        await database.execute(upd)  # اجرا
    access_token = create_access_token(db_user["phone"])  # access_token=ساخت JWT دسترسی
    refresh_token = create_refresh_token()  # refresh_token=ساخت رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش رفرش
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # refresh_exp=انقضا
    ins_rt = RefreshTokenTable.__table__.insert().values(user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False)  # درج رفرش
    await database.execute(ins_rt)  # اجرا
    mapping = getattr(db_user, "_mapping", {})  # mapping=سازگاری RowMapping
    name_val = mapping["name"] if "name" in mapping else ""  # name_val=نام
    address_val = mapping["address"] if "address" in mapping else ""  # address_val=آدرس
    return {"status": "ok", "access_token": access_token, "refresh_token": refresh_token, "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}}  # پاسخ=لاگین موفق

async def _register_login_failure(phone: str, ip: str):  # تابع=ثبت شکست لاگین
    now = datetime.now(timezone.utc)  # اکنون
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # sel=انتخاب رکورد
    row = await database.fetch_one(sel)  # row=نتیجه
    if row is None:  # اگر=رکورد نبود
        ins = LoginAttemptTable.__table__.insert().values(phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now)  # درج رکورد جدید
        await database.execute(ins); return  # اجرا و خروج
    window_start = row["window_start"] or now  # window_start=شروع پنجره
    within = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS  # within=داخل پنجره؟
    new_count = (row["attempt_count"] + 1) if within else 1  # new_count=شمارش جدید
    new_window_start = window_start if within else now  # new_window_start=شروع جدید
    locked_until = row["locked_until"]  # locked_until=قفل فعلی
    if new_count >= LOGIN_MAX_ATTEMPTS:  # اگر=عبور از حد
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # locked_until=تنظیم قفل
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now)  # به‌روزرسانی
    await database.execute(upd)  # اجرا

async def _register_login_success(phone: str, ip: str):  # تابع=ثبت موفق لاگین
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # sel=یافتن رکورد
    row = await database.fetch_one(sel)  # row=نتیجه
    if row:  # اگر=رکورد هست
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None)  # ریست شمارنده/قفل
        await database.execute(upd)  # اجرا

@app.post("/auth/refresh")  # مسیر=رفرش توکن دسترسی
async def refresh_access_token(req: Dict):  # تابع=رفرش
    refresh_token = req.get("refresh_token", "")  # refresh_token=خواندن از بدنه
    if not refresh_token:  # اگر=تهی
        raise HTTPException(status_code=400, detail="refresh_token required")  # 400
    token_hash = hash_refresh_token(refresh_token)  # token_hash=هش رفرش
    now = datetime.now(timezone.utc)  # اکنون
    sel = RefreshTokenTable.__table__.select().where((RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now))  # sel=انتخاب معتبرها
    rt = await database.fetch_one(sel)  # rt=نتیجه
    if not rt:  # اگر=یافت نشد
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # sel_user=یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # db_user=نتیجه
    if not db_user:  # اگر=کاربر نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401
    new_access = create_access_token(db_user["phone"])  # new_access=ساخت توکن جدید
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # پاسخ=ok

# -------------------- Notifications --------------------
@app.get("/user/{phone}/notifications")  # مسیر=فهرست اعلان‌ها
async def get_notifications(phone: str, only_unread: bool = True, limit: int = 50, offset: int = 0):  # تابع=گرفتن اعلان‌ها
    base_sel = NotificationTable.__table__.select().where(NotificationTable.user_phone == phone)  # base_sel=انتخاب بر اساس شماره
    if only_unread:  # اگر=فقط نخوانده‌ها
        base_sel = base_sel.where(NotificationTable.read == False)  # شرط read=False
    base_sel = base_sel.order_by(NotificationTable.created_at.desc()).limit(limit).offset(offset)  # مرتب/صفحه‌بندی
    rows = await database.fetch_all(base_sel)  # rows=نتیجه
    items = [dict(r) for r in rows]  # items=تبدیل به dict
    return unified_response("ok", "NOTIFICATIONS", "user notifications", {"items": items})  # پاسخ=ok

@app.post("/user/{phone}/notifications/{notif_id}/read")  # مسیر=علامت خوانده‌شدن اعلان
async def mark_notification_read(phone: str, notif_id: int):  # تابع=علامت خوانده
    now = datetime.now(timezone.utc)  # اکنون
    upd = NotificationTable.__table__.update().where((NotificationTable.id == notif_id) & (NotificationTable.user_phone == phone)).values(read=True, read_at=now)  # upd=به‌روزرسانی
    await database.execute(upd)  # اجرا
    return unified_response("ok", "NOTIF_READ", "notification marked as read", {"id": notif_id})  # پاسخ=ok

@app.post("/user/{phone}/notifications/mark_all_read")  # مسیر=علامت خوانده‌شدن همه
async def mark_all_notifications_read(phone: str):  # تابع=علامت همه خوانده
    now = datetime.now(timezone.utc)  # اکنون
    upd = NotificationTable.__table__.update().where((NotificationTable.user_phone == phone) & (NotificationTable.read == False)).values(read=True, read_at=now)  # upd=به‌روزرسانی
    await database.execute(upd)  # اجرا
    return unified_response("ok", "NOTIFS_READ_ALL", "all notifications marked as read", {})  # پاسخ=ok

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")  # مسیر=ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # تابع=ماشین‌ها
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # query=انتخاب کاربر
    user = await database.fetch_one(query)  # user=نتیجه
    if not user:  # اگر=نبود
        raise HTTPException(status_code=404, detail="User not found")  # 404
    items = user["car_list"] or []  # items=لیست ماشین‌ها
    return unified_response("ok", "USER_CARS", "user cars", {"items": items})  # پاسخ=ok

@app.post("/user_cars")  # مسیر=به‌روزرسانی ماشین‌ها
async def update_user_cars(data: CarListUpdateRequest):  # تابع=آپدیت ماشین‌ها
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # sel=یافتن کاربر
    user = await database.fetch_one(sel)  # user=نتیجه
    if not user:  # اگر=نبود
        raise HTTPException(status_code=404, detail="User not found")  # 404
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(car_list=[car.dict() for car in data.car_list])  # upd=ثبت لیست جدید
    await database.execute(upd)  # اجرا
    return unified_response("ok", "CARS_SAVED", "cars saved", {"count": len(data.car_list)})  # پاسخ=ok

# -------------------- Orders --------------------
@app.post("/order")  # مسیر=ثبت سفارش
async def create_order(order: OrderRequest):  # تابع=ایجاد سفارش
    ins = RequestTable.__table__.insert().values(  # ins=ساخت INSERT
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
    ).returning(RequestTable.id)  # returning=برگرداندن id ایجادشده
    row = await database.fetch_one(ins)  # row=اجرای درج
    new_id = row[0] if isinstance(row, (tuple, list)) else (row["id"] if row else None)  # new_id=استخراج id
    try:  # try=محافظ پوش
        await send_push_to_managers("درخواست جدید", "درخواست جدید ثبت شد.", {"type": "new_request", "order_id": str(new_id)})  # پوش مدیر
    except Exception:  # خطا=نادیده
        pass  # pass
    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # پاسخ=ok

@app.post("/cancel_order")  # مسیر=لغو سفارش
async def cancel_order(cancel: CancelRequest):  # تابع=لغو
    upd = (RequestTable.__table__.update().where(
        (RequestTable.user_phone == cancel.user_phone) &
        (RequestTable.service_type == cancel.service_type) &
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))
    ).values(status="CANCELED", scheduled_start=None).returning(RequestTable.id))  # upd=تغییر وضعیت به CANCELED
    rows = await database.fetch_all(upd)  # rows=اجرای آپدیت
    if rows and len(rows) > 0:  # اگر=رکوردی تغییر کرد
        try:  # try=ارسال پوش مدیر
            for r in rows:  # حلقه روی سفارش‌ها
                oid = None  # oid=شناسه
                mapping = getattr(r, "_mapping", None)  # mapping=سازگاری
                if mapping and "id" in mapping:  # اگر=id در mapping
                    oid = mapping["id"]  # oid=شناسه
                elif isinstance(r, (tuple, list)) and len(r) > 0:  # اگر=تاپل
                    oid = r[0]  # oid=عنصر اول
                await send_push_to_managers("لغو درخواست", "کاربر سفارش را لغو کرد.", {"type": "order_canceled", "order_id": str(oid) if oid is not None else ""})  # پوش مدیر
        except Exception:  # خطا=نادیده
            pass  # pass
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # پاسخ=ok
    raise HTTPException(status_code=404, detail="active order not found")  # raise=404 اگر سفارش فعالی نبود

@app.get("/user_active_services/{user_phone}")  # مسیر=سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # تابع=سفارش‌های فعال
    sel = RequestTable.__table__.select().where((RequestTable.user_phone == user_phone) & (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"])))  # sel=انتخاب فعال‌ها
    result = await database.fetch_all(sel)  # result=لیست ردیف‌ها
    items = [dict(r) for r in result]  # items=تبدیل به dict
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # پاسخ=ok

@app.get("/user_orders/{user_phone}")  # مسیر=تاریخچه کاربر
async def get_user_orders(user_phone: str):  # تابع=سفارش‌های کاربر
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # sel=انتخاب همه سفارش‌های کاربر
    result = await database.fetch_all(sel)  # result=لیست
    items = [dict(r) for r in result]  # items=تبدیل به dict
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # پاسخ=ok

# -------------------- Scheduling (1 hour slots) --------------------
@app.get("/provider/{provider_phone}/free_hours")  # مسیر=ساعات آزاد یک‌ساعته
async def get_free_hours(provider_phone: str, date: str, work_start: int = 8, work_end: int = 20, limit: int = 24):  # تابع=ساعات آزاد
    try:  # try=پارس تاریخ
        d = datetime.fromisoformat(date).date()  # d=تاریخ
    except Exception:  # catch=خطا
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # 400
    if not (0 <= work_start < 24 and 0 <= work_end <= 24 and work_start < work_end):  # if=اعتبار ساعات
        raise HTTPException(status_code=400, detail="invalid work hours")  # 400
    provider = provider_phone.strip()  # provider=تمیز
    if not provider or provider.lower() == "any":  # if=شماره نامعتبر
        raise HTTPException(status_code=400, detail="invalid provider_phone")  # 400
    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)  # day_start=شروع روز
    day_end = datetime(d.year, d.month, d.day, work_end, 0, tzinfo=timezone.utc)  # day_end=پایان روز
    results: List[str] = []  # results=خروجی
    cur = day_start  # cur=زمان جاری
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:  # حلقه تولید اسلات
        s, e = cur, cur + timedelta(hours=1)  # بازه [s,e)
        if await provider_is_free(provider, s, e):  # اگر=provider آزاد است
            results.append(s.isoformat())  # افزودن شروع اسلات
        cur = cur + timedelta(hours=1)  # حرکت به اسلات بعدی
    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})  # پاسخ=ok

@app.get("/busy_slots")  # مسیر=ساعات مشغول
async def get_busy_slots(provider_phone: str, date: str, exclude_order_id: Optional[int] = None):  # تابع=busy
    try:  # try=پارس تاریخ
        d = datetime.fromisoformat(date).date()  # d=تاریخ
    except Exception:  # catch=خطا
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # 400
    provider = provider_phone.strip()  # provider=شماره
    if not provider or provider.lower() == "any":  # if=نامعتبر
        raise HTTPException(status_code=400, detail="invalid provider_phone")  # 400
    day_start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)  # day_start=۰۰:۰۰ UTC
    day_end = day_start + timedelta(days=1)  # day_end=پایان روز
    sel_sched = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.slot_start >= day_start) & (ScheduleSlotTable.slot_start < day_end) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) & (ScheduleSlotTable.provider_phone == provider))  # sel_sched=اسلات‌های پیشنهادی/قبول‌شده
    if exclude_order_id is not None:  # اگر=حذف سفارش جاری
        sel_sched = sel_sched.where(ScheduleSlotTable.request_id != exclude_order_id)  # شرط حذف سفارش
    rows_sched = await database.fetch_all(sel_sched)  # rows_sched=نتیجه
    sel_app = AppointmentTable.__table__.select().where((AppointmentTable.start_time >= day_start) & (AppointmentTable.start_time < day_end) & (AppointmentTable.status == "BOOKED") & (AppointmentTable.provider_phone == provider))  # sel_app=رزروهای قطعی
    rows_app = await database.fetch_all(sel_app)  # rows_app=نتیجه
    busy: set[str] = set()  # busy=مجموعه بازه‌های مشغول
    for r in rows_sched:  # حلقه=اسلات‌ها
        busy.add(r["slot_start"].isoformat())  # افزودن start
    for r in rows_app:  # حلقه=رزروها
        busy.add(r["start_time"].isoformat())  # افزودن start
    items = sorted(busy)  # items=مرتب‌سازی
    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": items})  # پاسخ=ok

@app.post("/order/{order_id}/propose_slots")  # مسیر=پیشنهاد اسلات‌ها (مدیر)
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):  # تابع=ثبت اسلات
    require_admin(request)  # بررسی ادمین
    provider = (body.provider_phone or "").strip()  # provider=شماره سرویس‌گیرنده
    if not provider or provider.lower() == "any":  # if=نامعتبر
        raise HTTPException(status_code=400, detail="invalid provider_phone")  # 400
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == order_id))  # req=یافتن سفارش
    if not req:  # اگر=نبود
        raise HTTPException(status_code=404, detail="order not found")  # 404
    accepted: List[str] = []  # accepted=لیست اسلات‌های قابل قبول
    for s in body.slots[:3]:  # حداکثر ۳ اسلات
        start = parse_iso(s)  # start=پارس ISO
        end = start + timedelta(hours=1)  # end=پایان یک‌ساعت
        if await provider_is_free(provider, start, end):  # اگر=آزاد
            await database.execute(ScheduleSlotTable.__table__.insert().values(request_id=order_id, provider_phone=provider, slot_start=start, status="PROPOSED", created_at=datetime.now(timezone.utc)))  # درج اسلات
            accepted.append(start.isoformat())  # افزودن به لیست
    if accepted:  # اگر=چیزی پذیرفته شد
        await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="WAITING", driver_phone=provider, scheduled_start=None))  # به‌روزرسانی وضعیت سفارش
        try:  # try=ارسال اعلان/پوش به کاربر
            await notify_user(req["user_phone"], "زمان‌بندی بازدید", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.", data={"type": "visit_slots", "order_id": order_id, "slots": accepted})  # ثبت اعلان DB
            await send_push_to_user(req["user_phone"], "زمان‌بندی بازدید", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.", data={"type": "visit_slots", "order_id": order_id})  # پوش کاربر
        except Exception:  # خطا=نادیده
            pass  # pass
    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # پاسخ=ok

@app.get("/order/{order_id}/proposed_slots")  # مسیر=خواندن اسلات‌های پیشنهادی
async def get_proposed_slots(order_id: int):  # تابع=خواندن اسلات‌ها
    sel = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")).order_by(ScheduleSlotTable.slot_start.asc())  # sel=انتخاب PROPOSED به ترتیب صعودی
    rows = await database.fetch_all(sel)  # rows=نتیجه
    items = [r["slot_start"].isoformat() for r in rows]  # items=لیست ISO
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})  # پاسخ=ok

@app.post("/order/{order_id}/confirm_slot")  # مسیر=تأیید اسلات (کاربر)
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):  # تابع=تأیید
    chosen_start = parse_iso(body.slot)  # chosen_start=پارس ISO
    sel_slot = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.slot_start == chosen_start) & (ScheduleSlotTable.status == "PROPOSED"))  # sel=یافتن اسلات پیشنهادی
    slot = await database.fetch_one(sel_slot)  # slot=نتیجه
    if not slot:  # اگر=نیافت
        raise HTTPException(status_code=404, detail="slot not found or not proposed")  # 404
    provider_phone = slot["provider_phone"]  # provider_phone=شماره سرویس‌گیرنده
    start = slot["slot_start"]  # start=شروع
    end = start + timedelta(hours=1)  # end=پایان
    if not await provider_is_free(provider_phone, start, end):  # اگر=دیگر آزاد نیست
        await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="REJECTED"))  # رد اسلات
        raise HTTPException(status_code=409, detail="slot no longer available")  # 409
    await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="ACCEPTED"))  # قبول اسلات انتخابی
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED") & (ScheduleSlotTable.id != slot["id"])).values(status="REJECTED"))  # رد بقیه
    await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)))  # رزرو قطعی
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(scheduled_start=start, status="ASSIGNED", driver_phone=provider_phone))  # به‌روزرسانی سفارش
    try:  # try=پوش مدیر
        await send_push_to_managers("تأیید زمان بازدید", "کاربر زمان بازدید را تأیید کرد.", {"type": "time_confirm", "order_id": str(order_id)})  # پوش مدیر
    except Exception:  # خطا=نادیده
        pass  # pass
    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})  # پاسخ=ok

@app.post("/order/{order_id}/reject_all_and_cancel")  # مسیر=رد همه و کنسل
async def reject_all_and_cancel(order_id: int):  # تابع=رد/کنسل
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")).values(status="REJECTED"))  # رد همه اسلات‌ها
    upd = RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="CANCELED", scheduled_start=None).returning(RequestTable.id)  # کنسل سفارش
    await database.fetch_all(upd)  # اجرا
    try:  # try=پوش مدیر
        await send_push_to_managers("لغو درخواست", "کاربر سفارش را لغو کرد.", {"type": "order_canceled", "order_id": str(order_id)})  # پوش مدیر
    except Exception:  # خطا=نادیده
        pass  # pass
    return unified_response("ok", "ORDER_CANCELED", "order canceled after rejecting proposals", {"id": order_id})  # پاسخ=ok

# -------------------- Admin/Workflow --------------------
@app.get("/admin/requests/active")  # مسیر=لیست سفارش‌های فعال (ادمین)
async def admin_active_requests(request: Request):  # تابع=فعال‌ها
    require_admin(request)  # بررسی ادمین
    active = ["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]  # active=وضعیت‌های فعال
    sel = RequestTable.__table__.select().where(RequestTable.status.in_(active)).order_by(RequestTable.id.desc())  # sel=انتخاب و مرتب‌سازی نزولی
    rows = await database.fetch_all(sel)  # rows=نتیجه
    items = [dict(r) for r in rows]  # items=تبدیل به dict
    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": items})  # پاسخ=ok

@app.post("/admin/order/{order_id}/price")  # مسیر=ثبت قیمت (ادمین)
async def admin_set_price_and_status(order_id: int, body: PriceBody, request: Request):  # تابع=قیمت/وضعیت
    require_admin(request)  # بررسی ادمین
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel=یافتن سفارش
    req = await database.fetch_one(sel)  # req=نتیجه
    if not req:  # اگر=نبود
        raise HTTPException(status_code=404, detail="order not found")  # 404

    new_status = "IN_PROGRESS" if body.agree else "CANCELED"  # new_status=وضعیت جدید
    values = {"price": body.price, "status": new_status}  # values=مقادیر پایه آپدیت

    exec_iso = (body.exec_time or "").strip()  # exec_iso=زمان اجرای کار (رشته ISO)
    if body.agree and exec_iso:  # اگر=توافق و زمان اجرا موجود
        start = parse_iso(exec_iso)  # start=پارس ISO
        end = start + timedelta(hours=1)  # end=یک ساعت بعد
        provider_phone = (req["driver_phone"] or "").strip()  # provider_phone=شماره سرویس‌گیرنده
        if not provider_phone:  # اگر=provider خالی
            raise HTTPException(status_code=400, detail="driver_phone required for execution")  # 400
        free = await provider_is_free(provider_phone, start, end)  # free=آزاد بودن بازه
        if not free:  # اگر=مشغول
            raise HTTPException(status_code=409, detail="execution slot busy")  # 409
        await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)))  # رزرو اجرا
        values["execution_start"] = start  # ثبت execution_start
        try:  # try=اعلام و پوش به کاربر
            await notify_user(req["user_phone"], "تعیین قیمت و زمان اجرا", "قیمت و زمان اجرای کار تعیین شد.", data={"type": "execution_time", "order_id": order_id, "start": start.isoformat(), "price": body.price})  # اعلان DB
            await send_push_to_user(req["user_phone"], "تعیین قیمت و زمان اجرا", "قیمت و زمان اجرای کار تعیین شد.", data={"type": "execution_time", "order_id": order_id})  # پوش کاربر
        except Exception:  # خطا=نادیده
            pass  # pass
    elif body.agree:  # else=فقط قیمت بدون زمان
        try:  # try=اعلام به کاربر
            await notify_user(req["user_phone"], "تعیین قیمت", "قیمت سرویس تعیین شد.", data={"type": "price_set", "order_id": order_id, "price": body.price})  # اعلان DB
            await send_push_to_user(req["user_phone"], "تعیین قیمت", "قیمت سرویس تعیین شد.", data={"type": "price_set", "order_id": order_id})  # پوش کاربر
        except Exception:  # خطا=نادیده
            pass  # pass

    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(**values))  # اجرای آپدیت سفارش
    resp = {"order_id": order_id, "price": body.price, "status": new_status, "execution_start": values.get("execution_start").isoformat() if values.get("execution_start") else None}  # resp=خروجی پاسخ
    return unified_response("ok", "PRICE_SET", "price and status updated", resp)  # پاسخ=ok

@app.post("/order/{order_id}/start")  # مسیر=شروع کار
async def start_order(order_id: int, request: Request):  # تابع=شروع
    require_admin(request)  # بررسی ادمین
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel=یافتن سفارش
    req = await database.fetch_one(sel)  # req=نتیجه
    if not req:  # اگر=نبود
        raise HTTPException(status_code=404, detail="order not found")  # 404
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="STARTED"))  # به‌روزرسانی وضعیت
    return unified_response("ok", "ORDER_STARTED", "order started", {"order_id": order_id, "status": "STARTED"})  # پاسخ=ok

@app.post("/order/{order_id}/finish")  # مسیر=پایان کار
async def finish_order(order_id: int, request: Request):  # تابع=پایان
    require_admin(request)  # بررسی ادمین
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # sel=یافتن سفارش
    req = await database.fetch_one(sel)  # req=نتیجه
    if not req:  # اگر=نبود
        raise HTTPException(status_code=404, detail="order not found")  # 404
    now_iso = datetime.now(timezone.utc).isoformat()  # now_iso=زمان پایان
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="FINISH", finish_datetime=now_iso))  # به‌روزرسانی وضعیت به FINISH
    try:  # try=اعلام به کاربر
        await notify_user(req["user_phone"], "اتمام کار", "کار با موفقیت به پایان رسید.", data={"type": "work_finished", "order_id": order_id})  # اعلان DB
        await send_push_to_user(req["user_phone"], "اتمام کار", "کار با موفقیت به پایان رسید.", data={"type": "work_finished", "order_id": order_id})  # پوش کاربر
    except Exception:  # خطا=نادیده
        pass  # pass
    return unified_response("ok", "ORDER_FINISHED", "order finished", {"order_id": order_id, "status": "FINISH"})  # پاسخ=ok

# -------------------- Profile --------------------
@app.post("/user/profile")  # مسیر=ذخیره پروفایل
async def update_profile(body: UserProfileUpdate):  # تابع=به‌روزرسانی پروفایل
    if not body.phone.strip():  # اگر=شماره خالی
        raise HTTPException(status_code=400, detail="phone_required")  # 400
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # sel=یافتن کاربر
    user = await database.fetch_one(sel)  # user=نتیجه
    if user is None:  # اگر=نبود
        raise HTTPException(status_code=404, detail="User not found")  # 404
    await database.execute(UserTable.__table__.update().where(UserTable.phone == body.phone).values(name=body.name.strip(), address=body.address.strip()))  # به‌روزرسانی نام/آدرس
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # پاسخ=ok

@app.get("/user/profile/{phone}")  # مسیر=خواندن پروفایل
async def get_user_profile(phone: str):  # تابع=خواندن پروفایل
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # sel=انتخاب کاربر
    db_user = await database.fetch_one(sel)  # db_user=نتیجه
    if db_user is None:  # اگر=نبود
        raise HTTPException(status_code=404, detail="User not found")  # 404
    mapping = getattr(db_user, "_mapping", {})  # mapping=سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # name_val=نام
    address_val = mapping["address"] if "address" in mapping else ""  # address_val=آدرس
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {"phone": db_user["phone"], "name": name_val or "", "address": address_val or ""})  # پاسخ=ok

@app.get("/debug/users")  # مسیر=دیباگ کاربران
async def debug_users():  # تابع=لیست کاربران
    rows = await database.fetch_all(UserTable.__table__.select())  # rows=انتخاب همه
    out = []  # out=لیست خروجی
    for r in rows:  # حلقه=روی ردیف‌ها
        mapping = getattr(r, "_mapping", {})  # mapping=سازگاری
        name_val = mapping["name"] if "name" in mapping else ""  # name_val
        address_val = mapping["address"] if "address" in mapping else ""  # address_val
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})  # افزودن آیتم
    return out  # بازگشت لیست
