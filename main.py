# -*- coding: utf-8 -*-  # کدینگ فایل=یونیکد
# FastAPI server (orders + hourly scheduling + DB notifications + FCM push + AdminKey + execution_time + user push)  # توضیح=سرور با پوش به مدیر و کاربر

import os  # ماژول=سیستم
import hashlib  # ماژول=هش
import secrets  # ماژول=توکن
from datetime import datetime, timedelta, timezone  # کلاس‌های زمان
from typing import Optional, List, Dict  # نوع‌دهی

import bcrypt  # کتابخانه=bcrypt
import jwt  # کتابخانه=JWT
from fastapi import FastAPI, HTTPException, Request  # FastAPI=چارچوب | HTTPException=خطا | Request=درخواست
from fastapi.middleware.cors import CORSMiddleware  # CORS=میان‌افزار
from pydantic import BaseModel  # BaseModel=مدل‌ها

from sqlalchemy import (  # SQLAlchemy=ORM/SQL
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_, text, UniqueConstraint  # اجزاء ORM
)
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه ORM
import sqlalchemy  # sqlalchemy=پکیج اصلی
from databases import Database  # databases=اتصال async
from dotenv import load_dotenv  # load_dotenv=خواندن .env
import httpx  # httpx=کلاینت HTTP

# -------------------- Config --------------------
load_dotenv()  # بارگذاری .env
DATABASE_URL = os.getenv("DATABASE_URL")  # آدرس DB
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # کلید JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # pepper رمز
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # انقضا دسترسی
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # انقضا رفرش
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # دورهای bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # مبداهای مجاز
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))  # پنجره تلاش ورود
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # سقف تلاش
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))  # زمان قفل
FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "")  # کلید FCM
ADMIN_KEY = os.getenv("ADMIN_KEY", "CHANGE_ME_ADMIN")  # ADMIN_KEY=کلید ادمین ساده برای مسیرهای مدیریتی

database = Database(DATABASE_URL)  # نمونه اتصال DB
Base = declarative_base()  # پایه ORM

# -------------------- ORM models --------------------
class UserTable(Base):  # مدل=کاربران
    __tablename__ = "users"  # جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    phone = Column(String, unique=True, index=True)  # phone
    password_hash = Column(String)  # hash رمز
    address = Column(String)  # آدرس
    name = Column(String, default="")  # نام
    car_list = Column(JSONB, default=list)  # لیست ماشین‌ها

class DriverTable(Base):  # مدل=سرویس‌گیرنده‌ها
    __tablename__ = "drivers"  # جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    first_name = Column(String)  # نام
    last_name = Column(String)  # نام‌خانوادگی
    photo_url = Column(String)  # عکس
    id_card_number = Column(String)  # کد ملی
    phone = Column(String, unique=True, index=True)  # شماره
    phone_verified = Column(Boolean, default=False)  # تأیید
    is_online = Column(Boolean, default=False)  # آنلاین
    status = Column(String, default="فعال")  # وضعیت

class RequestTable(Base):  # مدل=سفارش‌ها
    __tablename__ = "requests"  # جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    user_phone = Column(String, index=True)  # شماره کاربر
    latitude = Column(Float)  # عرض
    longitude = Column(Float)  # طول
    car_list = Column(JSONB)  # لیست خدمات
    address = Column(String)  # آدرس
    home_number = Column(String, default="")  # پلاک
    service_type = Column(String, index=True)  # نوع سرویس
    price = Column(Integer)  # قیمت
    request_datetime = Column(String)  # زمان ثبت
    status = Column(String)  # وضعیت
    driver_name = Column(String)  # نام سرویس‌گیرنده
    driver_phone = Column(String)  # شماره سرویس‌گیرنده
    finish_datetime = Column(String)  # زمان پایان
    payment_type = Column(String)  # نوع پرداخت
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # شروع قطعی (بازدید/اولیه)
    service_place = Column(String, default="client")  # محل سرویس
    execution_start = Column(DateTime(timezone=True), nullable=True)  # زمان اجرای کار (جدید)

class RefreshTokenTable(Base):  # مدل=رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # ارجاع کاربر
    token_hash = Column(String, unique=True, index=True)  # هش توکن
    expires_at = Column(DateTime(timezone=True), index=True)  # انقضا
    revoked = Column(Boolean, default=False)  # باطل؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # ایندکس

class LoginAttemptTable(Base):  # مدل=تلاش‌های ورود
    __tablename__ = "login_attempts"  # جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    phone = Column(String, index=True)  # phone
    ip = Column(String, index=True)  # ip
    attempt_count = Column(Integer, default=0)  # تعداد تلاش
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # شروع پنجره
    locked_until = Column(DateTime(timezone=True), nullable=True)  # قفل تا
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # آخرین تلاش
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)  # ایندکس مرکب

class ScheduleSlotTable(Base):  # مدل=اسلات‌های پیشنهادی
    __tablename__ = "schedule_slots"  # جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # ارجاع سفارش
    provider_phone = Column(String, index=True)  # شماره سرویس‌گیرنده
    slot_start = Column(DateTime(timezone=True), index=True)  # شروع بازه
    status = Column(String, default="PROPOSED")  # وضعیت
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)  # ایندکس

class AppointmentTable(Base):  # مدل=نوبت‌های قطعی
    __tablename__ = "appointments"  # جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    provider_phone = Column(String, index=True)  # شماره سرویس‌گیرنده
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # ارجاع سفارش
    start_time = Column(DateTime(timezone=True), index=True)  # شروع
    end_time = Column(DateTime(timezone=True), index=True)  # پایان
    status = Column(String, default="BOOKED")  # وضعیت
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),  # یکتا=جلوگیری تداخل
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),  # ایندکس
    )

class NotificationTable(Base):  # مدل=اعلان‌ها
    __tablename__ = "notifications"  # جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    user_phone = Column(String, index=True)  # شماره کاربر
    title = Column(String)  # عنوان
    body = Column(String)  # متن
    data = Column(JSONB, default=dict)  # داده اضافی
    read = Column(Boolean, default=False, index=True)  # خوانده‌شده؟
    read_at = Column(DateTime(timezone=True), nullable=True)  # زمان خواندن
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)  # ایجاد
    __table_args__ = (Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),)  # ایندکس

class DeviceTokenTable(Base):  # مدل=توکن‌های پوش
    __tablename__ = "device_tokens"  # جدول
    id = Column(Integer, primary_key=True, index=True)  # id
    token = Column(String, unique=True, index=True)  # توکن
    role = Column(String, index=True)  # نقش
    platform = Column(String, default="android", index=True)  # پلتفرم
    user_phone = Column(String, nullable=True)  # شماره کاربر
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # به‌روزرسانی
    __table_args__ = (Index("ix_tokens_role_platform", "role", "platform"),)  # ایندکس

# -------------------- Pydantic models --------------------
class CarInfo(BaseModel):  # مدل=ماشین ساده
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک

class Location(BaseModel):  # مدل=مختصات
    latitude: float  # عرض
    longitude: float  # طول

class CarOrderItem(BaseModel):  # مدل=گزینه‌های سفارش
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک
    wash_outside: bool = False  # روشویی
    wash_inside: bool = False  # توشویی
    polish: bool = False  # پولیش

class OrderRequest(BaseModel):  # مدل=ثبت سفارش
    user_phone: str  # شماره کاربر
    location: Location  # مختصات
    car_list: List[CarOrderItem]  # خدمات
    address: str  # آدرس
    home_number: Optional[str] = ""  # پلاک
    service_type: str  # نوع سرویس
    price: int  # قیمت
    request_datetime: str  # زمان ثبت
    payment_type: str  # نوع پرداخت
    service_place: str  # محل انجام

class CarListUpdateRequest(BaseModel):  # مدل=آپدیت ماشین‌ها
    user_phone: str  # شماره
    car_list: List[CarInfo]  # ماشین‌ها

class CancelRequest(BaseModel):  # مدل=لغو سفارش
    user_phone: str  # شماره
    service_type: str  # نوع سرویس

class UserRegisterRequest(BaseModel):  # مدل=ثبت‌نام
    phone: str  # شماره
    password: str  # رمز
    address: Optional[str] = None  # آدرس

class UserLoginRequest(BaseModel):  # مدل=ورود
    phone: str  # شماره
    password: str  # رمز

class UserProfileUpdate(BaseModel):  # مدل=آپدیت پروفایل
    phone: str  # شماره
    name: str = ""  # نام
    address: str = ""  # آدرس

class ProposedSlotsRequest(BaseModel):  # مدل=ارسال اسلات‌ها
    provider_phone: str  # شماره سرویس‌گیرنده
    slots: List[str]  # لیست شروع‌های یک‌ساعته (ISO)

class ConfirmSlotRequest(BaseModel):  # مدل=تأیید اسلات
    slot: str  # شروع ISO انتخاب‌شده

class PriceBody(BaseModel):  # مدل=ثبت قیمت/توافق
    price: int  # قیمت
    agree: bool  # توافق؟
    exec_time: Optional[str] = None  # exec_time=زمان اجرای کار (ISO)

class PushRegister(BaseModel):  # مدل=ثبت توکن پوش
    role: str  # نقش
    token: str  # توکن
    platform: str = "android"  # پلتفرم
    user_phone: Optional[str] = None  # شماره کاربر

# -------------------- Security helpers --------------------
def bcrypt_hash_password(password: str) -> str:  # تابع=هش bcrypt
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # تولید نمک
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب رمز+pepper
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی=هش

def verify_password_secure(password: str, stored_hash: str) -> bool:  # تابع=اعتبارسنجی رمز
    try:  # try
        if stored_hash.startswith("$2"):  # اگر=فرمت bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # بررسی bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # هش قدیمی
        return old == stored_hash  # مقایسه
    except Exception:  # خطا
        return False  # بازگشت False

def create_access_token(phone: str) -> str:  # تابع=ساخت JWT دسترسی
    now = datetime.now(timezone.utc)  # اکنون
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # Payload
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # امضا

def create_refresh_token() -> str:  # تابع=ساخت رفرش
    return secrets.token_urlsafe(48)  # خروجی=توکن

def hash_refresh_token(token: str) -> str:  # تابع=هش رفرش
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # sha256

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # تابع=قالب پاسخ
    return {"status": status, "code": code, "message": message, "data": data or {}}  # قالب استاندارد

# -------------------- Admin helper --------------------
def require_admin(request: Request):  # تابع=بررسی هدر ادمین
    key = request.headers.get("x-admin-key", "")  # key=خواندن هدر X-Admin-Key
    if not key or key != ADMIN_KEY:  # بررسی=تهی یا نابرابر
        raise HTTPException(status_code=401, detail="admin auth required")  # خطا=عدم مجوز

# -------------------- Utils --------------------
def get_client_ip(request: Request) -> str:  # تابع=IP کلاینت
    xff = request.headers.get("x-forwarded-for", "")  # خواندن XFF
    if xff:  # وجود XFF
        return xff.split(",")[0].strip()  # اولین IP
    return request.client.host or "unknown"  # IP مستقیم

def parse_iso(ts: str) -> datetime:  # تابع=پارس ISO به datetime «بدون شیفت»
    try:  # try
        raw = ts.strip()  # پاکسازی
        if "T" not in raw:  # نبود T
            raise ValueError("no T in ISO")  # خطا
        date_part, time_part = raw.split("T", 1)  # جداسازی
        time_part = time_part.replace("Z", "")  # حذف Z
        for sign in ["+", "-"]:  # نشانه آفست
            idx = time_part.find(sign)  # یافتن نشانه
            if idx > 0:  # وجود آفست
                time_part = time_part[:idx]  # برش
                break  # خروج
        if time_part.count(":") == 1:  # فقط HH:MM
            time_part = f"{time_part}:00"  # افزودن ثانیه
        y, m, d = map(int, date_part.split("-"))  # پارس تاریخ
        hh, mm, ss = map(int, time_part.split(":"))  # پارس زمان
        dt = datetime(y, m, d, hh, mm, ss, tzinfo=timezone.utc)  # ساخت datetime با UTC
        return dt  # بازگشت
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail=f"invalid datetime: {ts}")  # 400

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:  # تابع=آزاد بودن
    q = AppointmentTable.__table__.select().where(  # انتخاب رزروهای BOOKED متداخل
        (AppointmentTable.provider_phone == provider_phone) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.end_time > start)
    )  # پایان where
    rows = await database.fetch_all(q)  # اجرا
    return len(rows) == 0  # True=آزاد

async def notify_user(phone: str, title: str, body: str, data: Optional[dict] = None):  # تابع=ثبت اعلان DB
    ins = NotificationTable.__table__.insert().values(  # درج اعلان
        user_phone=phone, title=title, body=body, data=(data or {}), read=False, created_at=datetime.now(timezone.utc)
    )  # پایان values
    await database.execute(ins)  # اجرا

# -------------------- Push helpers (FCM) --------------------
async def get_manager_tokens() -> List[str]:  # تابع=توکن‌های مدیر
    sel = DeviceTokenTable.__table__.select().where(  # انتخاب نقش=manager/اندروید
        (DeviceTokenTable.role == "manager") & (DeviceTokenTable.platform == "android")
    )  # پایان where
    rows = await database.fetch_all(sel)  # اجرا
    tokens = []  # لیست خروجی
    seen = set()  # حذف تکراری
    for r in rows:  # حلقه
        t = r["token"]  # توکن
        if t and t not in seen:  # غیرخالی و تکراری نبودن
            seen.add(t)  # افزودن به مجموعه
            tokens.append(t)  # افزودن به لیست
    return tokens  # بازگشت

async def get_user_tokens(phone: str) -> List[str]:  # تابع=توکن‌های کاربر
    sel = DeviceTokenTable.__table__.select().where(  # انتخاب نقش=client و شماره کاربر
        (DeviceTokenTable.role == "client") & (DeviceTokenTable.user_phone == phone)
    )  # پایان where
    rows = await database.fetch_all(sel)  # اجرا
    tokens = []  # لیست خروجی
    seen = set()  # حذف تکراری
    for r in rows:  # حلقه
        t = r["token"]  # توکن
        if t and t not in seen:  # غیرخالی و یکتا
            seen.add(t)  # افزودن
            tokens.append(t)  # افزودن
    return tokens  # بازگشت

async def send_push_to_tokens(tokens: List[str], title: str, body: str, data: Optional[dict] = None):  # تابع=ارسال پوش
    if not FCM_SERVER_KEY or not tokens:  # عدم کلید یا لیست خالی
        return  # خروج
    url = "https://fcm.googleapis.com/fcm/send"  # آدرس legacy
    headers = {"Authorization": f"key={FCM_SERVER_KEY}", "Content-Type": "application/json"}  # هدرها
    async with httpx.AsyncClient(timeout=10.0) as client:  # کلاینت
        for t in tokens:  # حلقه
            payload = {  # بدنه
                "to": t,
                "priority": "high",
                "notification": {"title": title, "body": body, "android_channel_id": "putz_manager_general"},
                "data": data or {}
            }  # پایان payload
            try:  # try
                await client.post(url, headers=headers, json=payload)  # POST
            except Exception:  # خطا
                pass  # نادیده

async def send_push_to_managers(title: str, body: str, data: Optional[dict] = None):  # تابع=ارسال پوش مدیران
    tokens = await get_manager_tokens()  # گرفتن توکن‌ها
    await send_push_to_tokens(tokens, title, body, data)  # ارسال

async def send_push_to_user(phone: str, title: str, body: str, data: Optional[dict] = None):  # تابع=ارسال پوش کاربر
    tokens = await get_user_tokens(phone)  # گرفتن توکن‌های کاربر
    await send_push_to_tokens(tokens, title, body, data)  # ارسال

# -------------------- App & CORS --------------------
app = FastAPI()  # نمونه اپ
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # مبداها
app.add_middleware(  # افزودن CORS
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Startup/Shutdown --------------------
@app.on_event("startup")  # رویداد=شروع
async def startup():  # تابع=راه‌اندازی
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # موتور sync
    Base.metadata.create_all(engine)  # ساخت جداول
    with engine.begin() as conn:  # تراکنش
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # تضمین ستون
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place TEXT DEFAULT 'client';"))  # تضمین ستون
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS execution_start TIMESTAMPTZ NULL;"))  # تضمین ستون execution_start
    await database.connect()  # اتصال DB

@app.on_event("shutdown")  # رویداد=پایان
async def shutdown():  # تابع=خاموشی
    await database.disconnect()  # قطع اتصال

# -------------------- Health --------------------
@app.get("/")  # مسیر=ریشه
def read_root():  # تابع=سلامتی
    return {"message": "Putzfee FastAPI Server is running!"}  # پاسخ

# -------------------- Push endpoints --------------------
@app.post("/push/register")  # مسیر=ثبت توکن پوش
async def register_push_token(body: PushRegister, request: Request):  # تابع=ثبت/به‌روزرسانی
    now = datetime.now(timezone.utc)  # اکنون
    sel = DeviceTokenTable.__table__.select().where(DeviceTokenTable.token == body.token)  # انتخاب توکن
    row = await database.fetch_one(sel)  # اجرا
    if row is None:  # عدم وجود
        ins = DeviceTokenTable.__table__.insert().values(token=body.token, role=body.role, platform=body.platform, user_phone=body.user_phone, created_at=now, updated_at=now)  # درج
        await database.execute(ins)  # اجرا
    else:  # وجود دارد
        upd = DeviceTokenTable.__table__.update().where(DeviceTokenTable.id == row["id"]).values(role=body.role, platform=body.platform, user_phone=body.user_phone or row["user_phone"], updated_at=now)  # آپدیت
        await database.execute(upd)  # اجرا
    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": body.role})  # پاسخ

# -------------------- Auth/User --------------------
@app.get("/users/exists")  # مسیر=بررسی وجود کاربر
async def user_exists(phone: str):  # تابع=exists
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # کوئری
    count = await database.fetch_val(q)  # اجرا
    exists = bool(count and int(count) > 0)  # تبدیل به بولین
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ

@app.post("/register_user")  # مسیر=ثبت‌نام
async def register_user(user: UserRegisterRequest):  # تابع=ثبت‌نام
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # بررسی تکرار
    count = await database.fetch_val(q)  # اجرا
    if count and int(count) > 0:  # وجود کاربر
        raise HTTPException(status_code=400, detail="User already exists")  # خطا
    password_hash = bcrypt_hash_password(user.password)  # هش bcrypt
    ins = UserTable.__table__.insert().values(phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[])  # درج کاربر
    await database.execute(ins)  # اجرا
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ

@app.post("/login")  # مسیر=ورود
async def login_user(user: UserLoginRequest, request: Request):  # تابع=ورود
    now = datetime.now(timezone.utc)  # اکنون
    client_ip = get_client_ip(request)  # IP
    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))  # رکورد تلاش
    attempt_row = await database.fetch_one(sel_attempt)  # اجرا
    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:  # قفل فعال
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())  # زمان باقی
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after})  # خطا
    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user:  # نبود کاربر
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})  # خطا
    if not verify_password_secure(user.password, db_user["password_hash"]):  # رمز غلط
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD"})  # خطا
    await _register_login_success(user.phone, client_ip)  # ثبت موفق
    if not db_user["password_hash"].startswith("$2"):  # هش قدیمی
        new_hash = bcrypt_hash_password(user.password)  # هش جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # آپدیت
        await database.execute(upd)  # اجرا
    access_token = create_access_token(db_user["phone"])  # ساخت دسترسی
    refresh_token = create_refresh_token()  # ساخت رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # هش رفرش
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # انقضا
    ins_rt = RefreshTokenTable.__table__.insert().values(user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False)  # درج رفرش
    await database.execute(ins_rt)  # اجرا
    mapping = getattr(db_user, "_mapping", {})  # سازگاری RowMapping
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس
    return {"status": "ok", "access_token": access_token, "refresh_token": refresh_token, "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}}  # پاسخ

async def _register_login_failure(phone: str, ip: str):  # تابع=ثبت شکست
    now = datetime.now(timezone.utc)  # اکنون
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # رکورد
    row = await database.fetch_one(sel)  # اجرا
    if row is None:  # نبود رکورد
        ins = LoginAttemptTable.__table__.insert().values(phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now)  # درج
        await database.execute(ins); return  # اجرا و خروج
    window_start = row["window_start"] or now  # شروع پنجره
    within = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS  # داخل پنجره
    new_count = (row["attempt_count"] + 1) if within else 1  # شمارش
    new_window_start = window_start if within else now  # شروع جدید
    locked_until = row["locked_until"]  # قفل فعلی
    if new_count >= LOGIN_MAX_ATTEMPTS:  # عبور از حد
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # تنظیم قفل
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now)  # آپدیت
    await database.execute(upd)  # اجرا

async def _register_login_success(phone: str, ip: str):  # تابع=ثبت موفق
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # رکورد
    row = await database.fetch_one(sel)  # اجرا
    if row:  # وجود رکورد
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None)  # ریست
        await database.execute(upd)  # اجرا

@app.post("/auth/refresh")  # مسیر=رفرش
async def refresh_access_token(req: Dict):  # تابع=رفرش
    refresh_token = req.get("refresh_token", "")  # خواندن رفرش
    if not refresh_token:  # تهی؟
        raise HTTPException(status_code=400, detail="refresh_token required")  # خطا
    token_hash = hash_refresh_token(refresh_token)  # هش
    now = datetime.now(timezone.utc)  # اکنون
    sel = RefreshTokenTable.__table__.select().where((RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now))  # انتخاب
    rt = await database.fetch_one(sel)  # اجرا
    if not rt:  # نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user:  # نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا
    new_access = create_access_token(db_user["phone"])  # تولید دسترسی
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # پاسخ

# -------------------- Notifications --------------------
@app.get("/user/{phone}/notifications")  # مسیر=لیست اعلان‌ها
async def get_notifications(phone: str, only_unread: bool = True, limit: int = 50, offset: int = 0):  # تابع=اعلان‌ها
    base_sel = NotificationTable.__table__.select().where(NotificationTable.user_phone == phone)  # انتخاب
    if only_unread:  # فیلتر
        base_sel = base_sel.where(NotificationTable.read == False)  # شرط
    base_sel = base_sel.order_by(NotificationTable.created_at.desc()).limit(limit).offset(offset)  # مرتب‌سازی/صفحه‌بندی
    rows = await database.fetch_all(base_sel)  # اجرا
    items = [dict(r) for r in rows]  # تبدیل به dict
    return unified_response("ok", "NOTIFICATIONS", "user notifications", {"items": items})  # پاسخ

@app.post("/user/{phone}/notifications/{notif_id}/read")  # مسیر=خوانده‌شدن
async def mark_notification_read(phone: str, notif_id: int):  # تابع=خوانده‌شدن
    now = datetime.now(timezone.utc)  # اکنون
    upd = NotificationTable.__table__.update().where((NotificationTable.id == notif_id) & (NotificationTable.user_phone == phone)).values(read=True, read_at=now)  # آپدیت
    await database.execute(upd)  # اجرا
    return unified_response("ok", "NOTIF_READ", "notification marked as read", {"id": notif_id})  # پاسخ

@app.post("/user/{phone}/notifications/mark_all_read")  # مسیر=همه خوانده
async def mark_all_notifications_read(phone: str):  # تابع=همه خوانده
    now = datetime.now(timezone.utc)  # اکنون
    upd = NotificationTable.__table__.update().where((NotificationTable.user_phone == phone) & (NotificationTable.read == False)).values(read=True, read_at=now)  # آپدیت
    await database.execute(upd)  # اجرا
    return unified_response("ok", "NOTIFS_READ_ALL", "all notifications marked as read", {})  # پاسخ

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")  # مسیر=ماشین‌ها
async def get_user_cars(user_phone: str):  # تابع=ماشین‌ها
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # انتخاب
    user = await database.fetch_one(query)  # اجرا
    if not user:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    items = user["car_list"] or []  # لیست
    return unified_response("ok", "USER_CARS", "user cars", {"items": items})  # پاسخ

@app.post("/user_cars")  # مسیر=آپدیت ماشین‌ها
async def update_user_cars(data: CarListUpdateRequest):  # تابع=آپدیت
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # یافتن کاربر
    user = await database.fetch_one(sel)  # اجرا
    if not user:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(car_list=[car.dict() for car in data.car_list])  # آپدیت
    await database.execute(upd)  # اجرا
    return unified_response("ok", "CARS_SAVED", "cars saved", {"count": len(data.car_list)})  # پاسخ

# -------------------- Orders --------------------
@app.post("/order")  # مسیر=ثبت سفارش
async def create_order(order: OrderRequest):  # تابع=ایجاد سفارش
    ins = RequestTable.__table__.insert().values(  # درج
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
    ).returning(RequestTable.id)  # بازگردانی id
    row = await database.fetch_one(ins)  # اجرا
    new_id = row[0] if isinstance(row, (tuple, list)) else (row["id"] if row else None)  # استخراج id
    try:  # try
        await send_push_to_managers("درخواست جدید", "درخواست جدید ثبت شد.", {"type": "new_request", "order_id": str(new_id)})  # پوش مدیر
    except Exception:  # خطا
        pass  # نادیده
    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # پاسخ

@app.post("/cancel_order")  # مسیر=لغو سفارش
async def cancel_order(cancel: CancelRequest):  # تابع=لغو
    upd = (RequestTable.__table__.update().where((RequestTable.user_phone == cancel.user_phone) & (RequestTable.service_type == cancel.service_type) & (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))).values(status="CANCELED", scheduled_start=None).returning(RequestTable.id))  # آپدیت
    rows = await database.fetch_all(upd)  # اجرا
    if rows and len(rows) > 0:  # وجود حداقل یک رکورد
        try:  # try
            for r in rows:  # حلقه
                oid = None  # شناسه
                mapping = getattr(r, "_mapping", None)  # mapping
                if mapping and "id" in mapping:  # کلید id
                    oid = mapping["id"]  # شناسه
                elif isinstance(r, (tuple, list)) and len(r) > 0:  # تاپل/لیست
                    oid = r[0]  # شناسه
                await send_push_to_managers("لغو درخواست", "کاربر سفارش را لغو کرد.", {"type": "order_canceled", "order_id": str(oid) if oid is not None else ""})  # پوش مدیر
        except Exception:  # خطا
            pass  # نادیده
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # پاسخ
    raise HTTPException(status_code=404, detail="active order not found")  # خطا

@app.get("/user_active_services/{user_phone}")  # مسیر=سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # تابع=سفارش‌های فعال
    sel = RequestTable.__table__.select().where((RequestTable.user_phone == user_phone) & (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"])))  # انتخاب
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # دیکشنری
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # پاسخ

@app.get("/user_orders/{user_phone}")  # مسیر=تاریخچه کاربر
async def get_user_orders(user_phone: str):  # تابع=سفارش‌های کاربر
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # انتخاب
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # دیکشنری
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # پاسخ

# -------------------- Scheduling (1 hour slots) --------------------
@app.get("/provider/{provider_phone}/free_hours")  # مسیر=ساعات آزاد
async def get_free_hours(provider_phone: str, date: str, work_start: int = 8, work_end: int = 20, limit: int = 24):  # تابع=ساعات آزاد
    try:  # try
        d = datetime.fromisoformat(date).date()  # پارس تاریخ
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # خطا
    if not (0 <= work_start < 24 and 0 <= work_end <= 24 and work_start < work_end):  # اعتبارسنجی ساعت
        raise HTTPException(status_code=400, detail="invalid work hours")  # خطا
    provider = provider_phone.strip()  # تمیز
    if not provider or provider.lower() == "any":  # اعتبارسنجی شماره سرویس‌گیرنده
        raise HTTPException(status_code=400, detail="invalid provider_phone")  # خطا
    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)  # شروع روز
    day_end = datetime(d.year, d.month, d.day, work_end, 0, tzinfo=timezone.utc)  # پایان روز
    results: List[str] = []  # خروجی
    cur = day_start  # زمان جاری
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:  # حلقه تولید اسلات
        s, e = cur, cur + timedelta(hours=1)  # بازه
        if await provider_is_free(provider, s, e):  # آزاد بودن provider
            results.append(s.isoformat())  # افزودن
        cur = cur + timedelta(hours=1)  # بعدی
    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})  # پاسخ

@app.get("/busy_slots")  # مسیر=ساعات مشغول
async def get_busy_slots(provider_phone: str, date: str, exclude_order_id: Optional[int] = None):  # تابع=busy
    try:  # try
        d = datetime.fromisoformat(date).date()  # تاریخ
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # خطا
    provider = provider_phone.strip()  # provider=شماره سرویس‌گیرنده
    if not provider or provider.lower() == "any":  # اعتبارسنجی provider
        raise HTTPException(status_code=400, detail="invalid provider_phone")  # خطا
    day_start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)  # شروع
    day_end = day_start + timedelta(days=1)  # پایان
    sel_sched = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.slot_start >= day_start) & (ScheduleSlotTable.slot_start < day_end) & (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) & (ScheduleSlotTable.provider_phone == provider))  # انتخاب فقط همین provider
    if exclude_order_id is not None:  # حذف سفارش جاری
        sel_sched = sel_sched.where(ScheduleSlotTable.request_id != exclude_order_id)  # شرط
    rows_sched = await database.fetch_all(sel_sched)  # اجرا
    sel_app = AppointmentTable.__table__.select().where((AppointmentTable.start_time >= day_start) & (AppointmentTable.start_time < day_end) & (AppointmentTable.status == "BOOKED") & (AppointmentTable.provider_phone == provider))  # رزرو قطعی همان provider (بازدید/اجرا)
    rows_app = await database.fetch_all(sel_app)  # اجرا
    busy: set[str] = set()  # مجموعه busy
    for r in rows_sched:  # حلقه اسلات‌ها
        busy.add(r["slot_start"].isoformat())  # افزودن
    for r in rows_app:  # حلقه رزروها
        busy.add(r["start_time"].isoformat())  # افزودن
    items = sorted(busy)  # مرتب‌سازی
    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": items})  # پاسخ

@app.post("/order/{order_id}/propose_slots")  # مسیر=پیشنهاد اسلات‌ها (مدیر)
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):  # تابع=ثبت اسلات
    require_admin(request)  # احراز هویت ادمین
    provider = (body.provider_phone or "").strip()  # provider=شماره سرویس‌گیرنده
    if not provider or provider.lower() == "any":  # اعتبارسنجی provider
        raise HTTPException(status_code=400, detail="invalid provider_phone")  # خطا provider
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == order_id))  # یافتن سفارش
    if not req:  # نبود سفارش
        raise HTTPException(status_code=404, detail="order not found")  # خطا
    accepted: List[str] = []  # لیست پذیرفته‌ها
    for s in body.slots[:3]:  # حداکثر ۳ اسلات
        start = parse_iso(s)  # پارس ISO
        end = start + timedelta(hours=1)  # پایان
        if await provider_is_free(provider, start, end):  # آزاد بودن
            await database.execute(ScheduleSlotTable.__table__.insert().values(request_id=order_id, provider_phone=provider, slot_start=start, status="PROPOSED", created_at=datetime.now(timezone.utc)))  # درج
            accepted.append(start.isoformat())  # افزودن
    if accepted:  # وجود اسلات
        await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="WAITING", driver_phone=provider, scheduled_start=None))  # وضعیت WAITING
        try:  # try
            await notify_user(req["user_phone"], "زمان‌بندی بازدید", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.", data={"type": "visit_slots", "order_id": order_id, "slots": accepted})  # اعلان DB
            await send_push_to_user(req["user_phone"], "زمان‌بندی بازدید", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.", data={"type": "visit_slots", "order_id": order_id})  # پوش کاربر
        except Exception:  # خطا
            pass  # نادیده
    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # پاسخ

@app.get("/order/{order_id}/proposed_slots")  # مسیر=خواندن اسلات‌های پیشنهادی
async def get_proposed_slots(order_id: int):  # تابع=خواندن
    sel = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")).order_by(ScheduleSlotTable.slot_start.asc())  # انتخاب
    rows = await database.fetch_all(sel)  # اجرا
    items = [r["slot_start"].isoformat() for r in rows]  # استخراج ISO
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})  # پاسخ

@app.post("/order/{order_id}/confirm_slot")  # مسیر=تأیید اسلات (کاربر)
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):  # تابع=تأیید
    chosen_start = parse_iso(body.slot)  # پارس
    sel_slot = ScheduleSlotTable.__table__.select().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.slot_start == chosen_start) & (ScheduleSlotTable.status == "PROPOSED"))  # یافتن
    slot = await database.fetch_one(sel_slot)  # اجرا
    if not slot:  # نبود
        raise HTTPException(status_code=404, detail="slot not found or not proposed")  # خطا
    provider_phone = slot["provider_phone"]  # provider
    start = slot["slot_start"]  # شروع
    end = start + timedelta(hours=1)  # پایان
    if not await provider_is_free(provider_phone, start, end):  # مشغول
        await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="REJECTED"))  # رد
        raise HTTPException(status_code=409, detail="slot no longer available")  # خطا
    await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="ACCEPTED"))  # قبول
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED") & (ScheduleSlotTable.id != slot["id"])).values(status="REJECTED"))  # رد سایرین
    await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)))  # درج نوبت
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(scheduled_start=start, status="ASSIGNED", driver_phone=provider_phone))  # به‌روزرسانی سفارش
    try:  # try
        await send_push_to_managers("تأیید زمان بازدید", "کاربر زمان بازدید را تأیید کرد.", {"type": "time_confirm", "order_id": str(order_id)})  # پوش مدیر
    except Exception:  # خطا
        pass  # نادیده
    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})  # پاسخ

@app.post("/order/{order_id}/reject_all_and_cancel")  # مسیر=رد همه و کنسل
async def reject_all_and_cancel(order_id: int):  # تابع=رد+کنسل
    await database.execute(ScheduleSlotTable.__table__.update().where((ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")).values(status="REJECTED"))  # رد همه
    upd = RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="CANCELED", scheduled_start=None).returning(RequestTable.id)  # آپدیت سفارش
    await database.fetch_all(upd)  # اجرا
    try:  # try
        await send_push_to_managers("لغو درخواست", "کاربر سفارش را لغو کرد.", {"type": "order_canceled", "order_id": str(order_id)})  # پوش مدیر
    except Exception:  # خطا
        pass  # نادیده
    return unified_response("ok", "ORDER_CANCELED", "order canceled after rejecting proposals", {"id": order_id})  # پاسخ

# -------------------- Admin/Workflow --------------------
@app.get("/admin/requests/active")  # مسیر=لیست سفارش‌های فعال (ادمین)
async def admin_active_requests(request: Request):  # تابع=فعال‌ها
    require_admin(request)  # احراز ادمین
    active = ["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]  # وضعیت‌های فعال
    sel = RequestTable.__table__.select().where(RequestTable.status.in_(active)).order_by(RequestTable.id.desc())  # انتخاب
    rows = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in rows]  # تبدیل
    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": items})  # پاسخ

@app.post("/admin/order/{order_id}/price")  # مسیر=ثبت قیمت (ادمین)
async def admin_set_price_and_status(order_id: int, body: PriceBody, request: Request):  # تابع=قیمت
    require_admin(request)  # احراز ادمین
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن سفارش
    req = await database.fetch_one(sel)  # اجرا
    if not req:  # نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا

    new_status = "IN_PROGRESS" if body.agree else "CANCELED"  # وضعیت جدید
    values = {"price": body.price, "status": new_status}  # values=مقادیر آپدیت پایه

    exec_iso = (body.exec_time or "").strip()  # exec_iso=رشته ISO
    if body.agree and exec_iso:  # ثبت زمان اجرا
        start = parse_iso(exec_iso)  # start=پارس ISO
        end = start + timedelta(hours=1)  # end=یک ساعت بعد
        provider_phone = (req["driver_phone"] or "").strip()  # provider_phone=شماره سرویس‌گیرنده
        if not provider_phone:  # نبود provider
            raise HTTPException(status_code=400, detail="driver_phone required for execution")  # خطا
        free = await provider_is_free(provider_phone, start, end)  # free=آزاد بودن بازه
        if not free:  # مشغول
            raise HTTPException(status_code=409, detail="execution slot busy")  # خطا
        await database.execute(AppointmentTable.__table__.insert().values(provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)))  # رزرو اجرا
        values["execution_start"] = start  # ثبت execution_start
        try:  # try
            await notify_user(req["user_phone"], "تعیین قیمت و زمان اجرا", "قیمت و زمان اجرای کار تعیین شد.", data={"type": "execution_time", "order_id": order_id, "start": start.isoformat(), "price": body.price})  # اعلان DB
            await send_push_to_user(req["user_phone"], "تعیین قیمت و زمان اجرا", "قیمت و زمان اجرای کار تعیین شد.", data={"type": "execution_time", "order_id": order_id})  # پوش کاربر
        except Exception:  # خطا
            pass  # نادیده
    elif body.agree:  # فقط قیمت بدون زمان اجرا
        try:  # try
            await notify_user(req["user_phone"], "تعیین قیمت", "قیمت سرویس تعیین شد.", data={"type": "price_set", "order_id": order_id, "price": body.price})  # اعلان DB
            await send_push_to_user(req["user_phone"], "تعیین قیمت", "قیمت سرویس تعیین شد.", data={"type": "price_set", "order_id": order_id})  # پوش کاربر
        except Exception:  # خطا
            pass  # نادیده

    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(**values))  # آپدیت سفارش
    resp = {"order_id": order_id, "price": body.price, "status": new_status, "execution_start": values.get("execution_start").isoformat() if values.get("execution_start") else None}  # resp=خروجی
    return unified_response("ok", "PRICE_SET", "price and status updated", resp)  # پاسخ

@app.post("/order/{order_id}/start")  # مسیر=شروع
async def start_order(order_id: int, request: Request):  # تابع=شروع
    require_admin(request)  # احراز ادمین
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن
    req = await database.fetch_one(sel)  # اجرا
    if not req:  # نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="STARTED"))  # آپدیت
    return unified_response("ok", "ORDER_STARTED", "order started", {"order_id": order_id, "status": "STARTED"})  # پاسخ

@app.post("/order/{order_id}/finish")  # مسیر=پایان
async def finish_order(order_id: int, request: Request):  # تابع=پایان
    require_admin(request)  # احراز ادمین
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن
    req = await database.fetch_one(sel)  # اجرا
    if not req:  # نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا
    now_iso = datetime.now(timezone.utc).isoformat()  # زمان ISO
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="FINISH", finish_datetime=now_iso))  # آپدیت
    try:  # try
        await notify_user(req["user_phone"], "اتمام کار", "کار با موفقیت به پایان رسید.", data={"type": "work_finished", "order_id": order_id})  # اعلان DB
        await send_push_to_user(req["user_phone"], "اتمام کار", "کار با موفقیت به پایان رسید.", data={"type": "work_finished", "order_id": order_id})  # پوش کاربر
    except Exception:  # خطا
        pass  # نادیده
    return unified_response("ok", "ORDER_FINISHED", "order finished", {"order_id": order_id, "status": "FINISH"})  # پاسخ

# -------------------- Profile --------------------
@app.post("/user/profile")  # مسیر=ذخیره پروفایل
async def update_profile(body: UserProfileUpdate):  # تابع=آپدیت
    if not body.phone.strip():  # اعتبارسنجی شماره
        raise HTTPException(status_code=400, detail="phone_required")  # خطا
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # یافتن
    user = await database.fetch_one(sel)  # اجرا
    if user is None:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    await database.execute(UserTable.__table__.update().where(UserTable.phone == body.phone).values(name=body.name.strip(), address=body.address.strip()))  # آپدیت
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # پاسخ

@app.get("/user/profile/{phone}")  # مسیر=خواندن پروفایل
async def get_user_profile(phone: str):  # تابع=خواندن
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # انتخاب
    db_user = await database.fetch_one(sel)  # اجرا
    if db_user is None:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    mapping = getattr(db_user, "_mapping", {})  # RowMapping
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {"phone": db_user["phone"], "name": name_val or "", "address": address_val or ""})  # پاسخ

@app.get("/debug/users")  # مسیر=دیباگ کاربران
async def debug_users():  # تابع=لیست کاربران
    rows = await database.fetch_all(UserTable.__table__.select())  # انتخاب همه
    out = []  # خروجی
    for r in rows:  # حلقه
        mapping = getattr(r, "_mapping", {})  # RowMapping
        name_val = mapping["name"] if "name" in mapping else ""  # نام
        address_val = mapping["address"] if "address" in mapping else ""  # آدرس
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})  # افزودن
    return out  # بازگشت
