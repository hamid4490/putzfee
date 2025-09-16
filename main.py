# -*- coding: utf-8 -*-
# FastAPI server (clean and focused on: orders + hourly scheduling)
import os  # ماژول متغیرهای محیطی و مسیرها
import hashlib  # هش‌کردن امن
import secrets  # تولید توکن‌های تصادفی امن
from datetime import datetime, timedelta, timezone, time as dtime  # واردکردن تاریخ/زمان | timedelta=بازه | timezone=منطقه زمانی | dtime=نام مستعار time
from typing import Optional, List, Dict  # نوع‌دهی | Optional=اختیاری | List=لیست | Dict=دیکشنری

import bcrypt  # هش پسورد
import jwt  # توکن JWT
from fastapi import FastAPI, HTTPException, Request, Header  # واردکردن کلاس‌های اصلی و Exception
from fastapi.middleware.cors import CORSMiddleware  # میان‌افزار برای اجازه دسترسی از مبداهای مختلف
from pydantic import BaseModel  # مدل‌های ورودی/خروجی

from sqlalchemy import (  # ORM/SQL
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_, text, UniqueConstraint  # ستون‌ها و توابع کوئری
)
from sqlalchemy.dialects.postgresql import JSONB  # نوع JSON باینری در PostgreSQL
from sqlalchemy.ext.declarative import declarative_base  # پایه ORM دکلراتیو
import sqlalchemy  # ماژول اصلی
from databases import Database  # کتابخانه async برای دسترسی DB
from dotenv import load_dotenv  # لود متغیرهای محیطی از فایل .env

# -------------------- Config --------------------
load_dotenv()  # بارگذاری متغیرهای محیطی از .env
DATABASE_URL = os.getenv("DATABASE_URL")  # خواندن URL پایگاه‌داده از محیط
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # کلید امضای JWT | مقدار پیش‌فرض=change-me-secret
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # فلفل برای پسورد | پیش‌فرض
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # مدت اعتبار توکن دسترسی (دقیقه)
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # مدت اعتبار رفرش توکن (روز)
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # تعداد دورهای bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # مبداهای مجاز CORS | پیش‌فرض=همه

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))  # پنجره زمانی شمارش تلاش (ثانیه)
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # حداکثر تلاش مجاز
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))  # مدت قفل پس از اتمام تلاش (ثانیه)

database = Database(DATABASE_URL)  # نمونه پایگاه‌داده async با آدرس داده‌شده
Base = declarative_base()  # کلاس پایه ORM برای تعریف جداول

# -------------------- ORM models --------------------
class UserTable(Base):  # تعریف=مدل جدول کاربران
    __tablename__ = "users"  # نام جدول users
    id = Column(Integer, primary_key=True, index=True)  # ستون کلید اصلی با ایندکس
    phone = Column(String, unique=True, index=True)  # شماره یکتا با ایندکس
    password_hash = Column(String)  # هش رمز
    address = Column(String)  # آدرس
    name = Column(String, default="")  # نام با پیش‌فرض خالی
    car_list = Column(JSONB, default=list)  # لیست ماشین‌ها به‌صورت JSONB

class DriverTable(Base):  # مدل=راننده‌ها
    __tablename__ = "drivers"  # نام جدول=drivers
    id = Column(Integer, primary_key=True, index=True)  # کلید اصلی
    first_name = Column(String)  # نام
    last_name = Column(String)  # نام خانوادگی
    photo_url = Column(String)  # آدرس عکس
    id_card_number = Column(String)  # کد ملی/شناسه
    phone = Column(String, unique=True, index=True)  # شماره یکتا
    phone_verified = Column(Boolean, default=False)  # تأیید شماره
    is_online = Column(Boolean, default=False)  # آنلاین بودن
    status = Column(String, default="فعال")  # وضعیت راننده

class RequestTable(Base):  # مدل=درخواست‌های سرویس
    __tablename__ = "requests"  # نام جدول=requests
    id = Column(Integer, primary_key=True, index=True)  # کلید اصلی
    user_phone = Column(String, index=True)  # شماره کاربر با ایندکس
    latitude = Column(Float)  # عرض جغرافیایی
    longitude = Column(Float)  # طول جغرافیایی
    car_list = Column(JSONB)  # لیست ماشین/خدمات انتخاب‌شده به‌صورت JSONB
    address = Column(String)  # آدرس
    home_number = Column(String, default="")  # پلاک منزل
    service_type = Column(String, index=True)  # نوع سرویس با ایندکس
    price = Column(Integer)  # قیمت
    request_datetime = Column(String)  # زمان ثبت
    status = Column(String)  # وضعیت سفارش PENDING/ACTIVE/CANCELED/DONE
    driver_name = Column(String)  # نام سفارش‌گیرنده
    driver_phone = Column(String)  # تلفن سفارش‌گیرنده
    finish_datetime = Column(String)  # زمان پایان
    payment_type = Column(String)  # نوع پرداخت
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # زمان شروع تأییدشده (اختیاری)
    service_place = Column(String, default="client")  # محل انجام سرویس (client/provider)
    
class RefreshTokenTable(Base):  # مدل=رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول=refresh_tokens
    id = Column(Integer, primary_key=True, index=True)  # کلید اصلی
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # ارجاع به users.id با ایندکس
    token_hash = Column(String, unique=True, index=True)  # هش رفرش‌توکن یکتا
    expires_at = Column(DateTime(timezone=True), index=True)  # انقضا با ایندکس
    revoked = Column(Boolean, default=False)  # ابطال‌شده؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # زمان ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # ایندکس مرکب

class LoginAttemptTable(Base):  # مدل=تلاش‌های ورود برای محدودسازی
    __tablename__ = "login_attempts"  # نام جدول=login_attempts
    id = Column(Integer, primary_key=True, index=True)  # کلید اصلی
    phone = Column(String, index=True)  # شماره با ایندکس
    ip = Column(String, index=True)  # آی‌پی با ایندکس
    attempt_count = Column(Integer, default=0)  # تعداد تلاش
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # شروع پنجره
    locked_until = Column(DateTime(timezone=True), nullable=True)  # قفل تا
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # آخرین تلاش
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)  # ایندکس مرکب phone+ip

class ScheduleSlotTable(Base):  # مدل=اسلات‌های پیشنهادی زمان
    __tablename__ = "schedule_slots"  # نام جدول=schedule_slots
    id = Column(Integer, primary_key=True, index=True)  # کلید اصلی
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # ارجاع به سفارش
    provider_phone = Column(String, index=True)  # شماره سفارش‌گیرنده
    slot_start = Column(DateTime(timezone=True), index=True)  # شروع بازه یک‌ساعته
    status = Column(String, default="PROPOSED")  # PROPOSED/ACCEPTED/REJECTED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # زمان ایجاد
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)  # ایندکس درخواست+وضعیت

class AppointmentTable(Base):  # مدل=نوبت‌های قطعی (رزرو نهایی)
    __tablename__ = "appointments"  # نام جدول=appointments
    id = Column(Integer, primary_key=True, index=True)  # کلید اصلی
    provider_phone = Column(String, index=True)  # شماره سفارش‌گیرنده
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # ارجاع به سفارش
    start_time = Column(DateTime(timezone=True), index=True)  # شروع رزرو
    end_time = Column(DateTime(timezone=True), index=True)  # پایان رزرو
    status = Column(String, default="BOOKED")  # BOOKED/CANCELLED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # زمان ایجاد
    __table_args__ = (  # قیدها/ایندکس‌ها
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),  # یکتا=برای جلوگیری از تداخل
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),  # ایندکس زمان‌ها
    )

# -------------------- Pydantic models --------------------
class CarInfo(BaseModel):  # مدل=ماشین ساده
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک

class Location(BaseModel):  # مدل=مختصات
    latitude: float  # عرض
    longitude: float  # طول

class CarOrderItem(BaseModel):  # مدل=آیتم سفارش کارواش با گزینه‌ها
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک
    wash_outside: bool = False  # روشویی
    wash_inside: bool = False  # توشویی
    polish: bool = False  # پولیش
    
class OrderRequest(BaseModel):  # مدل=درخواست ثبت سفارش
    user_phone: str  # شماره کاربر
    location: Location  # مختصات
    car_list: List[CarOrderItem]  # لیست ماشین‌ها با گزینه‌های انتخابی
    address: str  # آدرس
    home_number: Optional[str] = ""  # پلاک
    service_type: str  # نوع سرویس
    price: int  # قیمت
    request_datetime: str  # زمان ثبت (ISO)
    payment_type: str  # نوع پرداخت
    service_place: str  # محل سرویس (client/provider)

class CarListUpdateRequest(BaseModel):  # مدل=به‌روزرسانی لیست ماشین کاربر
    user_phone: str  # شماره کاربر
    car_list: List[CarInfo]  # لیست ماشین‌های ساده (پروفایل)

class CancelRequest(BaseModel):  # مدل=درخواست کنسل کردن
    user_phone: str  # شماره کاربر
    service_type: str  # نوع سرویس

class UserRegisterRequest(BaseModel):  # مدل=ثبت‌نام کاربر
    phone: str  # شماره
    password: str  # رمز
    address: Optional[str] = None  # آدرس اختیاری

class UserLoginRequest(BaseModel):  # مدل=ورود کاربر
    phone: str  # شماره
    password: str  # رمز

class UserProfileUpdate(BaseModel):  # مدل=به‌روزرسانی پروفایل
    phone: str  # شماره
    name: str = ""  # نام
    address: str = ""  # آدرس

# زمان‌بندی
class ProposedSlotsRequest(BaseModel):  # مدل=درخواست پیشنهاد اسلات‌های زمانی
    provider_phone: str  # شماره سفارش‌گیرنده
    slots: List[str]  # رشته‌های ISO شروع بازه‌های یک‌ساعته (حداکثر ۳)

class ConfirmSlotRequest(BaseModel):  # مدل=تأیید یک اسلات
    slot: str  # شروع ISO بازه یک‌ساعته انتخاب‌شده

# ⭐⭐⭐ مدل جدید برای endpoint قیمت ⭐⭐⭐
class PriceBody(BaseModel):  # مدل=بدنه قیمت و توافق
    price: int  # قیمت
    agree: bool  # توافق کاربر

# -------------------- Security helpers --------------------
def bcrypt_hash_password(password: str) -> str:  # تابع=تولید هش bcrypt با فلفل
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # نمک با تعداد دور تنظیم‌شده
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # پسورد+pepper به UTF-8
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # برگشت=هش bcrypt به str

def verify_password_secure(password: str, stored_hash: str) -> bool:  # تابع=راستی‌آزمایی رمز با پشتیبانی از قدیمی
    try:  # گرفتن استثناء
        if stored_hash.startswith("$2"):  # اگر=فرمت bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # پسورد+pepper
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # checkpw=راستی‌آزمایی bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # هش sha256 قدیمی
        return old == stored_hash  # مقایسه=برابر؟
    except Exception:  # هر خطا
        return False  # برگشت=false

def create_access_token(phone: str) -> str:  # تابع=ساخت JWT دسترسی
    now = datetime.now(timezone.utc)  # اکنون UTC
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # زمان انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # محتوای توکن
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # encode=امضای JWT

def create_refresh_token() -> str:  # تابع=ساخت رفرش‌توکن تصادفی
    return secrets.token_urlsafe(48)  # برگشت=توکن امن ۴۸ کاراکتری

def hash_refresh_token(token: str) -> str:  # تابع=هش رفرش‌توکن با pepper
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # برگشت=هش sha256

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # تابع=قالب پاسخ یکپارچه
    return {"status": status, "code": code, "message": message, "data": data or {}}  # برگشت=دیکشنری پاسخ

# -------------------- Utils --------------------
def get_client_ip(request: Request) -> str:  # تابع=گرفتن IP کلاینت پشت پراکسی
    xff = request.headers.get("x-forwarded-for", "")  # هدر x-forwarded-for
    if xff:  # اگر=هدر موجود
        return xff.split(",")[0].strip()  # برگشت=اولین IP در لیست
    return request.client.host or "unknown"  # برگشت=IP مستقیم یا unknown

def parse_iso(ts: str) -> datetime:  # تابع=پارس رشته ISO به datetime آگاه به منطقه
    # "2025-09-09T10:00:00Z" → tz-aware UTC  # توضیح=فرمت ورودی
    try:  # خطاگیری
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))  # پارس با جایگزینی Z به +00:00
    except Exception:  # خطای پارس
        raise HTTPException(status_code=400, detail=f"invalid datetime: {ts}")  # پرتاب=بدون فرمت معتبر
    if dt.tzinfo is None:  # اگر=بدون tzinfo
        dt = dt.replace(tzinfo=timezone.utc)  # تنظیم=UTC
    return dt.astimezone(timezone.utc)  # برگشت=UTC

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:  # تابع=بررسی خالی بودن بازه
    # فقط رزروهای نهایی BOOKED به عنوان اشغال در نظر گرفته می‌شوند (ساده و مطابق نیاز)  # توضیح
    q = AppointmentTable.__table__.select().where(  # q=کوئری انتخاب
        (AppointmentTable.provider_phone == provider_phone) &  # شرط=شماره سفارش‌گیرنده
        (AppointmentTable.status == "BOOKED") &  # شرط=وضعیت رزرو نهایی
        (AppointmentTable.start_time < end) &  # شرط=شروع کمتر از پایان انتخابی
        (AppointmentTable.end_time > start)  # شرط=پایان بیشتر از شروع انتخابی
    )
    rows = await database.fetch_all(q)  # خواندن نتایج
    return len(rows) == 0  # برگشت=خالی بودن بازه

async def notify_user(phone: str, title: str, body: str):  # تابع=ارسال نوتیفیکیشن (جایگزین سرویس واقعی)
    # در اینجا سرویس نوتیفیکیشن (FCM/...) خود را صدا بزنید.  # توضیح=پلیس‌هولدر
    pass  # بدون پیاده‌سازی

# -------------------- App & CORS --------------------
app = FastAPI()  # ایجاد برنامه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # لیست مبداهای مجاز
app.add_middleware(  # افزودن=میان‌افزار CORS
    CORSMiddleware,  # کلاس میان‌افزار
    allow_origins=allow_origins,  # مبداها
    allow_credentials=True,  # اجازه کوکی/اعتبار
    allow_methods=["*"],  # همه متدها
    allow_headers=["*"],  # همه هدرها
)

# -------------------- Startup/Shutdown --------------------
@app.on_event("startup")  # دکوریتور=رویداد شروع
async def startup():  # تابع=راه‌اندازی
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # ایجاد موتور sync برای create_all
    Base.metadata.create_all(engine)  # create_all=ایجاد جداول در صورت نبودن
    # اطمینان از ستون‌های جدید (اگر قبلاً جدول ساخته شده باشد)  # توضیح
    with engine.begin() as conn:  # شروع تراکنش
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # افزودن ستون scheduled_start
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place TEXT DEFAULT 'client';"))  # افزودن ستون service_place با پیش‌فرض
    await database.connect()  # اتصال=به پایگاه‌داده async

@app.on_event("shutdown")  # دکوریتور=رویداد خاتمه
async def shutdown():  # تابع=خاموشی
    await database.disconnect()  # قطع=اتصال پایگاه‌داده

# -------------------- Health --------------------
@app.get("/")  # مسیر=ریشه
def read_root():  # تابع=سلامتی
    return {"message": "Putzfee FastAPI Server is running!"}  # برگشت=پیام وضعیت

# -------------------- Auth/User --------------------
@app.get("/users/exists")  # مسیر=وجود کاربر
async def user_exists(phone: str):  # تابع=بررسی وجود کاربر با phone
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # q=کوئری شمارش
    count = await database.fetch_val(q)  # خواندن مقدار
    exists = bool(count and int(count) > 0)  # تبدیل به بولین
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # برگشت=پاسخ استاندارد

@app.post("/register_user")  # مسیر=ثبت‌نام کاربر
async def register_user(user: UserRegisterRequest):  # تابع=ثبت‌نام
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # q=بررسی تکرار
    count = await database.fetch_val(q)  # خواندن
    if count and int(count) > 0:  # شرط=وجود کاربر
        raise HTTPException(status_code=400, detail="User already exists")  # خطا=کاربر موجود
    password_hash = bcrypt_hash_password(user.password)  # هش رمز
    ins = UserTable.__table__.insert().values(  # اینزرت کاربر
        phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[]  # مقادیر=فیلدها
    )
    await database.execute(ins)  # اجرا=اینزرت
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # برگشت=ثبت موفق

@app.post("/login")  # مسیر=ورود
async def login_user(user: UserLoginRequest, request: Request):  # تابع=ورود با محدودسازی تلاش
    client_ip = get_client_ip(request)  # گرفتن آی‌پی کلاینت
    now = datetime.now(timezone.utc)  # اکنون UTC

    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))  # کوئری تلاش قبلی
    attempt_row = await database.fetch_one(sel_attempt)  # خواندن
    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:  # قفل=بررسی فعال بودن
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())  # زمان باقی‌مانده
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after, "window_seconds": LOGIN_WINDOW_SECONDS})  # خطا=محدودیت

    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # نتیجه
    if not db_user:  # نبود=کاربر
        await _register_login_failure(user.phone, client_ip)  # ثبت=شکست
        updated = await database.fetch_one(LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip)))  # رکورد جدید/به‌روز
        remaining = max(0, LOGIN_MAX_ATTEMPTS - int(updated["attempt_count"] or 0)) if updated else 0  # تلاش باقی
        lock_remaining = int((updated["locked_until"] - now).total_seconds()) if updated and updated["locked_until"] and updated["locked_until"] > now else 0  # زمان قفل
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND", "remaining_attempts": remaining, "lock_remaining": lock_remaining, "window_seconds": LOGIN_WINDOW_SECONDS})  # خطا=کاربر نیست

    if not verify_password_secure(user.password, db_user["password_hash"]):  # بررسی=رمز صحیح؟
        await _register_login_failure(user.phone, client_ip)  # ثبت=شکست
        updated = await database.fetch_one(LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip)))  # آخرین وضعیت
        remaining = max(0, LOGIN_MAX_ATTEMPTS - int(updated["attempt_count"] or 0)) if updated else 0  # باقی
        lock_remaining = int((updated["locked_until"] - now).total_seconds()) if updated and updated["locked_until"] and updated["locked_until"] > now else 0  # زمان قفل
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": remaining, "lock_remaining": lock_remaining, "window_seconds": LOGIN_WINDOW_SECONDS})  # خطا=رمز غلط

    await _register_login_success(user.phone, client_ip)  # ثبت=موفقیت و ریست شمارنده

    if not db_user["password_hash"].startswith("$2"):  # ارتقا=هش قدیمی به bcrypt
        new_hash = bcrypt_hash_password(user.password)  # bcrypt جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # به‌روزرسانی
        await database.execute(upd)  # اجرا=آپدیت

    access_token = create_access_token(db_user["phone"])  # ساخت توکن دسترسی
    refresh_token = create_refresh_token()  # ساخت رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # هش رفرش
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # انقضا رفرش
    ins_rt = RefreshTokenTable.__table__.insert().values(user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False)  # اینزرت رفرش
    await database.execute(ins_rt)  # اجرا=اینزرت

    mapping = getattr(db_user, "_mapping", {})  # سازگاری با RowMapping
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس

    return {  # برگشت=پاسخ ورود
        "status": "ok", "message": "Login successful", "token": access_token, "access_token": access_token,  # فیلدها=توکن‌ها
        "refresh_token": refresh_token,  # رفرش خام
        "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}  # اطلاعات کاربر
    }

async def _register_login_failure(phone: str, ip: str):  # تابع=ثبت تلاش ناموفق
    now = datetime.now(timezone.utc)  # اکنون
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # پیدا کردن رکورد
    row = await database.fetch_one(sel)  # رکورد
    if row is None:  # نبود=رکورد
        ins = LoginAttemptTable.__table__.insert().values(phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now)  # ایجاد رکورد
        await database.execute(ins); return  # اجرا=اینزرت؛ برگشت
    window_start = row["window_start"] or now  # شروع پنجره
    within = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS  # داخل پنجره
    new_count = (row["attempt_count"] + 1) if within else 1  # افزایش یا ریست
    new_window_start = window_start if within else now  # شروع جدید
    locked_until = row["locked_until"]  # مقدار فعلی
    if new_count >= LOGIN_MAX_ATTEMPTS:  # شرط=فراتر از حد
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # تمدید قفل
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(  # به‌روزرسانی رکورد
        attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now  # مقادیر=جدید
    )
    await database.execute(upd)  # اجرا=آپدیت

async def _register_login_success(phone: str, ip: str):  # تابع=ثبت موفقیت و ریست
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # یافتن رکورد
    row = await database.fetch_one(sel)  # نتیجه
    if row:  # وجود=رکورد
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(  # ریست شمارنده
            attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None  # مقادیر=ریست شده
        )
        await database.execute(upd)  # اجرا=آپدیت

@app.post("/auth/refresh")  # مسیر=رفرش توکن دسترسی
async def refresh_access_token(req: Dict):  # تابع=دریافت رفرش و تولید دسترسی
    refresh_token = req.get("refresh_token", "")  # گرفتن از بدنه
    if not refresh_token:  # بررسی=خالی بودن
        raise HTTPException(status_code=400, detail="refresh_token required")  # خطا=نیاز به رفرش
    token_hash = hash_refresh_token(refresh_token)  # هش رفرش
    now = datetime.now(timezone.utc)  # اکنون
    sel = RefreshTokenTable.__table__.select().where(  # یافتن رفرش معتبر
        (RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now)  # شرط‌ها=هش برابر، ابطال‌نشده، منقضی‌نشده
    )
    rt = await database.fetch_one(sel)  # نتیجه
    if not rt:  # نبود=یافت نشد
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا=رفرش نامعتبر
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # نتیجه
    if not db_user:  # نبود=کاربر
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا=نامعتبر
    new_access = create_access_token(db_user["phone"])  # توکن جدید
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # برگشت=پاسخ استاندارد

@app.get("/verify_token/{token}")  # مسیر=اعتبارسنجی توکن در path
async def verify_token_path(token: str):  # تابع=اعتبارسنجی
    try:  # امتحان
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode=دی‌کد JWT
        return {"status": "ok", "valid": True}  # برگشت=معتبر
    except jwt.ExpiredSignatureError:  # catch=انقضا
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # برگشت=منقضی
    except Exception:  # catch=سایر خطاها
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # برگشت=نامعتبر

@app.get("/verify_token")  # مسیر=اعتبارسنجی توکن از هدر Authorization
async def verify_token_header(authorization: Optional[str] = Header(None)):  # تابع=اعتبارسنجی از هدر
    if not authorization or not authorization.lower().startswith("bearer "):  # بررسی=وجود هدر Bearer
        return {"status": "error", "valid": False, "code": "NO_AUTH_HEADER"}  # برگشت=بدون هدر
    token = authorization.split(" ", 1)[1].strip()  # بریدن بخش توکن
    try:  # دی‌کد
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # JWT
        return {"status": "ok", "valid": True}  # برگشت=معتبر
    except jwt.ExpiredSignatureError:  # catch=منقضی
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # برگشت=منقضی
    except Exception:  # catch=سایر
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # برگشت=نامعتبر

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")  # مسیر=گرفتن ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # تابع=خواندن لیست ماشین
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # انتخاب کاربر
    user = await database.fetch_one(query)  # نتیجه
    if not user:  # نبود=کاربر
        raise HTTPException(status_code=404, detail="User not found")  # خطا=عدم وجود کاربر
    items = user["car_list"] or []  # لیست ماشین‌ها یا خالی
    return unified_response("ok", "USER_CARS", "user cars", {"items": items})  # برگشت=پاسخ استاندارد

@app.post("/user_cars")  # مسیر=به‌روزرسانی لیست ماشین‌های کاربر
async def update_user_cars(data: CarListUpdateRequest):  # تابع=به‌روزرسانی
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # یافتن کاربر
    user = await database.fetch_one(sel)  # نتیجه
    if not user:  # نبود=کاربر
        raise HTTPException(status_code=404, detail="User not found")  # خطا=کاربر یافت نشد
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(  # آپدیت car_list
        car_list=[car.dict() for car in data.car_list]  # سریال‌سازی Pydantic
    )
    await database.execute(upd)  # اجرا=آپدیت
    return unified_response("ok", "CARS_SAVED", "cars saved", {"count": len(data.car_list)})  # برگشت=تعداد ذخیره‌شده

# -------------------- Orders --------------------
@app.post("/order")  # مسیر=ثبت سفارش
async def create_order(order: OrderRequest):  # تابع=ایجاد سفارش جدید
    ins = RequestTable.__table__.insert().values(  # اینزرت سفارش
        user_phone=order.user_phone,  # شماره کاربر
        latitude=order.location.latitude,  # عرض
        longitude=order.location.longitude,  # طول
        car_list=[car.dict() for car in order.car_list],  # سریال‌سازی آیتم‌ها
        address=order.address.strip(),  # حذف فاصله‌های اضافه
        home_number=(order.home_number or "").strip(),  # پلاک
        service_type=order.service_type,  # نوع سرویس
        price=order.price,  # قیمت
        request_datetime=order.request_datetime,  # زمان درخواست
        status="PENDING",  # در انتظار
        payment_type=order.payment_type.strip().lower(),  # نرمال‌سازی نوع پرداخت
        service_place=order.service_place.strip().lower()  # محل انجام سرویس
    ).returning(RequestTable.id)  # برگشت شناسه ایجادشده
    row = await database.fetch_one(ins)  # نتیجه اینزرت با id
    new_id = row[0] if isinstance(row, (tuple, list)) else (row["id"] if row else None)  # شناسه استخراج‌شده
    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # برگشت=ایجاد موفق با id

@app.post("/cancel_order")  # مسیر=لغو سفارش فعال
async def cancel_order(cancel: CancelRequest):  # تابع=لغو با شماره و نوع سرویس
    upd = (  # آپدیت وضعیت
        RequestTable.__table__.update()
        .where(
            (RequestTable.user_phone == cancel.user_phone) &
            (RequestTable.service_type == cancel.service_type) &
            (RequestTable.status.in_(["PENDING", "ACTIVE"]))
        )
        .values(status="CANCELED", scheduled_start=None)
        .returning(RequestTable.id)
    )
    rows = await database.fetch_all(upd)  # شناسه‌های لغوشده
    if rows and len(rows) > 0:  # موفق=وجود حداقل یک رکورد
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # برگشت=تعداد
    raise HTTPException(status_code=404, detail="active order not found")  # خطا=فعال یافت نشد

@app.get("/user_active_services/{user_phone}")  # مسیر=سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # تابع=خواندن سفارش‌های فعال
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status.in_(["PENDING", "ACTIVE"]))
    )
    result = await database.fetch_all(sel)  # لیست رکوردها
    items = [dict(r) for r in result]  # تبدیل به dict
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # برگشت=پاسخ

@app.get("/user_orders/{user_phone}")  # مسیر=تاریخچه سفارش‌های کاربر
async def get_user_orders(user_phone: str):  # تابع=خواندن سفارش‌ها
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # انتخاب با phone
    result = await database.fetch_all(sel)  # رکوردها
    items = [dict(r) for r in result]  # dict
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # برگشت=پاسخ

# -------------------- Scheduling (1 hour slots) --------------------
@app.get("/provider/{provider_phone}/free_hours")  # مسیر=ساعات آزاد سفارش‌گیرنده در یک روز
async def get_free_hours(
    provider_phone: str,  # شماره سفارش‌گیرنده
    date: str,                   # تاریخ YYYY-MM-DD (UTC)
    work_start: int = 8,         # شروع کاری ساعت ۸
    work_end: int = 20,          # پایان کاری ساعت ۲۰
    limit: int = 24              # حداکثر تعداد اسلات برگردانده‌شده
):
    try:  # پارس تاریخ
        d = datetime.fromisoformat(date).date()  # تاریخ از رشته
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # خطا=فرمت نادرست

    if not (0 <= work_start < 24 and 0 <= work_end <= 24 and work_start < work_end):  # اعتبارسنجی=ساعات کاری
        raise HTTPException(status_code=400, detail="invalid work hours")  # خطا=نامعتبر

    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)  # شروع روز با UTC
    day_end   = datetime(d.year, d.month, d.day, work_end,   0, tzinfo=timezone.utc)  # پایان روز با UTC

    results = []  # لیست خروجی
    cur = day_start  # اشاره‌گر زمان جاری
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:  # حلقه=ساخت بازه‌های ۱ ساعته
        s, e = cur, cur + timedelta(hours=1)  # s=شروع | e=پایان
        if await provider_is_free(provider_phone, s, e):  # بررسی=خالی بودن
            results.append(s.isoformat())  # افزودن=شروع بازه به ISO
        cur = cur + timedelta(hours=1)  # حرکت به ساعت بعد

    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})  # برگشت=ساعات آزاد

@app.post("/order/{order_id}/propose_slots")  # مسیر=پیشنهاد ۳ اسلات زمانی توسط سفارش‌گیرنده
async def propose_slots(order_id: int, body: ProposedSlotsRequest):  # تابع=ثبت اسلات‌های پیشنهادی
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == order_id))  # یافتن سفارش
    if not req:  # نبود=سفارش
        raise HTTPException(status_code=404, detail="order not found")  # خطا=عدم وجود

    accepted: List[str] = []  # اسلات‌های پذیرفته‌شده
    for s in body.slots[:3]:  # حلقه=حداکثر ۳ زمان
        start = parse_iso(s)  # پارس ISO
        end = start + timedelta(hours=1)  # پایان یک‌ساعت بعد
        if await provider_is_free(body.provider_phone, start, end):  # بررسی=خالی بودن
            await database.execute(  # اجرا=اینزرت اسلات
                ScheduleSlotTable.__table__.insert().values(
                    request_id=order_id,  # شناسه سفارش
                    provider_phone=body.provider_phone,  # سفارش‌گیرنده
                    slot_start=start,  # شروع
                    status="PROPOSED",  # پیشنهادی
                    created_at=datetime.now(timezone.utc)  # اکنون
                )
            )
            accepted.append(start.isoformat())  # افزودن زمان پذیرفته‌شده

    # نوتیفیکیشن به کاربر (placeholder)  # توضیح=ارسال اطلاع
    if accepted:  # وجود=زمان پذیرفته‌شده
        try:  # فراخوانی سرویس نوتیف
            await notify_user(req["user_phone"], "زمان‌بندی", "درخواست شما بررسی شد؛ لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.")  # Placeholder
        except Exception:  # بی‌صدا
            pass  # هیچ

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # برگشت=اسلات‌های ثبت‌شده

@app.get("/order/{order_id}/proposed_slots")  # مسیر=گرفتن اسلات‌های پیشنهادی سفارش
async def get_proposed_slots(order_id: int):  # تابع=خواندن اسلات‌ها
    sel = ScheduleSlotTable.__table__.select().where(  # انتخاب اسلات‌های PROPOSED
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.status == "PROPOSED")
    ).order_by(ScheduleSlotTable.slot_start.asc())  # مرتب‌سازی صعودی
    rows = await database.fetch_all(sel)  # نتایج
    items = [r["slot_start"].isoformat() for r in rows]  # لیست زمان‌ها
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})  # برگشت=پاسخ

@app.post("/order/{order_id}/confirm_slot")  # مسیر=تأیید یکی از اسلات‌های پیشنهادی
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):  # تابع=تأیید
    chosen_start = parse_iso(body.slot)  # پارس شروع انتخاب‌شده
    sel_slot = ScheduleSlotTable.__table__.select().where(  # یافتن اسلات موردنظر
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.slot_start == chosen_start) &
        (ScheduleSlotTable.status == "PROPOSED")
    )
    slot = await database.fetch_one(sel_slot)  # نتیجه
    if not slot:  # نبود=پیشنهادی مناسب
        raise HTTPException(status_code=404, detail="slot not found or not proposed")  # خطا=یافت نشد

    provider_phone = slot["provider_phone"]  # شماره سفارش‌گیرنده
    start = slot["slot_start"]  # شروع
    end = start + timedelta(hours=1)  # پایان یک‌ساعت بعد

    # چک نهایی خالی بودن (Race-safe)  # توضیح=کنترل همزمانی
    if not await provider_is_free(provider_phone, start, end):  # بررسی=قبلاً رزرو نشود
        await database.execute(  # اجرا=رد اسلات
            ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="REJECTED")
        )
        raise HTTPException(status_code=409, detail="slot no longer available")  # خطا=غیرقابل‌دسترس

    # قبول انتخابی + رد بقیه  # توضیح=یک تایید، بقیه رد
    await database.execute(  # اجرا=قبول اسلات انتخابی
        ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="ACCEPTED")
    )
    await database.execute(  # اجرا=رد اسلات‌های دیگر
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == order_id) &
            (ScheduleSlotTable.status == "PROPOSED") &
            (ScheduleSlotTable.id != slot["id"])
        ).values(status="REJECTED")
    )

    # رزرو نهایی  # توضیح=ثبت در appointments
    await database.execute(
        AppointmentTable.__table__.insert().values(
            provider_phone=provider_phone,  # شماره سفارش‌گیرنده
            request_id=order_id,  # شناسه سفارش
            start_time=start,  # شروع
            end_time=end,  # پایان
            status="BOOKED",  # رزرو نهایی
            created_at=datetime.now(timezone.utc)  # اکنون
        )
    )
    # ست در سفارش  # توضیح=به‌روزرسانی وضعیت سفارش
    await database.execute(
        RequestTable.__table__.update().where(RequestTable.id == order_id).values(
            scheduled_start=start, status="ACTIVE", driver_phone=provider_phone
        )
    )

    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})  # برگشت=تأیید موفق

@app.post("/order/{order_id}/reject_all_and_cancel")  # مسیر=رد همه پیشنهادها و کنسل سفارش
async def reject_all_and_cancel(order_id: int):  # تابع=رد و کنسل
    await database.execute(  # اجرا=رد همه اسلات‌های پیشنهادی
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == order_id) &
            (ScheduleSlotTable.status == "PROPOSED")
        ).values(status="REJECTED")
    )
    await database.execute(  # اجرا=کنسل سفارش
        RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="CANCELED", scheduled_start=None)
    )
    return unified_response("ok", "ORDER_CANCELED", "order canceled after rejecting proposals", {})  # برگشت=کنسل موفق

# ⭐⭐⭐ Endpoint جدید برای تعیین قیمت و وضعیت نهایی توسط مدیر ⭐⭐⭐
@app.post("/admin/order/{order_id}/price")  # مسیر=ثبت قیمت و وضعیت نهایی توسط مدیر
async def admin_set_price_and_status(order_id: int, body: PriceBody):  # تابع=به‌روزرسانی قیمت و وضعیت
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن سفارش
    req = await database.fetch_one(sel)  # نتیجه
    if not req:  # نبود=سفارش
        raise HTTPException(status_code=404, detail="order not found")  # خطا=سفارش یافت نشد

    new_status = "ACTIVE" if body.agree else "CANCELED"  # فعال یا لغو بسته به توافق

    upd = RequestTable.__table__.update().where(RequestTable.id == order_id).values(  # به‌روزرسانی
        price=body.price,  # ثبت قیمت جدید
        status=new_status  # به‌روزرسانی وضعیت
    )
    await database.execute(upd)  # اجرا=آپدیت

    return unified_response("ok", "PRICE_SET", "price and status updated", {"order_id": order_id, "price": body.price, "status": new_status})  # برگشت=پاسخ موفق

# -------------------- Profile --------------------
@app.post("/user/profile")  # مسیر=ذخیره پروفایل
async def update_profile(body: UserProfileUpdate):  # تابع=به‌روزرسانی پروفایل
    if not body.phone.strip():  # بررسی=شماره خالی
        raise HTTPException(status_code=400, detail="phone_required")  # خطا=الزام شماره
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # یافتن کاربر
    user = await database.fetch_one(sel)  # نتیجه
    if user is None:  # نبود=کاربر
        raise HTTPException(status_code=404, detail="User not found")  # خطا=یافت نشد
    upd = UserTable.__table__.update().where(UserTable.phone == body.phone).values(  # به‌روزرسانی نام/آدرس
        name=body.name.strip(),  # نام
        address=body.address.strip()  # آدرس
    )
    await database.execute(upd)  # اجرا=آپدیت
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # برگشت=ذخیره موفق

@app.get("/user/profile/{phone}")  # مسیر=خواندن پروفایل
async def get_user_profile(phone: str):  # تابع=گرفتن پروفایل
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # انتخاب کاربر
    db_user = await database.fetch_one(sel)  # نتیجه
    if db_user is None:  # نبود=کاربر
        raise HTTPException(status_code=404, detail="User not found")  # خطا=یافت نشد
    mapping = getattr(db_user, "_mapping", {})  # سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {  # برگشت=پروفایل
        "phone": db_user["phone"], "name": name_val or "", "address": address_val or ""  # فیلدها=مقادیر
    })

@app.get("/debug/users")  # مسیر=دیباگ لیست کاربران
async def debug_users():  # تابع=لیست ساده کاربران
    rows = await database.fetch_all(UserTable.__table__.select())  # همه کاربران
    out = []  # لیست خروجی
    for r in rows:  # حلقه=هر کاربر
        mapping = getattr(r, "_mapping", {})  # سازگاری
        name_val = mapping["name"] if "name" in mapping else ""  # نام
        address_val = mapping["address"] if "address" in mapping else ""  # آدرس
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})  # افزودن آیتم
    return out  # برگشت=لیست ساده
