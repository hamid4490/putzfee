# -*- coding: utf-8 -*-  # تنظیم کدینگ فایل
# FastAPI server (orders + hourly scheduling)  # توضیح=سرور FastAPI برای سفارش و زمان‌بندی

import os  # ماژول سیستم/مسیرها
import hashlib  # هش امن
import secrets  # تولید توکن امن
from datetime import datetime, timedelta, timezone  # تاریخ/زمان | timedelta=بازه | timezone=منطقه زمانی
from typing import Optional, List, Dict  # نوع‌دهی عمومی

import bcrypt  # bcrypt=هش رمز
import jwt  # jwt=توکن
from fastapi import FastAPI, HTTPException, Request, Header  # FastAPI=چارچوب | HTTPException=خطا | Request=درخواست | Header=هدر
from fastapi.middleware.cors import CORSMiddleware  # CORS=میان‌افزار مجوز مبداها
from pydantic import BaseModel  # BaseModel=مدل‌های ورودی/خروجی

from sqlalchemy import (  # SQLAlchemy=ORM
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_, text, UniqueConstraint  # اجزای ORM/SQL
)
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON باینری
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه تعریف مدل‌ها
import sqlalchemy  # sqlalchemy=پکیج اصلی
from databases import Database  # databases=کتابخانه async برای DB
from dotenv import load_dotenv  # load_dotenv=خواندن .env

# -------------------- Config --------------------
load_dotenv()  # بارگذاری مقادیر .env
DATABASE_URL = os.getenv("DATABASE_URL")  # URL پایگاه‌داده
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # کلید JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # pepper رمز
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # انقضای توکن دسترسی (دقیقه)
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # انقضای رفرش‌توکن (روز)
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # دورهای bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # CORS origins

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))  # پنجره شمارش تلاش (ثانیه)
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # حداکثر تلاش
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))  # قفل پس از اتمام (ثانیه)

database = Database(DATABASE_URL)  # نمونه اتصال async به DB
Base = declarative_base()  # پایه مدل‌های ORM

# -------------------- ORM models --------------------
class UserTable(Base):  # مدل=جدول کاربران
    __tablename__ = "users"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    phone = Column(String, unique=True, index=True)  # phone=شماره یکتا
    password_hash = Column(String)  # password_hash=هش رمز
    address = Column(String)  # address=آدرس
    name = Column(String, default="")  # name=نام
    car_list = Column(JSONB, default=list)  # car_list=لیست ماشین‌ها (JSONB)

class DriverTable(Base):  # مدل=راننده‌ها/سرویس‌گیرنده‌ها
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    first_name = Column(String)  # first_name=نام
    last_name = Column(String)  # last_name=نام خانوادگی
    photo_url = Column(String)  # photo_url=عکس
    id_card_number = Column(String)  # id_card_number=کد ملی
    phone = Column(String, unique=True, index=True)  # phone=شماره
    phone_verified = Column(Boolean, default=False)  # phone_verified=تأیید شماره
    is_online = Column(Boolean, default=False)  # is_online=وضعیت آنلاین
    status = Column(String, default="فعال")  # status=وضعیت

class RequestTable(Base):  # مدل=درخواست‌ها/سفارش‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_phone = Column(String, index=True)  # user_phone=شماره کاربر
    latitude = Column(Float)  # latitude=عرض
    longitude = Column(Float)  # longitude=طول
    car_list = Column(JSONB)  # car_list=لیست ماشین/خدمات (JSONB)
    address = Column(String)  # address=آدرس
    home_number = Column(String, default="")  # home_number=پلاک
    service_type = Column(String, index=True)  # service_type=نوع سرویس
    price = Column(Integer)  # price=قیمت
    request_datetime = Column(String)  # request_datetime=زمان ثبت
    status = Column(String)  # status=وضعیت سفارش (PENDING/WAITING_CONFIRM/ACTIVE/CANCELED/DONE ...)
    driver_name = Column(String)  # driver_name=نام سرویس‌گیرنده
    driver_phone = Column(String)  # driver_phone=شماره سرویس‌گیرنده
    finish_datetime = Column(String)  # finish_datetime=زمان پایان
    payment_type = Column(String)  # payment_type=نوع پرداخت
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # scheduled_start=زمان شروع قطعی (اختیاری)
    service_place = Column(String, default="client")  # service_place=محل انجام (client/provider)

class RefreshTokenTable(Base):  # مدل=رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع کاربر
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش‌توکن
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=انقضا
    revoked = Column(Boolean, default=False)  # revoked=ابطال؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=زمان ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # ایندکس مرکب

class LoginAttemptTable(Base):  # مدل=تلاش‌های ورود
    __tablename__ = "login_attempts"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    phone = Column(String, index=True)  # phone=شماره
    ip = Column(String, index=True)  # ip=آی‌پی
    attempt_count = Column(Integer, default=0)  # attempt_count=تعداد تلاش
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # window_start=شروع پنجره
    locked_until = Column(DateTime(timezone=True), nullable=True)  # locked_until=قفل تا
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # last_attempt_at=آخرین تلاش
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)  # ایندکس مرکب

class ScheduleSlotTable(Base):  # مدل=اسلات‌های پیشنهادی
    __tablename__ = "schedule_slots"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id=ارجاع به سفارش
    provider_phone = Column(String, index=True)  # provider_phone=شماره سرویس‌گیرنده
    slot_start = Column(DateTime(timezone=True), index=True)  # slot_start=شروع بازه
    status = Column(String, default="PROPOSED")  # status=PROPOSED/ACCEPTED/REJECTED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=زمان ایجاد
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)  # ایندکس مرکب

class AppointmentTable(Base):  # مدل=نوبت‌های قطعی
    __tablename__ = "appointments"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    provider_phone = Column(String, index=True)  # provider_phone=شماره سرویس‌گیرنده
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id=ارجاع به سفارش
    start_time = Column(DateTime(timezone=True), index=True)  # start_time=شروع رزرو
    end_time = Column(DateTime(timezone=True), index=True)  # end_time=پایان رزرو
    status = Column(String, default="BOOKED")  # status=BOOKED/CANCELLED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),  # Unique=جلوگیری از تداخل
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

class CarOrderItem(BaseModel):  # مدل=آیتم سفارش با گزینه‌ها
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک
    wash_outside: bool = False  # روشویی
    wash_inside: bool = False  # توشویی
    polish: bool = False  # پولیش

class OrderRequest(BaseModel):  # مدل=درخواست سفارش
    user_phone: str  # شماره کاربر
    location: Location  # مختصات
    car_list: List[CarOrderItem]  # لیست ماشین‌ها/گزینه‌ها
    address: str  # آدرس
    home_number: Optional[str] = ""  # پلاک
    service_type: str  # نوع سرویس
    price: int  # قیمت
    request_datetime: str  # زمان ثبت (ISO)
    payment_type: str  # نوع پرداخت
    service_place: str  # محل سرویس (client/provider)

class CarListUpdateRequest(BaseModel):  # مدل=به‌روزرسانی لیست ماشین کاربر
    user_phone: str  # شماره
    car_list: List[CarInfo]  # لیست ماشین‌ها

class CancelRequest(BaseModel):  # مدل=درخواست کنسل
    user_phone: str  # شماره
    service_type: str  # سرویس

class UserRegisterRequest(BaseModel):  # مدل=ثبت‌نام
    phone: str  # شماره
    password: str  # رمز
    address: Optional[str] = None  # آدرس

class UserLoginRequest(BaseModel):  # مدل=ورود
    phone: str  # شماره
    password: str  # رمز

class UserProfileUpdate(BaseModel):  # مدل=به‌روزرسانی پروفایل
    phone: str  # شماره
    name: str = ""  # نام
    address: str = ""  # آدرس

class ProposedSlotsRequest(BaseModel):  # مدل=بدنه پیشنهاد اسلات‌ها
    provider_phone: str  # شماره سرویس‌گیرنده
    slots: List[str]  # لیست شروع‌های یک‌ساعته (ISO) حداکثر ۳

class ConfirmSlotRequest(BaseModel):  # مدل=تأیید یک اسلات
    slot: str  # شروع ISO اسلات انتخاب‌شده

class PriceBody(BaseModel):  # مدل=ثبت قیمت/توافق (مدیر)
    price: int  # قیمت
    agree: bool  # توافق

# -------------------- Security helpers --------------------
def bcrypt_hash_password(password: str) -> str:  # تولید هش bcrypt با pepper
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # تولید salt
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب پسورد با pepper
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی=هش

def verify_password_secure(password: str, stored_hash: str) -> bool:  # راستی‌آزمایی رمز
    try:  # try
        if stored_hash.startswith("$2"):  # اگر=فرمت bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # بررسی bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # هش قدیمی
        return old == stored_hash  # مقایسه
    except Exception:  # هر خطا
        return False  # false

def create_access_token(phone: str) -> str:  # ساخت JWT دسترسی
    now = datetime.now(timezone.utc)  # اکنون
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # امضا

def create_refresh_token() -> str:  # ساخت رفرش‌توکن
    return secrets.token_urlsafe(48)  # توکن تصادفی

def hash_refresh_token(token: str) -> str:  # هش رفرش‌توکن
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # sha256

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # پاسخ یکپارچه
    return {"status": status, "code": code, "message": message, "data": data or {}}  # دیکشنری پاسخ

# -------------------- Utils --------------------
def get_client_ip(request: Request) -> str:  # گرفتن IP کلاینت پشت پراکسی
    xff = request.headers.get("x-forwarded-for", "")  # x-forwarded-for
    if xff:  # اگر وجود دارد
        return xff.split(",")[0].strip()  # اولین IP
    return request.client.host or "unknown"  # IP مستقیم یا unknown

def parse_iso(ts: str) -> datetime:  # پارس ISO به datetime آگاه به timezone
    try:  # try
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))  # جایگزینی Z با +00:00
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail=f"invalid datetime: {ts}")  # خطای 400
    if dt.tzinfo is None:  # اگر بدون tz
        dt = dt.replace(tzinfo=timezone.utc)  # تنظیم UTC
    return dt.astimezone(timezone.utc)  # بازگشت در UTC

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:  # بررسی خالی بودن بازه
    q = AppointmentTable.__table__.select().where(  # کوئری تداخل رزرو
        (AppointmentTable.provider_phone == provider_phone) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.end_time > start)
    )
    rows = await database.fetch_all(q)  # اجرای کوئری
    return len(rows) == 0  # true=خالی است

async def notify_user(phone: str, title: str, body: str):  # ارسال نوتیف (پلیس‌هولدر)
    pass  # بدون پیاده‌سازی

# -------------------- App & CORS --------------------
app = FastAPI()  # ایجاد برنامه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # فهرست مبداها
app.add_middleware(  # افزودن میان‌افزار CORS
    CORSMiddleware,  # کلاس میان‌افزار
    allow_origins=allow_origins,  # مبداهای مجاز
    allow_credentials=True,  # اجازه کوکی/اعتبار
    allow_methods=["*"],  # همه متدها
    allow_headers=["*"],  # همه هدرها
)

# -------------------- Startup/Shutdown --------------------
@app.on_event("startup")  # رویداد شروع
async def startup():  # تابع شروع
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # موتور sync برای create_all
    Base.metadata.create_all(engine)  # ساخت جداول
    with engine.begin() as conn:  # آغاز تراکنش
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # افزودن ستون scheduled_start
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place TEXT DEFAULT 'client';"))  # افزودن service_place
    await database.connect()  # اتصال DB

@app.on_event("shutdown")  # رویداد خاتمه
async def shutdown():  # تابع خاتمه
    await database.disconnect()  # قطع اتصال DB

# -------------------- Health --------------------
@app.get("/")  # مسیر ریشه
def read_root():  # تابع سلامتی
    return {"message": "Putzfee FastAPI Server is running!"}  # پیام وضعیت

# -------------------- Auth/User --------------------
@app.get("/users/exists")  # بررسی وجود کاربر
async def user_exists(phone: str):  # تابع بررسی
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # کوئری شمارش
    count = await database.fetch_val(q)  # اجرا
    exists = bool(count and int(count) > 0)  # تبدیل به بولین
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ

@app.post("/register_user")  # ثبت‌نام کاربر
async def register_user(user: UserRegisterRequest):  # تابع ثبت‌نام
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # بررسی تکرار
    count = await database.fetch_val(q)  # اجرا
    if count and int(count) > 0:  # اگر وجود دارد
        raise HTTPException(status_code=400, detail="User already exists")  # خطا
    password_hash = bcrypt_hash_password(user.password)  # تولید هش
    ins = UserTable.__table__.insert().values(phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[])  # درج کاربر
    await database.execute(ins)  # اجرا
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ

@app.post("/login")  # ورود
async def login_user(user: UserLoginRequest, request: Request):  # تابع ورود
    client_ip = get_client_ip(request)  # IP کلاینت
    now = datetime.now(timezone.utc)  # اکنون UTC

    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))  # رکورد تلاش قبلی
    attempt_row = await database.fetch_one(sel_attempt)  # اجرا
    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:  # قفل فعال؟
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())  # زمان باقی
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after, "window_seconds": LOGIN_WINDOW_SECONDS})  # خطا

    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user:  # نبود کاربر
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        updated = await database.fetch_one(LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip)))  # آخرین وضعیت
        remaining = max(0, LOGIN_MAX_ATTEMPTS - int(updated["attempt_count"] or 0)) if updated else 0  # باقی تلاش
        lock_remaining = int((updated["locked_until"] - now).total_seconds()) if updated and updated["locked_until"] and updated["locked_until"] > now else 0  # زمان قفل
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND", "remaining_attempts": remaining, "lock_remaining": lock_remaining, "window_seconds": LOGIN_WINDOW_SECONDS})  # خطا

    if not verify_password_secure(user.password, db_user["password_hash"]):  # رمز نادرست؟
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        updated = await database.fetch_one(LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip)))  # وضعیت
        remaining = max(0, LOGIN_MAX_ATTEMPTS - int(updated["attempt_count"] or 0)) if updated else 0  # باقی
        lock_remaining = int((updated["locked_until"] - now).total_seconds()) if updated and updated["locked_until"] and updated["locked_until"] > now else 0  # قفل
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": remaining, "lock_remaining": lock_remaining, "window_seconds": LOGIN_WINDOW_SECONDS})  # خطا

    await _register_login_success(user.phone, client_ip)  # ثبت موفقیت

    if not db_user["password_hash"].startswith("$2"):  # ارتقای هش قدیمی
        new_hash = bcrypt_hash_password(user.password)  # هش bcrypt
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # آپدیت هش
        await database.execute(upd)  # اجرا

    access_token = create_access_token(db_user["phone"])  # ساخت توکن دسترسی
    refresh_token = create_refresh_token()  # ساخت رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # هش رفرش
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # انقضا
    ins_rt = RefreshTokenTable.__table__.insert().values(user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False)  # درج رفرش
    await database.execute(ins_rt)  # اجرا

    mapping = getattr(db_user, "_mapping", {})  # سازگاری RowMapping
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس

    return {  # پاسخ ورود
        "status": "ok", "message": "Login successful", "token": access_token, "access_token": access_token,  # توکن‌ها
        "refresh_token": refresh_token,  # رفرش خام
        "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}  # اطلاعات
    }

async def _register_login_failure(phone: str, ip: str):  # ثبت تلاش ناموفق
    now = datetime.now(timezone.utc)  # اکنون
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # رکورد
    row = await database.fetch_one(sel)  # اجرا
    if row is None:  # نبود رکورد
        ins = LoginAttemptTable.__table__.insert().values(phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now)  # درج
        await database.execute(ins); return  # اجرا و خروج
    window_start = row["window_start"] or now  # شروع پنجره
    within = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS  # داخل پنجره؟
    new_count = (row["attempt_count"] + 1) if within else 1  # شمارش
    new_window_start = window_start if within else now  # شروع جدید
    locked_until = row["locked_until"]  # قفل فعلی
    if new_count >= LOGIN_MAX_ATTEMPTS:  # فراتر از حد
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # تعیین قفل
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now)  # به‌روزرسانی
    await database.execute(upd)  # اجرا

async def _register_login_success(phone: str, ip: str):  # ثبت موفقیت
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # رکورد
    row = await database.fetch_one(sel)  # اجرا
    if row:  # اگر وجود دارد
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None)  # ریست شمارنده
        await database.execute(upd)  # اجرا

@app.post("/auth/refresh")  # دریافت توکن دسترسی جدید
async def refresh_access_token(req: Dict):  # بدنه شامل refresh_token
    refresh_token = req.get("refresh_token", "")  # خواندن رفرش
    if not refresh_token:  # خالی؟
        raise HTTPException(status_code=400, detail="refresh_token required")  # خطا
    token_hash = hash_refresh_token(refresh_token)  # هش
    now = datetime.now(timezone.utc)  # اکنون
    sel = RefreshTokenTable.__table__.select().where(  # یافتن رفرش معتبر
        (RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now)
    )
    rt = await database.fetch_one(sel)  # اجرا
    if not rt:  # نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user:  # نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا
    new_access = create_access_token(db_user["phone"])  # ساخت توکن
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # پاسخ

@app.get("/verify_token/{token}")  # اعتبارسنجی توکن (path)
async def verify_token_path(token: str):  # تابع اعتبارسنجی
    try:  # try
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode JWT
        return {"status": "ok", "valid": True}  # معتبر
    except jwt.ExpiredSignatureError:  # انقضا
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # منقضی
    except Exception:  # سایر خطاها
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # نامعتبر

@app.get("/verify_token")  # اعتبارسنجی توکن (هدر)
async def verify_token_header(authorization: Optional[str] = Header(None)):  # از هدر Bearer
    if not authorization or not authorization.lower().startswith("bearer "):  # نبود هدر
        return {"status": "error", "valid": False, "code": "NO_AUTH_HEADER"}  # خطا
    token = authorization.split(" ", 1)[1].strip()  # استخراج توکن
    try:  # try
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode
        return {"status": "ok", "valid": True}  # معتبر
    except jwt.ExpiredSignatureError:  # انقضا
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # منقضی
    except Exception:  # سایر
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # نامعتبر

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")  # گرفتن ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # تابع
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # انتخاب کاربر
    user = await database.fetch_one(query)  # اجرا
    if not user:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    items = user["car_list"] or []  # لیست ماشین‌ها
    return unified_response("ok", "USER_CARS", "user cars", {"items": items})  # پاسخ

@app.post("/user_cars")  # به‌روزرسانی ماشین‌های کاربر
async def update_user_cars(data: CarListUpdateRequest):  # تابع
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # یافتن کاربر
    user = await database.fetch_one(sel)  # اجرا
    if not user:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(car_list=[car.dict() for car in data.car_list])  # آپدیت car_list
    await database.execute(upd)  # اجرا
    return unified_response("ok", "CARS_SAVED", "cars saved", {"count": len(data.car_list)})  # پاسخ

# -------------------- Orders --------------------
@app.post("/order")  # ثبت سفارش
async def create_order(order: OrderRequest):  # تابع
    ins = RequestTable.__table__.insert().values(  # درج سفارش
        user_phone=order.user_phone,  # شماره کاربر
        latitude=order.location.latitude,  # عرض
        longitude=order.location.longitude,  # طول
        car_list=[car.dict() for car in order.car_list],  # سریال‌سازی آیتم‌ها
        address=order.address.strip(),  # آدرس
        home_number=(order.home_number or "").strip(),  # پلاک
        service_type=order.service_type,  # نوع سرویس
        price=order.price,  # قیمت
        request_datetime=order.request_datetime,  # زمان ثبت
        status="PENDING",  # وضعیت اولیه
        payment_type=order.payment_type.strip().lower(),  # نوع پرداخت
        service_place=order.service_place.strip().lower()  # محل سرویس
    ).returning(RequestTable.id)  # بازگردانی id
    row = await database.fetch_one(ins)  # اجرا
    new_id = row[0] if isinstance(row, (tuple, list)) else (row["id"] if row else None)  # استخراج id
    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # پاسخ

@app.post("/cancel_order")  # لغو سفارش فعال
async def cancel_order(cancel: CancelRequest):  # تابع
    upd = (
        RequestTable.__table__.update()
        .where(
            (RequestTable.user_phone == cancel.user_phone) &
            (RequestTable.service_type == cancel.service_type) &
            (RequestTable.status.in_(["PENDING", "WAITING_CONFIRM", "ACTIVE"]))  # افزوده=اجازه کنسل در WAITING_CONFIRM
        )
        .values(status="CANCELED", scheduled_start=None)
        .returning(RequestTable.id)
    )
    rows = await database.fetch_all(upd)  # اجرا
    if rows and len(rows) > 0:  # موفق
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # پاسخ
    raise HTTPException(status_code=404, detail="active order not found")  # خطا

@app.get("/user_active_services/{user_phone}")  # سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # تابع
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status.in_(["PENDING", "WAITING_CONFIRM", "ACTIVE"]))  # افزوده=WAITING_CONFIRM
    )
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # تبدیل به dict
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # پاسخ

@app.get("/user_orders/{user_phone}")  # تاریخچه سفارش‌های کاربر
async def get_user_orders(user_phone: str):  # تابع
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # کوئری همه سفارش‌ها
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # تبدیل به dict
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # پاسخ

# -------------------- Scheduling (1 hour slots) --------------------
@app.get("/provider/{provider_phone}/free_hours")  # ساعات آزاد یک روز برای سرویس‌گیرنده
async def get_free_hours(
    provider_phone: str,  # provider_phone=شماره سرویس‌گیرنده (یا any)
    date: str,  # تاریخ YYYY-MM-DD
    work_start: int = 8,  # شروع کاری
    work_end: int = 20,  # پایان کاری
    limit: int = 24  # سقف خروجی
):
    try:  # try
        d = datetime.fromisoformat(date).date()  # پارس تاریخ
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # خطا تاریخ

    if not (0 <= work_start < 24 and 0 <= work_end <= 24 and work_start < work_end):  # اعتبارسنجی ساعت کاری
        raise HTTPException(status_code=400, detail="invalid work hours")  # خطا ساعت

    provider = provider_phone.strip()  # provider=شماره تمیز
    # تولید اسلات‌های یک‌ساعته و فیلتر بر اساس رزروهای BOOKED  # توضیح
    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)  # شروع روز
    day_end = datetime(d.year, d.month, d.day, work_end, 0, tzinfo=timezone.utc)  # پایان روز

    results: List[str] = []  # لیست خروجی
    cur = day_start  # اشاره‌گر
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:  # حلقه ساعت‌ها
        s, e = cur, cur + timedelta(hours=1)  # بازه
        # حالت "any": بدون محدودیت سرویس‌گیرنده → همیشه آزاد محسوب می‌شود (مناسب سناریوی بدون رزرو)  # توضیح
        if provider.lower() == "any" or await provider_is_free(provider, s, e):  # آزاد؟
            results.append(s.isoformat())  # افزودن ISO
        cur = cur + timedelta(hours=1)  # حرکت به بعدی

    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})  # پاسخ

@app.post("/order/{order_id}/propose_slots")  # ثبت اسلات‌های پیشنهادی
async def propose_slots(order_id: int, body: ProposedSlotsRequest):  # تابع
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == order_id))  # یافتن سفارش
    if not req:  # نبود سفارش
        raise HTTPException(status_code=404, detail="order not found")  # خطا

    accepted: List[str] = []  # لیست پذیرفته‌ها
    for s in body.slots[:3]:  # حداکثر ۳ زمان
        start = parse_iso(s)  # پارس ISO
        end = start + timedelta(hours=1)  # پایان یک‌ساعت بعد
        if await provider_is_free(body.provider_phone, start, end):  # اگر بازه آزاد است
            await database.execute(  # درج اسلات پیشنهادی
                ScheduleSlotTable.__table__.insert().values(
                    request_id=order_id,  # رفرنس سفارش
                    provider_phone=body.provider_phone,  # شماره سرویس‌گیرنده
                    slot_start=start,  # شروع بازه
                    status="PROPOSED",  # وضعیت پیشنهادی
                    created_at=datetime.now(timezone.utc)  # زمان ایجاد
                )
            )
            accepted.append(start.isoformat())  # افزودن ISO به لیست

    if accepted:  # اگر اسلاتی ثبت شد
        await database.execute(  # به‌روزرسانی وضعیت سفارش به «منتظر تأیید کاربر»
            RequestTable.__table__.update()
            .where(RequestTable.id == order_id)
            .values(status="WAITING_CONFIRM", driver_phone=body.provider_phone, scheduled_start=None)
        )
        # اطلاع کاربر (اختیاری)
        try:
            await notify_user(req["user_phone"], "زمان‌بندی", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.")
        except Exception:
            pass

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # پاسخ

@app.get("/order/{order_id}/proposed_slots")  # خواندن اسلات‌های پیشنهادی یک سفارش
async def get_proposed_slots(order_id: int):  # تابع
    sel = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.status == "PROPOSED")
    ).order_by(ScheduleSlotTable.slot_start.asc())  # مرتب‌سازی
    rows = await database.fetch_all(sel)  # اجرا
    items = [r["slot_start"].isoformat() for r in rows]  # استخراج ISO
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})  # پاسخ

@app.post("/order/{order_id}/confirm_slot")  # تأیید یک اسلات
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):  # تابع
    chosen_start = parse_iso(body.slot)  # پارس شروع انتخاب‌شده
    sel_slot = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.slot_start == chosen_start) &
        (ScheduleSlotTable.status == "PROPOSED")
    )  # یافتن همان اسلات
    slot = await database.fetch_one(sel_slot)  # اجرا
    if not slot:  # نبود
        raise HTTPException(status_code=404, detail="slot not found or not proposed")  # خطا

    provider_phone = slot["provider_phone"]  # شماره سرویس‌گیرنده
    start = slot["slot_start"]  # شروع
    end = start + timedelta(hours=1)  # پایان

    if not await provider_is_free(provider_phone, start, end):  # چک مجدد آزاد بودن (Race-safe)
        await database.execute(  # رد اسلات
            ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="REJECTED")
        )
        raise HTTPException(status_code=409, detail="slot no longer available")  # خطا

    await database.execute(  # قبول اسلات انتخابی
        ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="ACCEPTED")
    )
    await database.execute(  # رد سایر اسلات‌ها
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == order_id) &
            (ScheduleSlotTable.status == "PROPOSED") &
            (ScheduleSlotTable.id != slot["id"])
        ).values(status="REJECTED")
    )

    await database.execute(  # ثبت رزرو نهایی
        AppointmentTable.__table__.insert().values(
            provider_phone=provider_phone,  # شماره سرویس‌گیرنده
            request_id=order_id,  # شناسه سفارش
            start_time=start,  # شروع
            end_time=end,  # پایان
            status="BOOKED",  # رزرو
            created_at=datetime.now(timezone.utc)  # ایجاد
        )
    )
    await database.execute(  # به‌روزرسانی سفارش → ACTIVE + تعیین زمان قطعی + ذخیره شماره
        RequestTable.__table__.update().where(RequestTable.id == order_id).values(
            scheduled_start=start, status="ACTIVE", driver_phone=provider_phone
        )
    )

    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})  # پاسخ

@app.post("/order/{order_id}/reject_all_and_cancel")  # رد همه پیشنهادها و کنسل
async def reject_all_and_cancel(order_id: int):  # تابع
    await database.execute(  # رد همه PROPOSED
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == order_id) &
            (ScheduleSlotTable.status == "PROPOSED")
        ).values(status="REJECTED")
    )
    await database.execute(  # کنسل سفارش
        RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="CANCELED", scheduled_start=None)
    )
    return unified_response("ok", "ORDER_CANCELED", "order canceled after rejecting proposals", {})  # پاسخ

# -------------------- Admin (price) --------------------
@app.post("/admin/order/{order_id}/price")  # تعیین قیمت/وضعیت توسط مدیر
async def admin_set_price_and_status(order_id: int, body: PriceBody):  # تابع
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن سفارش
    req = await database.fetch_one(sel)  # اجرا
    if not req:  # نبود سفارش
        raise HTTPException(status_code=404, detail="order not found")  # خطا

    new_status = "ACTIVE" if body.agree else "CANCELED"  # وضعیت جدید

    upd = RequestTable.__table__.update().where(RequestTable.id == order_id).values(
        price=body.price,  # قیمت
        status=new_status  # وضعیت
    )  # آپدیت
    await database.execute(upd)  # اجرا

    return unified_response("ok", "PRICE_SET", "price and status updated", {"order_id": order_id, "price": body.price, "status": new_status})  # پاسخ

# -------------------- Profile --------------------
@app.post("/user/profile")  # ذخیره پروفایل
async def update_profile(body: UserProfileUpdate):  # تابع
    if not body.phone.strip():  # اعتبارسنجی
        raise HTTPException(status_code=400, detail="phone_required")  # خطا
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # یافتن کاربر
    user = await database.fetch_one(sel)  # اجرا
    if user is None:  # نبود کاربر
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    upd = UserTable.__table__.update().where(UserTable.phone == body.phone).values(name=body.name.strip(), address=body.address.strip())  # آپدیت
    await database.execute(upd)  # اجرا
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # پاسخ

@app.get("/user/profile/{phone}")  # خواندن پروفایل
async def get_user_profile(phone: str):  # تابع
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # انتخاب کاربر
    db_user = await database.fetch_one(sel)  # اجرا
    if db_user is None:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    mapping = getattr(db_user, "_mapping", {})  # سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {"phone": db_user["phone"], "name": name_val or "", "address": address_val or ""})  # پاسخ

@app.get("/debug/users")  # دیباگ=لیست کاربران
async def debug_users():  # تابع
    rows = await database.fetch_all(UserTable.__table__.select())  # همه کاربران
    out = []  # خروجی
    for r in rows:  # حلقه
        mapping = getattr(r, "_mapping", {})  # سازگاری
        name_val = mapping["name"] if "name" in mapping else ""  # نام
        address_val = mapping["address"] if "address" in mapping else ""  # آدرس
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})  # افزودن
    return out  # بازگشت
