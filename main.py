# -*- coding: utf-8 -*-  # کدینگ فایل=یونیکد
# FastAPI server (orders + hourly scheduling with new status workflow)  # توضیح=سرور با گردش وضعیت جدید

import os  # os=ماژول سیستم
import hashlib  # hashlib=هش امن
import secrets  # secrets=توکن امن
from datetime import datetime, timedelta, timezone  # datetime/timedelta/timezone=تاریخ/زمان
from typing import Optional, List, Dict  # typing=نوع‌دهی

import bcrypt  # bcrypt=هش رمز
import jwt  # jwt=توکن JWT
from fastapi import FastAPI, HTTPException, Request, Header  # FastAPI=چارچوب | HTTPException=خطا | Request/Header=درخواست/هدر
from fastapi.middleware.cors import CORSMiddleware  # CORSMiddleware=CORS
from pydantic import BaseModel  # BaseModel=مدل‌های ورودی

from sqlalchemy import (  # SQLAlchemy=ORM
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_, text, UniqueConstraint  # اجزای ORM/SQL
)
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه ORM
import sqlalchemy  # sqlalchemy=پکیج اصلی
from databases import Database  # databases=اتصال async به DB
from dotenv import load_dotenv  # load_dotenv=خواندن .env

# -------------------- Config --------------------
load_dotenv()  # load_dotenv=بارگذاری متغیرهای محیطی
DATABASE_URL = os.getenv("DATABASE_URL")  # DATABASE_URL=آدرس پایگاه‌داده
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # JWT_SECRET=کلید JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # PASSWORD_PEPPER=pepper
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # ACCESS_TOKEN_EXPIRE_MINUTES=انقضای توکن
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # REFRESH_TOKEN_EXPIRE_DAYS=انقضای رفرش
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # BCRYPT_ROUNDS=دورهای bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # ALLOW_ORIGINS_ENV=مبداهای مجاز CORS

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))  # LOGIN_WINDOW_SECONDS=پنجره شمارش
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # LOGIN_MAX_ATTEMPTS=حداکثر تلاش
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))  # LOGIN_LOCK_SECONDS=مدت قفل

database = Database(DATABASE_URL)  # database=نمونه اتصال async به DB
Base = declarative_base()  # Base=پایه ORM

# -------------------- ORM models --------------------
class UserTable(Base):  # UserTable=جدول کاربران
    __tablename__ = "users"  # __tablename__=نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    phone = Column(String, unique=True, index=True)  # phone=شماره یکتا
    password_hash = Column(String)  # password_hash=هش رمز
    address = Column(String)  # address=آدرس
    name = Column(String, default="")  # name=نام
    car_list = Column(JSONB, default=list)  # car_list=ماشین‌ها (JSONB)

class DriverTable(Base):  # DriverTable=جدول سرویس‌گیرنده‌ها
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    first_name = Column(String)  # first_name=نام
    last_name = Column(String)  # last_name=نام‌خانوادگی
    photo_url = Column(String)  # photo_url=عکس
    id_card_number = Column(String)  # id_card_number=کد ملی
    phone = Column(String, unique=True, index=True)  # phone=شماره
    phone_verified = Column(Boolean, default=False)  # phone_verified=تأیید‌شده
    is_online = Column(Boolean, default=False)  # is_online=آنلاین؟
    status = Column(String, default="فعال")  # status=وضعیت

class RequestTable(Base):  # RequestTable=جدول سفارش‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_phone = Column(String, index=True)  # user_phone=شماره کاربر
    latitude = Column(Float)  # latitude=عرض
    longitude = Column(Float)  # longitude=طول
    car_list = Column(JSONB)  # car_list=لیست ماشین/خدمات
    address = Column(String)  # address=آدرس
    home_number = Column(String, default="")  # home_number=پلاک
    service_type = Column(String, index=True)  # service_type=نوع سرویس
    price = Column(Integer)  # price=قیمت
    request_datetime = Column(String)  # request_datetime=زمان ثبت
    status = Column(String)  # status=وضعیت سفارش (PENDING/WAITING/ASSIGNED/IN_PROGRESS/STARTED/FINISH/CANCELED)
    driver_name = Column(String)  # driver_name=نام سرویس‌گیرنده
    driver_phone = Column(String)  # driver_phone=شماره سرویس‌گیرنده
    finish_datetime = Column(String)  # finish_datetime=زمان پایان
    payment_type = Column(String)  # payment_type=نوع پرداخت
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # scheduled_start=زمان شروع قطعی
    service_place = Column(String, default="client")  # service_place=محل سرویس

class RefreshTokenTable(Base):  # RefreshTokenTable=رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع کاربر
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=انقضا
    revoked = Column(Boolean, default=False)  # revoked=باطل؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # ایندکس مرکب

class LoginAttemptTable(Base):  # LoginAttemptTable=تلاش‌های ورود
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

class ScheduleSlotTable(Base):  # ScheduleSlotTable=اسلات‌های پیشنهادی
    __tablename__ = "schedule_slots"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id=ارجاع به سفارش
    provider_phone = Column(String, index=True)  # provider_phone=شماره سرویس‌گیرنده
    slot_start = Column(DateTime(timezone=True), index=True)  # slot_start=شروع بازه
    status = Column(String, default="PROPOSED")  # status=PROPOSED/ACCEPTED/REJECTED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)  # ایندکس مرکب

class AppointmentTable(Base):  # AppointmentTable=نوبت‌های قطعی
    __tablename__ = "appointments"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    provider_phone = Column(String, index=True)  # provider_phone=شماره سرویس‌گیرنده
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id=ارجاع به سفارش
    start_time = Column(DateTime(timezone=True), index=True)  # start_time=شروع
    end_time = Column(DateTime(timezone=True), index=True)  # end_time=پایان
    status = Column(String, default="BOOKED")  # status=BOOKED/CANCELLED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),  # Unique=جلوگیری تداخل
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),  # ایندکس زمان‌ها
    )

# -------------------- Pydantic models --------------------
class CarInfo(BaseModel):  # CarInfo=ماشین ساده
    brand: str  # brand=برند
    model: str  # model=مدل
    plate: str  # plate=پلاک

class Location(BaseModel):  # Location=مختصات
    latitude: float  # latitude=عرض
    longitude: float  # longitude=طول

class CarOrderItem(BaseModel):  # CarOrderItem=آیتم سفارش
    brand: str  # brand=برند
    model: str  # model=مدل
    plate: str  # plate=پلاک
    wash_outside: bool = False  # wash_outside=روشویی
    wash_inside: bool = False  # wash_inside=توشویی
    polish: bool = False  # polish=پولیش

class OrderRequest(BaseModel):  # OrderRequest=ثبت سفارش
    user_phone: str  # user_phone=شماره کاربر
    location: Location  # location=مختصات
    car_list: List[CarOrderItem]  # car_list=ماشین‌ها/گزینه‌ها
    address: str  # address=آدرس
    home_number: Optional[str] = ""  # home_number=پلاک
    service_type: str  # service_type=نوع سرویس
    price: int  # price=قیمت
    request_datetime: str  # request_datetime=زمان ثبت
    payment_type: str  # payment_type=نوع پرداخت
    service_place: str  # service_place=محل سرویس

class CarListUpdateRequest(BaseModel):  # CarListUpdateRequest=آپدیت ماشین‌های کاربر
    user_phone: str  # user_phone=شماره
    car_list: List[CarInfo]  # car_list=ماشین‌ها

class CancelRequest(BaseModel):  # CancelRequest=لغو سفارش
    user_phone: str  # user_phone=شماره
    service_type: str  # service_type=نوع سرویس

class UserRegisterRequest(BaseModel):  # UserRegisterRequest=ثبت‌نام
    phone: str  # phone=شماره
    password: str  # password=رمز
    address: Optional[str] = None  # address=آدرس

class UserLoginRequest(BaseModel):  # UserLoginRequest=ورود
    phone: str  # phone=شماره
    password: str  # password=رمز

class UserProfileUpdate(BaseModel):  # UserProfileUpdate=آپدیت پروفایل
    phone: str  # phone=شماره
    name: str = ""  # name=نام
    address: str = ""  # address=آدرس

class ProposedSlotsRequest(BaseModel):  # ProposedSlotsRequest=بدنه پیشنهاد اسلات
    provider_phone: str  # provider_phone=شماره سرویس‌گیرنده
    slots: List[str]  # slots=لیست شروع‌های یک‌ساعته (ISO)

class ConfirmSlotRequest(BaseModel):  # ConfirmSlotRequest=تأیید اسلات
    slot: str  # slot=شروع انتخاب‌شده (ISO)

class PriceBody(BaseModel):  # PriceBody=بدنه ثبت قیمت/توافق
    price: int  # price=قیمت
    agree: bool  # agree=توافق؟

# -------------------- Security helpers --------------------
def bcrypt_hash_password(password: str) -> str:  # bcrypt_hash_password=هش رمز با pepper
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # salt=نمک
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=ترکیب رمز+pepper
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی=هش

def verify_password_secure(password: str, stored_hash: str) -> bool:  # verify_password_secure=بررسی رمز
    try:  # try
        if stored_hash.startswith("$2"):  # اگر bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # بررسی bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # هش قدیمی
        return old == stored_hash  # مقایسه
    except Exception:  # خطا
        return False  # false

def create_access_token(phone: str) -> str:  # create_access_token=ساخت JWT دسترسی
    now = datetime.now(timezone.utc)  # now=UTC
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # exp=انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload=داده
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # encode=امضا

def create_refresh_token() -> str:  # create_refresh_token=ساخت رفرش
    return secrets.token_urlsafe(48)  # خروجی=توکن امن

def hash_refresh_token(token: str) -> str:  # hash_refresh_token=هش رفرش
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # sha256

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # unified_response=قالب پاسخ
    return {"status": status, "code": code, "message": message, "data": data or {}}  # dict=پاسخ

# -------------------- Utils --------------------
def get_client_ip(request: Request) -> str:  # get_client_ip=گرفتن IP کلاینت
    xff = request.headers.get("x-forwarded-for", "")  # xff=هدر XFF
    if xff:  # اگر موجود
        return xff.split(",")[0].strip()  # اولین IP
    return request.client.host or "unknown"  # IP مستقیم یا unknown

def parse_iso(ts: str) -> datetime:  # parse_iso=پارس ISO → datetime UTC
    try:  # try
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))  # جایگزینی Z با +00:00
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail=f"invalid datetime: {ts}")  # 400
    if dt.tzinfo is None:  # اگر بدون tz
        dt = dt.replace(tzinfo=timezone.utc)  # تنظیم UTC
    return dt.astimezone(timezone.utc)  # بازگشت UTC

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:  # provider_is_free=آزاد بودن بازه
    q = AppointmentTable.__table__.select().where(  # q=کوئری رزروهای BOOKED
        (AppointmentTable.provider_phone == provider_phone) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.end_time > start)
    )
    rows = await database.fetch_all(q)  # اجرا
    return len(rows) == 0  # True=آزاد

async def notify_user(phone: str, title: str, body: str):  # notify_user=نوتیف (پلیس‌هولدر)
    pass  # بدون پیاده‌سازی

# -------------------- App & CORS --------------------
app = FastAPI()  # app=برنامه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # allow_origins=فهرست مبداها
app.add_middleware(  # add_middleware=افزودن CORS
    CORSMiddleware,  # کلاس میان‌افزار
    allow_origins=allow_origins,  # مبداها
    allow_credentials=True,  # credentials=اجازه
    allow_methods=["*"],  # روش‌ها
    allow_headers=["*"],  # هدرها
)

# -------------------- Startup/Shutdown --------------------
@app.on_event("startup")  # رویداد شروع
async def startup():  # تابع شروع
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # engine=موتور sync برای create_all
    Base.metadata.create_all(engine)  # create_all=ساخت جداول
    with engine.begin() as conn:  # تراکنش
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # تضمین scheduled_start
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place TEXT DEFAULT 'client';"))  # تضمین service_place
    await database.connect()  # اتصال DB

@app.on_event("shutdown")  # رویداد خاتمه
async def shutdown():  # تابع خاتمه
    await database.disconnect()  # قطع اتصال

# -------------------- Health --------------------
@app.get("/")  # مسیر ریشه
def read_root():  # تابع وضعیت
    return {"message": "Putzfee FastAPI Server is running!"}  # پیام OK

# -------------------- Auth/User --------------------
@app.get("/users/exists")  # بررسی وجود کاربر
async def user_exists(phone: str):  # تابع
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # کوئری شمارش
    count = await database.fetch_val(q)  # اجرا
    exists = bool(count and int(count) > 0)  # بولین
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ

@app.post("/register_user")  # ثبت‌نام
async def register_user(user: UserRegisterRequest):  # تابع
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # بررسی تکرار
    count = await database.fetch_val(q)  # اجرا
    if count and int(count) > 0:  # وجود؟
        raise HTTPException(status_code=400, detail="User already exists")  # خطا
    password_hash = bcrypt_hash_password(user.password)  # هش رمز
    ins = UserTable.__table__.insert().values(phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[])  # درج کاربر
    await database.execute(ins)  # اجرا
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ

@app.post("/login")  # ورود
async def login_user(user: UserLoginRequest, request: Request):  # تابع ورود
    client_ip = get_client_ip(request)  # IP کلاینت
    now = datetime.now(timezone.utc)  # اکنون

    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))  # رکورد تلاش
    attempt_row = await database.fetch_one(sel_attempt)  # اجرا
    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:  # قفل فعال؟
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())  # زمان باقی
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after})  # 429

    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user:  # نبود
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})  # 404

    if not verify_password_secure(user.password, db_user["password_hash"]):  # رمز غلط؟
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD"})  # 401

    await _register_login_success(user.phone, client_ip)  # ثبت موفقیت

    if not db_user["password_hash"].startswith("$2"):  # ارتقای هش قدیمی
        new_hash = bcrypt_hash_password(user.password)  # bcrypt جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # آپدیت
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

    return {  # پاسخ
        "status": "ok", "access_token": access_token, "refresh_token": refresh_token,  # توکن‌ها
        "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}  # اطلاعات کاربر
    }  # پایان پاسخ

async def _register_login_failure(phone: str, ip: str):  # ثبت تلاش ناموفق
    now = datetime.now(timezone.utc)  # اکنون
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # رکورد
    row = await database.fetch_one(sel)  # اجرا
    if row is None:  # نبود رکورد
        ins = LoginAttemptTable.__table__.insert().values(phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now)  # درج
        await database.execute(ins); return  # اجرا
    window_start = row["window_start"] or now  # شروع
    within = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS  # داخل پنجره؟
    new_count = (row["attempt_count"] + 1) if within else 1  # تعداد جدید
    new_window_start = window_start if within else now  # شروع جدید
    locked_until = row["locked_until"]  # قفل فعلی
    if new_count >= LOGIN_MAX_ATTEMPTS:  # بیش از حد؟
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # قفل
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now)  # آپدیت
    await database.execute(upd)  # اجرا

async def _register_login_success(phone: str, ip: str):  # ثبت موفقیت ورود
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # رکورد
    row = await database.fetch_one(sel)  # اجرا
    if row:  # وجود رکورد
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None)  # ریست
        await database.execute(upd)  # اجرا

@app.post("/auth/refresh")  # رفرش توکن
async def refresh_access_token(req: Dict):  # تابع
    refresh_token = req.get("refresh_token", "")  # خواندن رفرش
    if not refresh_token:  # خالی؟
        raise HTTPException(status_code=400, detail="refresh_token required")  # 400
    token_hash = hash_refresh_token(refresh_token)  # هش
    now = datetime.now(timezone.utc)  # اکنون
    sel = RefreshTokenTable.__table__.select().where((RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now))  # رفرش معتبر
    rt = await database.fetch_one(sel)  # اجرا
    if not rt:  # نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user:  # نبود کاربر
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401
    new_access = create_access_token(db_user["phone"])  # توکن جدید
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # پاسخ

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")  # دریافت ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # تابع
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # کوئری
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
@app.post("/order")  # ثبت سفارش جدید
async def create_order(order: OrderRequest):  # تابع
    ins = RequestTable.__table__.insert().values(
        user_phone=order.user_phone,  # شماره کاربر
        latitude=order.location.latitude,  # عرض
        longitude=order.location.longitude,  # طول
        car_list=[car.dict() for car in order.car_list],  # ماشین‌ها
        address=order.address.strip(),  # آدرس
        home_number=(order.home_number or "").strip(),  # پلاک
        service_type=order.service_type,  # سرویس
        price=order.price,  # قیمت
        request_datetime=order.request_datetime,  # زمان ثبت
        status="PENDING",  # وضعیت اولیه=PENDING
        payment_type=order.payment_type.strip().lower(),  # نوع پرداخت
        service_place=order.service_place.strip().lower()  # محل سرویس
    ).returning(RequestTable.id)  # بازگشت id
    row = await database.fetch_one(ins)  # اجرا
    new_id = row[0] if isinstance(row, (tuple, list)) else (row["id"] if row else None)  # استخراج id
    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # پاسخ

@app.post("/cancel_order")  # لغو سفارش
async def cancel_order(cancel: CancelRequest):  # تابع
    upd = (
        RequestTable.__table__.update()
        .where(
            (RequestTable.user_phone == cancel.user_phone) &
            (RequestTable.service_type == cancel.service_type) &
            (RequestTable.status.in_(["PENDING", "WAITING", "ASSIGNED", "IN_PROGRESS"]))  # وضعیت‌های قابل لغو
        )
        .values(status="CANCELED", scheduled_start=None)  # تنظیم به CANCELED
        .returning(RequestTable.id)  # بازگشت id
    )
    rows = await database.fetch_all(upd)  # اجرا
    if rows and len(rows) > 0:  # اگر حداقل یکی لغو شد
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # پاسخ
    raise HTTPException(status_code=404, detail="active order not found")  # خطا

@app.get("/user_active_services/{user_phone}")  # سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # تابع
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status.in_(["PENDING", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))  # وضعیت‌های فعال مطابق کلاینت
    )
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # تبدیل به dict
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # پاسخ

@app.get("/user_orders/{user_phone}")  # لیست همه سفارش‌ها
async def get_user_orders(user_phone: str):  # تابع
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # کوئری
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # dict
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # پاسخ

# -------------------- Scheduling (1 hour slots) --------------------
@app.get("/provider/{provider_phone}/free_hours")  # ساعات آزاد یک روز
async def get_free_hours(
    provider_phone: str,  # شماره سرویس‌گیرنده (یا any)
    date: str,  # تاریخ YYYY-MM-DD
    work_start: int = 8,  # شروع کاری
    work_end: int = 20,  # پایان کاری
    limit: int = 24  # سقف
):
    try:
        d = datetime.fromisoformat(date).date()  # پارس تاریخ
    except Exception:
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # خطا
    if not (0 <= work_start < 24 and 0 <= work_end <= 24 and work_start < work_end):  # اعتبارسنجی ساعت
        raise HTTPException(status_code=400, detail="invalid work hours")  # خطا

    provider = provider_phone.strip()  # تمیز کردن شماره
    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)  # شروع روز (UTC)
    day_end = datetime(d.year, d.month, d.day, work_end, 0, tzinfo=timezone.utc)  # پایان روز (UTC)

    results: List[str] = []  # خروجی
    cur = day_start  # زمان جاری
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:  # حلقه ساعتی
        s, e = cur, cur + timedelta(hours=1)  # بازه
        if provider.lower() == "any" or await provider_is_free(provider, s, e):  # any=بدون محدودیت
            results.append(s.isoformat())  # افزودن ISO
        cur = cur + timedelta(hours=1)  # بعدی

    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})  # پاسخ

@app.post("/order/{order_id}/propose_slots")  # پیشنهاد اسلات‌ها توسط مدیر/سرویس‌گیرنده
async def propose_slots(order_id: int, body: ProposedSlotsRequest):  # تابع
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == order_id))  # یافتن سفارش
    if not req:
        raise HTTPException(status_code=404, detail="order not found")  # خطا

    accepted: List[str] = []  # لیست قبول‌شده‌ها
    for s in body.slots[:3]:  # حداکثر ۳ زمان
        start = parse_iso(s)  # پارس ISO
        end = start + timedelta(hours=1)  # پایان
        if await provider_is_free(body.provider_phone, start, end):  # خالی؟
            await database.execute(  # درج اسلات
                ScheduleSlotTable.__table__.insert().values(
                    request_id=order_id, provider_phone=body.provider_phone, slot_start=start, status="PROPOSED", created_at=datetime.now(timezone.utc)
                )
            )
            accepted.append(start.isoformat())  # افزودن ISO

    if accepted:  # اگر ثبت شد
        await database.execute(  # وضعیت سفارش=WAITING (منتظر انتخاب کاربر)
            RequestTable.__table__.update().where(RequestTable.id == order_id).values(
                status="WAITING", driver_phone=body.provider_phone, scheduled_start=None
            )
        )
        # نوتیف (اختیاری)
        try:
            await notify_user(req["user_phone"], "زمان‌بندی", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.")
        except Exception:
            pass

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # پاسخ

@app.get("/order/{order_id}/proposed_slots")  # دریافت اسلات‌های پیشنهادی
async def get_proposed_slots(order_id: int):  # تابع
    sel = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")
    ).order_by(ScheduleSlotTable.slot_start.asc())  # مرتب‌سازی
    rows = await database.fetch_all(sel)  # اجرا
    items = [r["slot_start"].isoformat() for r in rows]  # ISO
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})  # پاسخ

@app.post("/order/{order_id}/confirm_slot")  # تأیید اسلات توسط کاربر
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):  # تابع
    chosen_start = parse_iso(body.slot)  # پارس شروع
    sel_slot = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.slot_start == chosen_start) &
        (ScheduleSlotTable.status == "PROPOSED")
    )  # کوئری اسلات
    slot = await database.fetch_one(sel_slot)  # اجرا
    if not slot:
        raise HTTPException(status_code=404, detail="slot not found or not proposed")  # خطا

    provider_phone = slot["provider_phone"]  # شماره سرویس‌گیرنده
    start = slot["slot_start"]  # شروع
    end = start + timedelta(hours=1)  # پایان

    if not await provider_is_free(provider_phone, start, end):  # آزاد نیست؟
        await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="REJECTED"))  # رد
        raise HTTPException(status_code=409, detail="slot no longer available")  # 409

    await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="ACCEPTED"))  # قبول انتخابی
    await database.execute(ScheduleSlotTable.__table__.update().where(
        (ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED") & (ScheduleSlotTable.id != slot["id"])
    ).values(status="REJECTED"))  # رد بقیه

    await database.execute(AppointmentTable.__table__.insert().values(
        provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)
    ))  # درج نوبت قطعی

    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(
        scheduled_start=start, status="ASSIGNED", driver_phone=provider_phone
    ))  # وضعیت=ASSIGNED (کاربر زمان را انتخاب کرده)

    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})  # پاسخ

@app.post("/order/{order_id}/reject_all_and_cancel")  # رد همه اسلات‌ها و کنسل سفارش
async def reject_all_and_cancel(order_id: int):  # تابع
    await database.execute(ScheduleSlotTable.__table__.update().where(
        (ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")
    ).values(status="REJECTED"))  # رد همه
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="CANCELED", scheduled_start=None))  # کنسل سفارش
    return unified_response("ok", "ORDER_CANCELED", "order canceled after rejecting proposals", {})  # پاسخ

# -------------------- Admin/Workflow --------------------
@app.post("/admin/order/{order_id}/price")  # تعیین قیمت و وضعیت بعدی
async def admin_set_price_and_status(order_id: int, body: PriceBody):  # تابع
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن سفارش
    req = await database.fetch_one(sel)  # اجرا
    if not req:
        raise HTTPException(status_code=404, detail="order not found")  # خطا

    new_status = "IN_PROGRESS" if body.agree else "CANCELED"  # توافق قیمت → IN_PROGRESS؛ عدم توافق → CANCELED
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(price=body.price, status=new_status))  # آپدیت
    return unified_response("ok", "PRICE_SET", "price and status updated", {"order_id": order_id, "price": body.price, "status": new_status})  # پاسخ

@app.post("/order/{order_id}/start")  # شروع کار توسط سرویس‌گیرنده/مدیر
async def start_order(order_id: int):  # تابع
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن سفارش
    req = await database.fetch_one(sel)  # اجرا
    if not req:
        raise HTTPException(status_code=404, detail="order not found")  # خطا
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="STARTED"))  # وضعیت=STARTED
    return unified_response("ok", "ORDER_STARTED", "order started", {"order_id": order_id, "status": "STARTED"})  # پاسخ

@app.post("/order/{order_id}/finish")  # پایان کار
async def finish_order(order_id: int):  # تابع
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن سفارش
    req = await database.fetch_one(sel)  # اجرا
    if not req:
        raise HTTPException(status_code=404, detail="order not found")  # خطا
    now = datetime.now(timezone.utc).isoformat()  # now=اکنون ISO
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="FINISH", finish_datetime=now))  # وضعیت=FINISH
    return unified_response("ok", "ORDER_FINISHED", "order finished", {"order_id": order_id, "status": "FINISH"})  # پاسخ

# -------------------- Profile --------------------
@app.post("/user/profile")  # ذخیره پروفایل
async def update_profile(body: UserProfileUpdate):  # تابع
    if not body.phone.strip():  # اعتبارسنجی
        raise HTTPException(status_code=400, detail="phone_required")  # خطا
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # یافتن کاربر
    user = await database.fetch_one(sel)  # اجرا
    if user is None:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    await database.execute(UserTable.__table__.update().where(UserTable.phone == body.phone).values(name=body.name.strip(), address=body.address.strip()))  # آپدیت
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # پاسخ

@app.get("/user/profile/{phone}")  # خواندن پروفایل
async def get_user_profile(phone: str):  # تابع
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # انتخاب کاربر
    db_user = await database.fetch_one(sel)  # اجرا
    if db_user is None:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    mapping = getattr(db_user, "_mapping", {})  # سازگاری RowMapping
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
