# -*- coding: utf-8 -*-  # -*-=اعلان کدینگ فایل | utf-8=یونیکد
import os  # os=کتابخانه سیستم‌عامل
import hashlib  # hashlib=هش
import secrets  # secrets=توکن امن
from datetime import datetime, timedelta, timezone  # datetime=زمان/تاریخ
from typing import Optional, List  # typing=نوع‌دهی

import bcrypt  # bcrypt=هش امن پسورد
import jwt  # jwt=ساخت/بررسی JSON Web Token
from fastapi import FastAPI, HTTPException, Request, Header  # FastAPI=فریم‌ورک وب | HTTPException=خطا
from fastapi.middleware.cors import CORSMiddleware  # CORSMiddleware=CORS
from pydantic import BaseModel  # BaseModel=مدل‌های ورودی/خروجی

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_  # sqlalchemy=ORM
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON در PostgreSQL
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه ORM
import sqlalchemy  # sqlalchemy=کتابخانه ORM
from databases import Database  # Database=اتصال async دیتابیس
from dotenv import load_dotenv  # load_dotenv=خواندن .env

# ——— پیکربندی محیط ———
load_dotenv()  # بارگذاری متغیرها از .env
DATABASE_URL = os.getenv("DATABASE_URL")  # DATABASE_URL=آدرس پایگاه‌داده
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # JWT_SECRET=کلید JWT (پیش‌فرض توسعه)
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # PASSWORD_PEPPER=pepper برای پسورد
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # مدت اعتبار access_token (دقیقه)
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # مدت اعتبار refresh_token (روز)
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # تعداد راند bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # لیست دامنه‌های مجاز CORS (CSV یا "*")

# ——— Rate limit / Lockout پیکربندی ———
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))  # پنجره تلاش (ثانیه) | پیش‌فرض=۵ دقیقه
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # سقف تلاش ناموفق در پنجره | پیش‌فرض=۵
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))  # زمان قفل (ثانیه) | پیش‌فرض=۱۵ دقیقه

database = Database(DATABASE_URL)  # database=نمونه اتصال دیتابیس
Base = declarative_base()  # Base=پایه ORM

# ——— مدل‌های ORM ———
class UserTable(Base):  # UserTable=جدول کاربران
    __tablename__ = "users"  # __tablename__=نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    phone = Column(String, unique=True, index=True)  # phone=شماره یکتا
    password_hash = Column(String)  # password_hash=هش پسورد
    address = Column(String)  # address=آدرس
    name = Column(String, default="")  # name=نام
    car_list = Column(JSONB, default=list)  # car_list=لیست ماشین‌ها به‌صورت JSON

class DriverTable(Base):  # DriverTable=جدول راننده‌ها
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    photo_url = Column(String)
    id_card_number = Column(String)
    phone = Column(String, unique=True)
    phone_verified = Column(Boolean, default=False)
    is_online = Column(Boolean, default=False)
    status = Column(String, default="فعال")

class RequestTable(Base):  # RequestTable=جدول سفارش‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید
    user_phone = Column(String)  # user_phone=شماره کاربر
    latitude = Column(Float)  # latitude=عرض
    longitude = Column(Float)  # longitude=طول
    car_list = Column(JSONB)  # car_list=لیست ماشین‌ها
    address = Column(String)  # address=آدرس
    home_number = Column(String, default="")  # home_number=پلاک خانه
    service_type = Column(String)  # service_type=کد سرویس انگلیسی
    price = Column(Integer)  # price=قیمت
    request_datetime = Column(String)  # request_datetime=زمان ثبت
    status = Column(String)  # status=کد وضعیت انگلیسی
    driver_name = Column(String)  # driver_name=نام راننده
    driver_phone = Column(String)  # driver_phone=شماره راننده
    finish_datetime = Column(String)  # finish_datetime=زمان پایان
    payment_type = Column(String)  # payment_type=کد پرداخت انگلیسی

class RefreshTokenTable(Base):  # RefreshTokenTable=جدول رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع به users
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش‌توکن
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=انقضا
    revoked = Column(Boolean, default=False)  # revoked=باطل شده؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=زمان ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # ایندکس ترکیبی

class LoginAttemptTable(Base):  # LoginAttemptTable=جدول تلاش‌های ورود (برای Rate limit/Lockout)
    __tablename__ = "login_attempts"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید
    phone = Column(String, index=True)  # phone=شماره کاربر
    ip = Column(String, index=True)  # ip=آی‌پی کلاینت
    attempt_count = Column(Integer, default=0)  # attempt_count=تعداد تلاش ناموفق در پنجره
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # window_start=شروع پنجره
    locked_until = Column(DateTime(timezone=True), nullable=True)  # locked_until=تا این زمان قفل است
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # last_attempt_at=آخرین تلاش
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)  # ایندکس روی phone+ip

# ——— مدل‌های Pydantic ———
class CarInfo(BaseModel):  # CarInfo=مدل ماشین
    brand: str  # brand=برند
    model: str  # model=مدل
    plate: str  # plate=پلاک

class Location(BaseModel):  # Location=مدل موقعیت
    latitude: float  # latitude=عرض
    longitude: float  # longitude=طول

class OrderRequest(BaseModel):  # OrderRequest=مدل ثبت سفارش
    user_phone: str  # user_phone=شماره کاربر
    location: Location  # location=موقعیت
    car_list: List[CarInfo]  # car_list=لیست ماشین‌ها
    address: str  # address=آدرس
    home_number: Optional[str] = ""  # home_number=پلاک
    service_type: str  # service_type=کد سرویس انگلیسی
    price: int  # price=قیمت
    request_datetime: str  # request_datetime=زمان ثبت
    payment_type: str  # payment_type=کد پرداخت انگلیسی

class CarListUpdateRequest(BaseModel):  # CarListUpdateRequest=به‌روزرسانی ماشین‌ها
    user_phone: str  # user_phone=شماره کاربر
    car_list: List[CarInfo]  # car_list=لیست ماشین‌ها

class CancelRequest(BaseModel):  # CancelRequest=لغو سفارش
    user_phone: str  # user_phone=شماره کاربر
    service_type: str  # service_type=کد سرویس انگلیسی

class UserRegisterRequest(BaseModel):  # UserRegisterRequest=ثبت‌نام کاربر
    phone: str  # phone=شماره
    password: str  # password=پسورد
    address: Optional[str] = None  # address=آدرس اختیاری

class UserLoginRequest(BaseModel):  # UserLoginRequest=ورود
    phone: str  # phone=شماره
    password: str  # password=پسورد

class UserProfileUpdate(BaseModel):  # UserProfileUpdate=ویرایش پروفایل
    phone: str  # phone=شماره
    name: str = ""  # name=نام
    address: str = ""  # address=آدرس

# ——— توابع امنیت ———
def bcrypt_hash_password(password: str) -> str:  # bcrypt_hash_password=هش کردن پسورد با bcrypt+pepper
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # salt=تولید نمک
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=ترکیب پسورد+pepper
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی=هش رشته‌ای

def verify_password_secure(password: str, stored_hash: str) -> bool:  # verify_password_secure=بررسی پسورد
    try:  # try=محافظت از خطا
        if stored_hash.startswith("$2"):  # اگر=فرمت bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=پسورد+pepper
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # check=مقایسه bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # old=سازگاری sha256 قدیمی
        return old == stored_hash  # return=برابر بودن
    except Exception:  # Exception=هر خطا
        return False  # return=false

def create_access_token(phone: str) -> str:  # create_access_token=ساخت access_token کوتاه‌عمر
    now = datetime.now(timezone.utc)  # now=اکنون
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # exp=انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload=اطلاعات توکن
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # encode=JWT

def create_refresh_token() -> str:  # create_refresh_token=ساخت رفرش‌توکن
    return secrets.token_urlsafe(48)  # return=توکن امن

def hash_refresh_token(token: str) -> str:  # hash_refresh_token=هش رفرش‌توکن
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # return=sha256(توکن+pepper)

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # unified_response=پاسخ یکدست
    return {"status": status, "code": code, "message": message, "data": data or {}}  # return=دیکشنری استاندارد

# ——— ابزارها ———
def get_client_ip(request: Request) -> str:  # get_client_ip=گرفتن IP واقعی کلاینت
    xff = request.headers.get("x-forwarded-for", "")  # xff=هدر X-Forwarded-For
    if xff:  # اگر=هدر موجود
        return xff.split(",")[0].strip()  # return=اولین IP (اصلی)
    return request.client.host or "unknown"  # return=IP مستقیم یا unknown

# ——— اپ و CORS ———
app = FastAPI()  # app=نمونه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # allow_origins=دامنه‌های مجاز
app.add_middleware(  # add_middleware=افزودن CORS
    CORSMiddleware,
    allow_origins=allow_origins,  # allow_origins=فهرست مبداها (در Production: فقط دامنه‌های مجاز)
    allow_credentials=True,  # allow_credentials=اجازه کوکی/اعتبارنامه
    allow_methods=["*"],  # allow_methods=همه متدها
    allow_headers=["*"],  # allow_headers=همه هدرها
)

# ——— چرخه عمر ———
@app.on_event("startup")  # startup=رویداد شروع
async def startup():  # startup=تابع async شروع
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # engine=Engine sync برای create_all
    Base.metadata.create_all(engine)  # create_all=ساخت جداول
    await database.connect()  # اتصال دیتابیس

@app.on_event("shutdown")  # shutdown=رویداد پایان
async def shutdown():  # shutdown=تابع async پایان
    await database.disconnect()  # قطع اتصال دیتابیس

# ——— روت سلامت ———
@app.get("/")  # GET /
def read_root():  # read_root=هندلر
    return {"message": "Putzfee FastAPI Server is running!"}  # پیام سلامت

# ——— اندپوینت‌ها ———
@app.get("/users/exists")  # GET وجود کاربر
async def user_exists(phone: str):  # user_exists=بررسی وجود کاربر
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # q=کوئری شمارش
    count = await database.fetch_val(q)  # count=نتیجه
    exists = bool(count and int(count) > 0)  # exists=بولی وجود
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ یکدست

@app.post("/register_user")  # POST ثبت‌نام
async def register_user(user: UserRegisterRequest):  # register_user=هندلر ثبت‌نام
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # q=بررسی تکراری بودن
    count = await database.fetch_val(q)  # count=نتیجه
    if count and int(count) > 0:  # اگر=وجود دارد
        raise HTTPException(status_code=400, detail="User already exists")  # 400=کاربر قبلاً وجود دارد

    password_hash = bcrypt_hash_password(user.password)  # password_hash=هش پسورد
    ins = UserTable.__table__.insert().values(  # ins=کوئری درج
        phone=user.phone,
        password_hash=password_hash,
        address=(user.address or "").strip(),
        name="",
        car_list=[]
    )
    await database.execute(ins)  # execute=اجرای درج
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ یکدست

@app.post("/login")  # POST ورود
async def login_user(user: UserLoginRequest, request: Request):  # login_user=هندلر ورود
    client_ip = get_client_ip(request)  # client_ip=IP کلاینت
    now = datetime.now(timezone.utc)  # now=اکنون

    # — Rate limit / Lockout: بررسی قفل —
    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))  # sel_attempt=انتخاب رکورد تلاش
    attempt_row = await database.fetch_one(sel_attempt)  # attempt_row=نتیجه
    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:  # اگر=قفل است
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())  # retry_after=زمان باقی‌مانده
        raise HTTPException(status_code=429, detail=f"RATE_LIMITED:{retry_after}")  # 429=محدودیت نرخ (بازگشت زمان باقی‌مانده)

    # — یافتن کاربر —
    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # sel_user=انتخاب کاربر
    db_user = await database.fetch_one(sel_user)  # db_user=کاربر
    if not db_user:  # اگر=کاربر نیست
        # ثبت تلاش ناموفق + قفل احتمالی
        await _register_login_failure(user.phone, client_ip)  # ثبت تلاش ناموفق
        raise HTTPException(status_code=404, detail="User not found")  # 404

    # — بررسی پسورد —
    if not verify_password_secure(user.password, db_user["password_hash"]):  # اگر=پسورد نادرست
        await _register_login_failure(user.phone, client_ip)  # ثبت تلاش ناموفق
        raise HTTPException(status_code=401, detail="Invalid password")  # 401

    # — پاک‌سازی شمارنده تلاش بعد از موفقیت —
    await _register_login_success(user.phone, client_ip)  # ریست تلاش‌ها

    # — ارتقای هش قدیمی به bcrypt در صورت نیاز —
    if not db_user["password_hash"].startswith("$2"):  # اگر=هش قدیمی
        new_hash = bcrypt_hash_password(user.password)  # new_hash=هش جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # upd=آپدیت
        await database.execute(upd)  # اجرا

    # — ساخت توکن‌ها —
    access_token = create_access_token(db_user["phone"])  # access_token=JWT دسترسی
    refresh_token = create_refresh_token()  # refresh_token=توکن تجدید
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش رفرش
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # refresh_exp=انقضا

    ins_rt = RefreshTokenTable.__table__.insert().values(  # درج رفرش‌توکن
        user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False
    )
    await database.execute(ins_rt)  # اجرا

    mapping = getattr(db_user, "_mapping", {})  # mapping=سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # name_val=نام
    address_val = mapping["address"] if "address" in mapping else ""  # address_val=آدرس

    return {  # return=پاسخ ورود (سازگار با کلاینت فعلی)
        "status": "ok", "message": "Login successful", "token": access_token, "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}
    }

async def _register_login_failure(phone: str, ip: str):  # _register_login_failure=ثبت تلاش ناموفق
    now = datetime.now(timezone.utc)  # now=اکنون
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # sel=انتخاب رکورد
    row = await database.fetch_one(sel)  # row=نتیجه
    if row is None:  # اگر=رکورد نیست
        ins = LoginAttemptTable.__table__.insert().values(  # ins=درج رکورد جدید
            phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now
        )
        await database.execute(ins)  # اجرا
        return  # return=پایان
    # اگر پنجره منقضی شده → ریست شمارنده
    window_start = row["window_start"] or now  # window_start=شروع پنجره
    within_window = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS  # within_window=داخل پنجره؟
    new_count = (row["attempt_count"] + 1) if within_window else 1  # new_count=شمارنده جدید
    new_window_start = window_start if within_window else now  # new_window_start=شروع جدید در صورت خروج از پنجره
    locked_until = row["locked_until"]  # locked_until=وضعیت قفل
    # اگر سقف رد شد → قفل
    if new_count >= LOGIN_MAX_ATTEMPTS:  # اگر=شمارنده >= سقف
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # locked_until=تنظیم قفل
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(  # upd=آپدیت رکورد
        attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now
    )
    await database.execute(upd)  # اجرا

async def _register_login_success(phone: str, ip: str):  # _register_login_success=ریست تلاش‌ها پس از موفقیت
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # sel=انتخاب رکورد
    row = await database.fetch_one(sel)  # row=نتیجه
    if row:  # اگر=وجود دارد
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(  # upd=آپدیت ریست
            attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None
        )
        await database.execute(upd)  # اجرا

@app.post("/auth/refresh")  # POST=رفرش access_token
async def refresh_access_token(req: dict):  # refresh_access_token=هندلر رفرش
    refresh_token = req.get("refresh_token", "")  # refresh_token=خواندن از بدنه
    if not refresh_token:  # اگر=خالی
        raise HTTPException(status_code=400, detail="refresh_token required")  # 400
    token_hash = hash_refresh_token(refresh_token)  # token_hash=هش
    now = datetime.now(timezone.utc)  # اکنون
    sel = RefreshTokenTable.__table__.select().where(  # sel=انتخاب رفرش معتبر
        (RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now)
    )
    rt = await database.fetch_one(sel)  # rt=نتیجه
    if not rt:  # اگر=یافت نشد
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # sel_user=انتخاب کاربر
    db_user = await database.fetch_one(sel_user)  # db_user=کاربر
    if not db_user:  # اگر=کاربر نیست
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401
    new_access = create_access_token(db_user["phone"])  # new_access=توکن جدید
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # پاسخ یکدست

@app.get("/verify_token/{token}")  # GET=بررسی توکن از مسیر
async def verify_token_path(token: str):  # verify_token_path=هندلر
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode=بررسی امضا/انقضا
        return {"status": "ok", "valid": True}  # معتبر
    except jwt.ExpiredSignatureError:
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # منقضی
    except Exception:
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # نامعتبر

@app.get("/verify_token")  # GET=بررسی توکن از هدر Authorization
async def verify_token_header(authorization: Optional[str] = Header(None)):  # authorization=هدر
    if not authorization or not authorization.lower().startswith("bearer "):  # نبود هدر صحیح
        return {"status": "error", "valid": False, "code": "NO_AUTH_HEADER"}  # خطا
    token = authorization.split(" ", 1)[1].strip()  # token=جداکردن
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode=بررسی
        return {"status": "ok", "valid": True}  # معتبر
    except jwt.ExpiredSignatureError:
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # منقضی
    except Exception:
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # نامعتبر

@app.get("/user_cars/{user_phone}")  # GET=لیست ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # get_user_cars=هندلر
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # query=انتخاب کاربر
    user = await database.fetch_one(query)  # user=نتیجه
    if not user:  # اگر=کاربر نیست
        raise HTTPException(status_code=404, detail="User not found")  # 404
    items = user["car_list"] or []  # items=لیست ماشین‌ها (خالی اگر نبود)
    return unified_response("ok", "USER_CARS", "user cars", {"items": items})  # پاسخ یکدست با data.items

@app.post("/user_cars")  # POST=به‌روزرسانی لیست ماشین‌ها
async def update_user_cars(data: CarListUpdateRequest):  # update_user_cars=هندلر
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # sel=انتخاب کاربر
    user = await database.fetch_one(sel)  # user=نتیجه
    if not user:  # اگر=کاربر نیست
        raise HTTPException(status_code=404, detail="User not found")  # 404
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(  # upd=آپدیت
        car_list=[car.dict() for car in data.car_list]  # car_list=نگاشت Pydantic→dict
    )
    await database.execute(upd)  # اجرا
    return unified_response("ok", "CARS_SAVED", "cars saved", {"count": len(data.car_list)})  # پاسخ یکدست

@app.post("/order")  # POST=ثبت سفارش
async def create_order(order: OrderRequest):  # create_order=هندلر
    ins = RequestTable.__table__.insert().values(  # ins=درج سفارش
        user_phone=order.user_phone,
        latitude=order.location.latitude,
        longitude=order.location.longitude,
        car_list=[car.dict() for car in order.car_list],
        address=order.address.strip(),
        home_number=(order.home_number or "").strip(),
        service_type=order.service_type,
        price=order.price,
        request_datetime=order.request_datetime,
        status="PENDING",
        payment_type=order.payment_type.strip().lower()
    )
    await database.execute(ins)  # اجرا
    return unified_response("ok", "REQUEST_CREATED", "request created", {})  # پاسخ یکدست

@app.post("/cancel_order")  # POST=لغو سفارش
async def cancel_order(cancel: CancelRequest):  # cancel_order=هندلر
    upd = (
        RequestTable.__table__.update()
        .where(
            (RequestTable.user_phone == cancel.user_phone) &
            (RequestTable.service_type == cancel.service_type) &
            (RequestTable.status.in_(["PENDING", "ACTIVE"]))
        )
        .values(status="CANCELED")
        .returning(RequestTable.id)
    )
    rows = await database.fetch_all(upd)  # rows=لیست ردیف‌های تغییر یافته
    if rows and len(rows) > 0:  # اگر=حداقل یک ردیف آپدیت شد
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # پاسخ موفق
    raise HTTPException(status_code=404, detail="active order not found")  # نبود سفارش فعال

@app.get("/user_active_services/{user_phone}")  # GET=سفارش‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # get_user_active_services=هندلر
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status.in_(["PENDING", "ACTIVE"]))
    )
    result = await database.fetch_all(sel)  # result=نتیجه
    items = [dict(row) for row in result]  # items=تبدیل به dict
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # پاسخ یکدست

@app.get("/user_orders/{user_phone}")  # GET=همه سفارش‌های کاربر
async def get_user_orders(user_phone: str):  # get_user_orders=هندلر
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # sel=انتخاب همه سفارش‌ها
    result = await database.fetch_all(sel)  # result=نتیجه
    items = [dict(row) for row in result]  # items=تبدیل به dict
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # پاسخ یکدست

@app.post("/user/profile")  # POST=ویرایش پروفایل
async def update_profile(body: UserProfileUpdate):  # update_profile=هندلر
    if not body.phone.strip():  # اگر=شماره خالی
        raise HTTPException(status_code=400, detail="phone_required")  # 400
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # sel=انتخاب کاربر
    user = await database.fetch_one(sel)  # user=نتیجه
    if user is None:  # اگر=کاربر نیست
        raise HTTPException(status_code=404, detail="User not found")  # 404
    upd = UserTable.__table__.update().where(UserTable.phone == body.phone).values(  # upd=آپدیت
        name=body.name.strip(),
        address=body.address.strip()
    )
    await database.execute(upd)  # اجرا
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # پاسخ یکدست

@app.get("/user/profile/{phone}")  # GET=گرفتن پروفایل
async def get_user_profile(phone: str):  # get_user_profile=هندلر
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # sel=انتخاب کاربر
    db_user = await database.fetch_one(sel)  # db_user=نتیجه
    if db_user is None:  # اگر=کاربر نیست
        raise HTTPException(status_code=404, detail="User not found")  # 404
    mapping = getattr(db_user, "_mapping", {})  # mapping=سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # name=نام
    address_val = mapping["address"] if "address" in mapping else ""  # address=آدرس
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {  # پاسخ یکدست
        "phone": db_user["phone"], "name": name_val or "", "address": address_val or ""
    })

@app.get("/debug/users")  # GET=دیباگ کاربران
async def debug_users():  # debug_users=هندلر
    rows = await database.fetch_all(UserTable.__table__.select())  # rows=همه کاربران
    out = []  # out=لیست خروجی
    for r in rows:  # حلقه روی نتایج
        mapping = getattr(r, "_mapping", {})  # mapping=سازگاری
        name_val = mapping["name"] if "name" in mapping else ""  # name
        address_val = mapping["address"] if "address" in mapping else ""  # address
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})  # افزودن به خروجی
    return out  # return=خروجی خام (برای دیباگ)
