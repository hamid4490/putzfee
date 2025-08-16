# -*- coding: utf-8 -*-  # -*- coding: utf-8 -*-=اعلان کدینگ فایل به UTF-8 برای پشتیبانی فارسی

import os  # import=os=ماژول سیستم‌عامل برای خواندن متغیرهای محیطی
import hashlib  # import=hashlib=ماژول هش (برای هش رفرش‌توکن و سازگاری قدیمی)
import secrets  # import=secrets=ماژول تولید توکن امن (رمزنگاری)
from datetime import datetime, timedelta, timezone  # import=datetime/timedelta/timezone=زمان و تاریخ با منطقه زمانی

import bcrypt  # import=bcrypt=کتابخانه هش امن پسورد با salt/cost
import jwt  # import=jwt=کتابخانه PyJWT برای ساخت/بررسی توکن‌های JWT

from typing import Optional, List, Dict  # import=typing=نوع‌های کمکی (Optional/List/Dict)

from fastapi import FastAPI, HTTPException, Request  # import=FastAPI/HTTPException/Request=چارچوب وب، مدیریت خطا، دسترسی به درخواست
from fastapi.middleware.cors import CORSMiddleware  # import=CORSMiddleware=میان‌افزار CORS

from pydantic import BaseModel  # import=BaseModel=مدل‌های ورودی/خروجی بررسی‌شونده

from sqlalchemy import (  # import=sqlalchemy=ORM/DDL
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index  # Column/Integer/...=انواع/ستون‌ها/ایندکس‌ها
)
from sqlalchemy.dialects.postgresql import JSONB  # import=JSONB=نوع JSON مخصوص PostgreSQL
from sqlalchemy.ext.declarative import declarative_base  # import=declarative_base=پایه ORM
import sqlalchemy  # import=sqlalchemy=برای ساخت engine

from databases import Database  # import=Database=کتابخانه دیتابیس async

from dotenv import load_dotenv  # import=load_dotenv=بارگذاری متغیرهای محیطی از .env


# ——————————— پیکربندی/تنظیمات ———————————

load_dotenv()  # load_dotenv()=بارگذاری متغیرهای محیطی از فایل .env

DATABASE_URL = os.getenv("DATABASE_URL")  # DATABASE_URL=خواندن آدرس دیتابیس از محیط
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # JWT_SECRET=راز امضا JWT (HS256) | پیش‌فرض→تغییر شود
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # PASSWORD_PEPPER=فلفل رمز برای سخت‌تر کردن کرک
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # انقضای اکسس‌توکن=دقیقه
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # انقضای رفرش‌توکن=روز
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # BCRYPT_ROUNDS=هزینه bcrypt (قدرت هش)
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # ALLOW_ORIGINS_ENV=دامنه‌های مجاز CORS ("," جداکننده)

# ——————————— راه‌اندازی دیتابیس و ORM ———————————

database = Database(DATABASE_URL)  # database=نمونه دیتابیس async با URL
Base = declarative_base()  # Base=پایه ORM برای تعریف جدول‌ها


# ——————————— مدل‌های دیتابیس (ORM) ———————————

class UserTable(Base):  # class=تعریف مدل ORM | UserTable=جدول کاربران
    __tablename__ = "users"  # __tablename__=نام جدول در دیتابیس
    id = Column(Integer, primary_key=True, index=True)  # id=ستون شناسه | primary_key=True=کلید اصلی | index=True=ایندکس
    phone = Column(String, unique=True, index=True)  # phone=شماره موبایل | unique=True=یکتا | index=True=ایندکس
    password_hash = Column(String)  # password_hash=ذخیره هش پسورد (bcrypt)
    address = Column(String)  # address=آدرس کاربر
    car_list = Column(JSONB, default=list)  # car_list=لیست ماشین‌ها (JSONB)
    auth_token = Column(String, nullable=True)  # auth_token=ستون قدیمی (سازگاری)، فعلاً استفاده نمی‌شود

    # نکته: ستون‌های موجود باقی می‌مانند تا مهاجرت ساده باشد


class DriverTable(Base):  # class=مدل ORM | DriverTable=جدول راننده‌ها
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    first_name = Column(String)  # first_name=نام
    last_name = Column(String)  # last_name=نام‌خانوادگی
    photo_url = Column(String)  # photo_url=آدرس عکس
    id_card_number = Column(String)  # id_card_number=شماره کارت ملی
    phone = Column(String, unique=True)  # phone=شماره موبایل | unique=True=یکتا
    phone_verified = Column(Boolean, default=False)  # phone_verified=تأیید شماره
    is_online = Column(Boolean, default=False)  # is_online=آنلاین بودن
    status = Column(String, default="فعال")  # status=وضعیت (فعال/غیرفعال)


class RequestTable(Base):  # class=مدل ORM | RequestTable=جدول سفارش‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_phone = Column(String)  # user_phone=شماره کاربر
    latitude = Column(Float)  # latitude=عرض جغرافیایی
    longitude = Column(Float)  # longitude=طول جغرافیایی
    car_list = Column(JSONB)  # car_list=لیست ماشین‌ها JSONB
    address = Column(String)  # address=آدرس
    service_type = Column(String)  # service_type=نوع سرویس
    price = Column(Integer)  # price=قیمت
    request_datetime = Column(String)  # request_datetime=تاریخ/ساعت درخواست
    status = Column(String)  # status=وضعیت سفارش
    driver_name = Column(String)  # driver_name=نام راننده
    driver_phone = Column(String)  # driver_phone=تلفن راننده
    finish_datetime = Column(String)  # finish_datetime=زمان پایان
    payment_type = Column(String)  # payment_type=نوع پرداخت


class RefreshTokenTable(Base):  # class=مدل ORM | RefreshTokenTable=جدول رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع به کاربر | ForeignKey=کلید خارجی
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش‌توکن (یونیک+ایندکس)
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=انقضا با منطقه زمانی
    revoked = Column(Boolean, default=False)  # revoked=باطل شده؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=زمان ایجاد

    __table_args__ = (  # __table_args__=آرگومان‌های جدول
        Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),  # ایندکس ترکیبی کاربر+انقضا
    )


# ——————————— مدل‌های Pydantic (در/خروج) ———————————

class CarInfo(BaseModel):  # class=مدل Pydantic | CarInfo=ماشین
    brand: str  # brand=برند
    model: str  # model=مدل
    plate: str  # plate=پلاک


class Location(BaseModel):  # class=مدل Pydantic | Location=مختصات
    latitude: float  # latitude=عرض
    longitude: float  # longitude=طول


class OrderRequest(BaseModel):  # class=مدل Pydantic | OrderRequest=درخواست سفارش
    user_phone: str  # user_phone=شماره کاربر
    location: Location  # location=مختصات
    car_list: List[CarInfo]  # car_list=لیست ماشین‌ها
    address: str  # address=آدرس
    service_type: str  # service_type=نوع سرویس
    price: int  # price=قیمت
    request_datetime: str  # request_datetime=زمان درخواست
    payment_type: str  # payment_type=نوع پرداخت


class CarListUpdateRequest(BaseModel):  # class=مدل Pydantic | CarListUpdateRequest=به‌روزرسانی لیست ماشین‌ها
    user_phone: str  # user_phone=شماره کاربر
    car_list: List[CarInfo]  # car_list=لیست ماشین‌ها


class CancelRequest(BaseModel):  # class=مدل Pydantic | CancelRequest=لغو سفارش
    user_phone: str  # user_phone=شماره کاربر
    service_type: str  # service_type=نوع سرویس


class UserRegisterRequest(BaseModel):  # class=مدل Pydantic | UserRegisterRequest=ثبت‌نام کاربر
    phone: str  # phone=شماره موبایل
    password: str  # password=پسورد خام (سمت سرور هش می‌شود)
    address: Optional[str] = None  # address=آدرس (اختیاری)


class UserLoginRequest(BaseModel):  # class=مدل Pydantic | UserLoginRequest=ورود با رمز
    phone: str  # phone=شماره
    password: str  # password=پسورد خام


class TokenRefreshRequest(BaseModel):  # class=مدل Pydantic | TokenRefreshRequest=درخواست رفرش‌توکن
    refresh_token: str  # refresh_token=رفرش‌توکن خام


# ——————————— ابزار امنیت/توکن ———————————

def bcrypt_hash_password(password: str) -> str:  # def=تعریف تابع | bcrypt_hash_password=هش پسورد با bcrypt
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # salt=تولید نمک با هزینه مشخص
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=ترکیب پسورد+pepper و تبدیل به بایت
    hashed = bcrypt.hashpw(mixed, salt)  # hashed=هش کردن با bcrypt
    return hashed.decode("utf-8")  # return=بازگشت رشته هش


def verify_password_secure(password: str, stored_hash: str) -> bool:  # def=بررسی پسورد | verify_password_secure=صحت‌سنجی
    try:  # try=مدیریت خطا برای قالب‌های متفاوت
        if stored_hash.startswith("$2"):  # if=اگر هش از نوع bcrypt است (پیشوند $2)
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=پسورد+pepper به بایت
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # return=نتیجه بررسی bcrypt
        # سازگاری قدیمی: اگر هش قدیمی (SHA-256) باشد، بررسی و سپس ارتقا
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # old=محاسبه SHA-256 قدیمی
        return old == stored_hash  # return=مقایسه با هش ذخیره‌شده
    except Exception:  # except=هر خطا
        return False  # return=نامعتبر


def create_access_token(phone: str) -> str:  # def=ساخت اکسس‌توکن | create_access_token
    now = datetime.now(timezone.utc)  # now=زمان فعلی با منطقه UTC
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # exp=زمان انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload=بدنه JWT (شناسه/نوع/انقضا)
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # token=امضای JWT با HS256
    return token  # return=بازگشت توکن


def create_refresh_token() -> str:  # def=ساخت رفرش‌توکن | create_refresh_token
    return secrets.token_urlsafe(48)  # return=توکن امن با طول مناسب


def hash_refresh_token(token: str) -> str:  # def=هش رفرش‌توکن برای ذخیره امن
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # return=SHA-256(token+pepper)


def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # def=فرمت پاسخ یکسان
    return {"status": status, "code": code, "message": message, "data": data or {}}  # return=دیکشنری پاسخ استاندارد


# ——————————— ریت‌لیمیت ورود ———————————

LOGIN_MAX_ATTEMPTS = 5  # LOGIN_MAX_ATTEMPTS=حداکثر تلاش مجاز
LOGIN_WINDOW_MINUTES = 15  # LOGIN_WINDOW_MINUTES=پنجره زمانی بررسی (دقیقه)
LOGIN_LOCK_MINUTES = 15  # LOGIN_LOCK_MINUTES=مدت قفل پس از عبور از حد (دقیقه)

login_attempts: Dict[str, List[datetime]] = {}  # login_attempts=دیکشنری کلید→لیست زمان‌های تلاش
login_locked_until: Dict[str, datetime] = {}  # login_locked_until=کلید→زمان پایان قفل

def _attempt_key(phone: str, ip: str) -> str:  # def=ساخت کلید یکتا برای تلاش | phone+ip
    return f"{phone}|{ip}"  # return=رشته کلید


def check_login_rate_limit(phone: str, ip: str):  # def=بررسی ریت‌لیمیت برای ورود
    key = _attempt_key(phone, ip)  # key=کلید تلاش
    now = datetime.now(timezone.utc)  # now=زمان فعلی
    # بررسی قفل
    if key in login_locked_until and login_locked_until[key] > now:  # if=اگر قفل فعال
        raise HTTPException(status_code=429, detail="Too many attempts. Try later.")  # raise=خطای 429
    # پاکسازی تلاش‌های قدیمی
    recent = [t for t in login_attempts.get(key, []) if (now - t) <= timedelta(minutes=LOGIN_WINDOW_MINUTES)]  # recent=لیست اخیر
    login_attempts[key] = recent  # به‌روز کردن لیست
    if len(recent) >= LOGIN_MAX_ATTEMPTS:  # if=اگر از حد گذشته
        login_locked_until[key] = now + timedelta(minutes=LOGIN_LOCK_MINUTES)  # قفل تا مدت مشخص
        raise HTTPException(status_code=429, detail="Too many attempts. Try later.")  # raise=429


def record_login_attempt(phone: str, ip: str, success: bool):  # def=ثبت تلاش ورود
    key = _attempt_key(phone, ip)  # key=کلید
    now = datetime.now(timezone.utc)  # now=زمان فعلی
    if not success:  # if=در صورت شکست
        login_attempts.setdefault(key, []).append(now)  # افزودن زمان تلاش به لیست
    else:  # else=در صورت موفقیت
        login_attempts.pop(key, None)  # پاکسازی لیست تلاش‌ها
        login_locked_until.pop(key, None)  # پاکسازی قفل


# ——————————— راه‌اندازی FastAPI + CORS ———————————

app = FastAPI()  # app=نمونه اپ FastAPI

allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # allow_origins=محاسبه لیست دامنه‌های مجاز
app.add_middleware(  # add_middleware=افزودن میان‌افزار CORS
    CORSMiddleware,  # CORSMiddleware=میان‌افزار CORS
    allow_origins=allow_origins,  # allow_origins=دامنه‌های مجاز
    allow_credentials=True,  # allow_credentials=ارسال کوکی/اعتبارنامه
    allow_methods=["*"],  # allow_methods=تمام متدها
    allow_headers=["*"],  # allow_headers=تمام هدرها
)  # پایان add_middleware


# ——————————— رویدادهای چرخه عمر اپ ———————————

@app.on_event("startup")  # @on_event("startup")=اجرای تابع در شروع اپ
async def startup():  # def=تابع async شروع
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # engine=انجین sync برای create_all
    Base.metadata.create_all(engine)  # create_all=ساخت جدول‌ها در صورت نبود
    await database.connect()  # اتصال async به دیتابیس


@app.on_event("shutdown")  # @on_event("shutdown")=تابع پایان اپ
async def shutdown():  # def=تابع async پایان
    await database.disconnect()  # قطع اتصال دیتابیس


# ——————————— اندپوینت‌های عمومی ———————————

@app.get("/")  # @app.get("/")=اندپوینت GET ریشه
def read_root():  # def=تابع هندلر
    return {"message": "Putzfee FastAPI Server is running!"}  # return=پاسخ ساده سلامت


# ——————————— احراز هویت / کاربران ———————————

@app.get("/users/exists")  # @app.get(...)=اندپوینت بررسی وجود کاربر
async def user_exists(phone: str):  # def=تابع async | phone=پارامتر کوئری
    query = UserTable.__table__.select().where(UserTable.phone == phone)  # query=SELECT کاربر با phone
    existing = await database.fetch_one(query)  # existing=یک رکورد (یا None)
    exists = existing is not None  # exists=وجود دارد؟
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "وضعیت کاربر", {"exists": exists})  # return=پاسخ استاندارد


@app.post("/register_user")  # @app.post(...)=اندپوینت ثبت‌نام کاربر
async def register_user(user: UserRegisterRequest):  # def=تابع async | user=بدنه ورودی ثبت‌نام
    # چک وجود کاربر
    query = UserTable.__table__.select().where(UserTable.phone == user.phone)  # query=SELECT کاربر با phone
    existing = await database.fetch_one(query)  # existing=رکورد کاربر
    if existing:  # if=اگر وجود دارد
        raise HTTPException(status_code=400, detail="User already exists")  # raise=برگرداندن 400 (کاربر وجود دارد)

    # هش امن پسورد با bcrypt (+pepper)
    password_hash = bcrypt_hash_password(user.password)  # password_hash=هش bcrypt پسورد

    # درج کاربر جدید
    ins = UserTable.__table__.insert().values(  # ins=INSERT به جدول users
        phone=user.phone,  # phone=شماره
        password_hash=password_hash,  # password_hash=هش ذخیره
        address=user.address or "",  # address=آدرس یا خالی
        car_list=[]  # car_list=لیست خالی
    )  # پایان INSERT
    await database.execute(ins)  # اجرای INSERT

    return unified_response("ok", "USER_REGISTERED", "ثبت‌نام با موفقیت انجام شد", {"phone": user.phone})  # return=پاسخ استاندارد


@app.post("/login")  # @app.post(...)=اندپوینت ورود
async def login_user(user: UserLoginRequest, request: Request):  # def=تابع async | user=بدنه | request=درخواست (برای IP/UA و ریت‌لیمیت)
    client_ip = request.client.host if request.client else "unknown"  # client_ip=آی‌پی کلاینت
    user_agent = request.headers.get("user-agent", "")  # user_agent=هدر مرورگر/کلاینت

    check_login_rate_limit(user.phone, client_ip)  # بررسی ریت‌لیمیت قبل از پردازش

    # یافتن کاربر
    sel = UserTable.__table__.select().where(UserTable.phone == user.phone)  # sel=SELECT کاربر
    db_user = await database.fetch_one(sel)  # db_user=رکورد کاربر

    if not db_user:  # if=کاربر موجود نیست
        record_login_attempt(user.phone, client_ip, success=False)  # ثبت تلاش ناموفق
        raise HTTPException(status_code=404, detail="User not found")  # raise=404

    # بررسی پسورد (bcrypt یا سازگاری قدیمی SHA-256)
    valid = verify_password_secure(user.password, db_user["password_hash"])  # valid=صحت پسورد
    if not valid:  # if=نامعتبر
        record_login_attempt(user.phone, client_ip, success=False)  # ثبت شکست
        raise HTTPException(status_code=401, detail="Invalid password")  # raise=401

    # ارتقای هش قدیمی به bcrypt (در صورت نیاز)
    if not db_user["password_hash"].startswith("$2"):  # if=اگر هش قدیمی بود
        new_hash = bcrypt_hash_password(user.password)  # new_hash=هش bcrypt تازه
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # upd=UPDATE هش
        await database.execute(upd)  # اجرای UPDATE

    # ساخت توکن‌ها
    access_token = create_access_token(db_user["phone"])  # access_token=ساخت JWT با انقضا
    refresh_token = create_refresh_token()  # refresh_token=تولید رفرش‌توکن خام
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش رفرش‌توکن
    refresh_exp = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # refresh_exp=انقضای رفرش

    # ذخیره رفرش‌توکن در جدول مجزا
    ins_rt = RefreshTokenTable.__table__.insert().values(  # ins_rt=INSERT رفرش‌توکن
        user_id=db_user["id"],  # user_id=شناسه کاربر
        token_hash=refresh_hash,  # token_hash=هش توکن
        expires_at=refresh_exp,  # expires_at=انقضا
        revoked=False  # revoked=باطل نشده
    )  # پایان INSERT
    await database.execute(ins_rt)  # اجرای INSERT

    record_login_attempt(user.phone, client_ip, success=True)  # ثبت موفقیت برای پاکسازی قفل

    # پاسخ ورود (سازگار با قبلی: token=اکسس‌توکن، user=اطلاعات کاربر)
    return {  # return=پاسخ JSON
        "status": "ok",  # status=وضعیت موفق
        "message": "Login successful",  # message=پیام
        "token": access_token,  # token=اکسس‌توکن (سازگاری قبلی)
        "access_token": access_token,  # access_token=اکسس‌توکن
        "refresh_token": refresh_token,  # refresh_token=رفرش‌توکن خام
        "user": {  # user=اطلاعات کاربر
            "phone": db_user["phone"],  # phone=شماره
            "address": db_user["address"]  # address=آدرس
        }  # پایان user
    }  # پایان پاسخ


@app.post("/auth/refresh")  # @app.post(...)=اندپوینت رفرش توکن
async def refresh_access_token(req: TokenRefreshRequest):  # def=تابع async | req=بدنه شامل refresh_token
    now = datetime.now(timezone.utc)  # now=زمان فعلی
    token_hash = hash_refresh_token(req.refresh_token)  # token_hash=هش رفرش‌توکن ورودی

    # یافتن رفرش‌توکن معتبر
    sel = RefreshTokenTable.__table__.select().where(
        (RefreshTokenTable.token_hash == token_hash) &  # شرط=همسانی هش
        (RefreshTokenTable.revoked == False) &  # شرط=عدم ابطال
        (RefreshTokenTable.expires_at > now)  # شرط=عدم انقضا
    )  # پایان سِلکت
    rt = await database.fetch_one(sel)  # rt=رکورد رفرش‌توکن

    if not rt:  # if=یافت نشد یا نامعتبر
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # raise=401

    # یافتن کاربر مربوط به توکن
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # sel_user=SELECT کاربر
    db_user = await database.fetch_one(sel_user)  # db_user=کاربر
    if not db_user:  # if=کاربر ناموجود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # raise=401

    # صدور اکسس‌توکن جدید
    new_access = create_access_token(db_user["phone"])  # new_access=اکسس‌توکن جدید

    return unified_response("ok", "TOKEN_REFRESHED", "توکن دسترسی جدید صادر شد", {"access_token": new_access})  # return=پاسخ استاندارد


@app.get("/verify_token/{token}")  # @app.get(...)=اندپوینت بررسی اعتبار اکسس‌توکن
async def verify_token(token: str):  # def=تابع async | token=پارامتر مسیر
    try:  # try=تلاش برای دیکود JWT
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # payload=دیکود با بررسی امضا/انقضا
        phone = payload.get("sub")  # phone=شناسه کاربر از توکن
        return {"status": "ok", "valid": True, "user": {"phone": phone}}  # return=پاسخ معتبر
    except jwt.ExpiredSignatureError:  # except=انقضای توکن
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # return=نامعتبر (منقضی)
    except Exception:  # except=سایر خطاها
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # return=نامعتبر


# ——————————— مدیریت ماشین‌های کاربر ———————————

@app.get("/user_cars/{user_phone}")  # @app.get(...)=گرفتن لیست ماشین‌ها
async def get_user_cars(user_phone: str):  # def=تابع async | user_phone=پارامتر مسیر
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # query=SELECT کاربر
    user = await database.fetch_one(query)  # user=رکورد کاربر
    if user:  # if=کاربر موجود
        return user["car_list"] or []  # return=لیست ماشین‌ها (یا خالی)
    else:  # else=کاربر ناموجود
        raise HTTPException(status_code=404, detail="User not found")  # raise=404


@app.post("/user_cars")  # @app.post(...)=به‌روزرسانی لیست ماشین‌ها (کل لیست)
async def update_user_cars(data: CarListUpdateRequest):  # def=تابع async | data=بدنه درخواست
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # sel=SELECT کاربر
    user = await database.fetch_one(sel)  # user=رکورد کاربر
    if user:  # if=موجود
        upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(  # upd=UPDATE users
            car_list=[car.dict() for car in data.car_list]  # car_list=لیست تبدیل‌شده به dict
        )  # پایان UPDATE
        await database.execute(upd)  # اجرای UPDATE
    else:  # else=ناموجود
        raise HTTPException(status_code=404, detail="User not found")  # raise=404
    return {"status": "ok", "message": "لیست ماشین‌ها ذخیره شد"}  # return=پاسخ سازگار قبلی


# ——————————— مدیریت سفارش‌ها ———————————

@app.post("/order")  # @app.post(...)=ثبت سفارش
async def create_order(order: OrderRequest):  # def=تابع async | order=بدنه سفارش
    ins = RequestTable.__table__.insert().values(  # ins=INSERT سفارش
        user_phone=order.user_phone,  # user_phone=شماره کاربر
        latitude=order.location.latitude,  # latitude=عرض
        longitude=order.location.longitude,  # longitude=طول
        car_list=[car.dict() for car in order.car_list],  # car_list=لیست ماشین‌ها
        address=order.address,  # address=آدرس
        service_type=order.service_type,  # service_type=نوع سرویس
        price=order.price,  # price=قیمت
        request_datetime=order.request_datetime,  # request_datetime=زمان درخواست
        status="در انتظار",  # status=وضعیت اولیه «در انتظار» (سازگار با کلاینت فعلی)
        driver_name="",  # driver_name=خالی
        driver_phone="",  # driver_phone=خالی
        finish_datetime="",  # finish_datetime=خالی
        payment_type=order.payment_type  # payment_type=نوع پرداخت
    )  # پایان INSERT
    await database.execute(ins)  # اجرای INSERT
    return {"status": "ok", "message": "درخواست ثبت شد"}  # return=پاسخ سازگار


@app.get("/orders")  # @app.get(...)=گرفتن همه سفارش‌ها (ادمین/دیباگ)
async def get_orders():  # def=تابع async
    query = RequestTable.__table__.select()  # query=SELECT همه سفارش‌ها
    result = await database.fetch_all(query)  # result=لیست رکوردها
    return [dict(row) for row in result]  # return=تبدیل به لیست دیکشنری


@app.post("/cancel_order")  # @app.post(...)=لغو سفارش در وضعیت «در انتظار»
async def cancel_order(cancel: CancelRequest):  # def=تابع async | cancel=بدنه شامل phone+service
    upd = RequestTable.__table__.update().where(  # upd=UPDATE سفارش
        (RequestTable.user_phone == cancel.user_phone) &  # شرط=شماره کاربر
        (RequestTable.service_type == cancel.service_type) &  # شرط=نوع سرویس
        (RequestTable.status == "در انتظار")  # شرط=وضعیت «در انتظار»
    ).values(status="کنسل شده")  # values=تغییر وضعیت به «کنسل شده»
    result = await database.execute(upd)  # result=اجرای UPDATE (تأثیر)
    if result:  # if=اگر تغییری اعمال شد
        return {"status": "ok", "message": "درخواست کنسل شد"}  # return=موفق
    else:  # else=سفارشی پیدا نشد
        raise HTTPException(status_code=404, detail="سفارش فعال پیدا نشد")  # raise=404


@app.get("/user_active_services/{user_phone}")  # @app.get(...)=سرویس‌های فعال کاربر (در انتظار)
async def get_user_active_services(user_phone: str):  # def=تابع async | user_phone=پارامتر مسیر
    sel = RequestTable.__table__.select().where(  # sel=SELECT
        (RequestTable.user_phone == user_phone) &  # شرط=شماره
        (RequestTable.status == "در انتظار")  # شرط=وضعیت «در انتظار»
    )  # پایان where
    result = await database.fetch_all(sel)  # result=لیست
    return [dict(row) for row in result]  # return=لیست دیکشنری


@app.get("/user_orders/{user_phone}")  # @app.get(...)=تاریخچه سفارش‌های کاربر
async def get_user_orders(user_phone: str):  # def=تابع async | user_phone=پارامتر مسیر
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # sel=SELECT با فیلتر شماره
    result = await database.fetch_all(sel)  # result=لیست رکوردها
    return [dict(row) for row in result]  # return=لیست دیکشنری
