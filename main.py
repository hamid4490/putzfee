# -*- coding: utf-8 -*-  # -*-=اعلان کدینگ فایل | utf-8=پشتیبانی فارسی
import os  # os=دسترسی به محیط/متغیرها
import hashlib  # hashlib=هش (برای سازگاری قدیمی/هش رفرش)
import secrets  # secrets=توکن‌های امن
from datetime import datetime, timedelta, timezone  # datetime/timedelta/timezone=زمان/انقضا

import bcrypt  # bcrypt=هش امن پسورد
import jwt  # jwt=توکن‌های JWT

from typing import Optional, List  # typing=نوع‌های کمکی

from fastapi import FastAPI, HTTPException, Request  # FastAPI/HTTPException/Request=چارچوب وب/خطا/درخواست
from fastapi.middleware.cors import CORSMiddleware  # CORSMiddleware=CORS
from pydantic import BaseModel  # BaseModel=مدل‌های ورودی/خروجی

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func  # sqlalchemy=ORM/DDL
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON پستگرس
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه ORM
import sqlalchemy  # sqlalchemy=برای ساخت engine

from databases import Database  # Database=کتابخانه دیتابیس async

from dotenv import load_dotenv  # load_dotenv=خواندن .env

# ——— پیکربندی محیط ———
load_dotenv()  # load_dotenv=بارگذاری ENV از .env
DATABASE_URL = os.getenv("DATABASE_URL")  # DATABASE_URL=آدرس دیتابیس
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # JWT_SECRET=راز امضای JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # PASSWORD_PEPPER=pepper برای پسورد
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # ACCESS_TOKEN_EXPIRE_MINUTES=انقضای access
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # REFRESH_TOKEN_EXPIRE_DAYS=انقضای refresh
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # BCRYPT_ROUNDS=هزینه bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # ALLOW_ORIGINS_ENV=دامنه‌های مجاز CORS

database = Database(DATABASE_URL)  # database=اتصال async به دیتابیس
Base = declarative_base()  # Base=پایه ORM

# ——— مدل‌های ORM ———
class UserTable(Base):  # UserTable=جدول کاربران
    __tablename__ = "users"  # __tablename__=نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی+ایندکس
    phone = Column(String, unique=True, index=True)  # phone=شماره (یکتا+ایندکس)
    password_hash = Column(String)  # password_hash=هش پسورد
    address = Column(String)  # address=آدرس
    car_list = Column(JSONB, default=list)  # car_list=لیست ماشین‌ها JSONB
    auth_token = Column(String, nullable=True)  # auth_token=سازگاری قدیمی (قابل حذف)

class DriverTable(Base):  # DriverTable=جدول راننده‌ها
    __tablename__ = "drivers"
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    first_name = Column(String)  # first_name=نام
    last_name = Column(String)  # last_name=نام‌خانوادگی
    photo_url = Column(String)  # photo_url=آدرس عکس
    id_card_number = Column(String)  # id_card_number=کد ملی
    phone = Column(String, unique=True)  # phone=شماره (یکتا)
    phone_verified = Column(Boolean, default=False)  # phone_verified=تأیید شماره
    is_online = Column(Boolean, default=False)  # is_online=آنلاین بودن
    status = Column(String, default="فعال")  # status=وضعیت

class RequestTable(Base):  # RequestTable=جدول سفارش‌ها
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_phone = Column(String)  # user_phone=شماره کاربر
    latitude = Column(Float)  # latitude=عرض
    longitude = Column(Float)  # longitude=طول
    car_list = Column(JSONB)  # car_list=ماشین‌ها
    address = Column(String)  # address=آدرس
    service_type = Column(String)  # service_type=سرویس
    price = Column(Integer)  # price=قیمت
    request_datetime = Column(String)  # request_datetime=زمان درخواست
    status = Column(String)  # status=وضعیت
    driver_name = Column(String)  # driver_name=نام راننده
    driver_phone = Column(String)  # driver_phone=تلفن راننده
    finish_datetime = Column(String)  # finish_datetime=زمان پایان
    payment_type = Column(String)  # payment_type=پرداخت

class RefreshTokenTable(Base):  # RefreshTokenTable=جدول رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع به کاربر
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش‌توکن (یکتا)
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=انقضا
    revoked = Column(Boolean, default=False)  # revoked=ابطال‌شده؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=زمان ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # __table_args__=ایندکس ترکیبی

# ——— مدل‌های Pydantic ———
class CarInfo(BaseModel):  # CarInfo=ماشین
    brand: str  # brand=برند
    model: str  # model=مدل
    plate: str  # plate=پلاک

class Location(BaseModel):  # Location=مختصات
    latitude: float  # latitude=عرض
    longitude: float  # longitude=طول

class OrderRequest(BaseModel):  # OrderRequest=بدنه ایجاد سفارش
    user_phone: str  # user_phone=شماره
    location: Location  # location=مختصات
    car_list: List[CarInfo]  # car_list=لیست ماشین‌ها
    address: str  # address=آدرس
    service_type: str  # service_type=سرویس
    price: int  # price=قیمت
    request_datetime: str  # request_datetime=زمان درخواست
    payment_type: str  # payment_type=پرداخت

class CarListUpdateRequest(BaseModel):  # CarListUpdateRequest=بدنه ذخیره لیست ماشین‌ها
    user_phone: str  # user_phone=شماره
    car_list: List[CarInfo]  # car_list=ماشین‌ها

class CancelRequest(BaseModel):  # CancelRequest=لغو سفارش
    user_phone: str  # user_phone=شماره
    service_type: str  # service_type=سرویس

class UserRegisterRequest(BaseModel):  # UserRegisterRequest=ثبت‌نام با پسورد
    phone: str  # phone=شماره
    password: str  # password=پسورد
    address: Optional[str] = None  # address=آدرس (اختیاری)

class UserLoginRequest(BaseModel):  # UserLoginRequest=ورود با پسورد
    phone: str  # phone=شماره
    password: str  # password=پسورد

# ——— توابع امنیت ———
def bcrypt_hash_password(password: str) -> str:  # bcrypt_hash_password=هش پسورد
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # salt=نمک با هزینه
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=پسورد+pepper بایت
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # return=هش رشته‌ای

def verify_password_secure(password: str, stored_hash: str) -> bool:  # verify_password_secure=صحت پسورد
    try:
        if stored_hash.startswith("$2"):  # bcrypt؟
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=پسورد+pepper
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # check=تطبیق bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # old=هش قدیمی SHA-256
        return old == stored_hash  # return=تطبیق قدیمی
    except Exception:
        return False  # خطا→نادرست

def create_access_token(phone: str) -> str:  # create_access_token=ساخت JWT دسترسی
    now = datetime.now(timezone.utc)  # now=زمان فعلی
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # exp=انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload=بدنه JWT
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # return=توکن

def create_refresh_token() -> str:  # create_refresh_token=رفرش‌توکن تصادفی
    return secrets.token_urlsafe(48)  # return=توکن امن

def hash_refresh_token(token: str) -> str:  # hash_refresh_token=هش رفرش‌توکن
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # return=SHA-256

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # unified_response=پاسخ یکنواخت
    return {"status": status, "code": code, "message": message, "data": data or {}}  # return=دیکشنری پاسخ

# ——— اپ و CORS ———
app = FastAPI()  # app=نمونه اپ FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # allow_origins=دامنه‌های مجاز
app.add_middleware(  # add_middleware=افزودن CORS
    CORSMiddleware,  # CORSMiddleware=میان‌افزار CORS
    allow_origins=allow_origins,  # allow_origins=دامنه‌ها
    allow_credentials=True,  # allow_credentials=اعتبارنامه
    allow_methods=["*"],  # allow_methods=تمام متدها
    allow_headers=["*"],  # allow_headers=تمام هدرها
)  # پایان add_middleware

# ——— چرخه عمر ———
@app.on_event("startup")  # startup=رویداد شروع
async def startup():
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # engine=انجین sync برای create_all
    Base.metadata.create_all(engine)  # create_all=ساخت جداول اگر نبود
    await database.connect()  # اتصال async

@app.on_event("shutdown")  # shutdown=رویداد پایان
async def shutdown():
    await database.disconnect()  # قطع اتصال

# ——— روت سلامت ———
@app.get("/")  # GET=ریشه
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}  # return=پیام سلامت

# ——— اندپوینت وجود کاربر (اصلاح‌شده) ———
@app.get("/users/exists")  # GET=/users/exists
async def user_exists(phone: str):  # phone=پارامتر کوئری
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # q=SELECT COUNT(*) FROM users WHERE phone=...
    count = await database.fetch_val(q)  # count=گرفتن مقدار شمارش
    exists = bool(count and int(count) > 0)  # exists=تبدیل به بولین
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # return=پاسخ یکنواخت

# ——— ثبت‌نام کاربر (اصلاح‌شده) ———
@app.post("/register_user")  # POST=ثبت‌نام
async def register_user(user: UserRegisterRequest):  # user=بدنه ثبت‌نام
    # چک وجود کاربر با COUNT (دقیق و بدون ابهام)
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # q=COUNT بر اساس phone
    count = await database.fetch_val(q)  # count=مقدار شمارش
    if count and int(count) > 0:  # اگر > 0
        raise HTTPException(status_code=400, detail="User already exists")  # 400=قبلاً ثبت‌نام شده

    # هش امن پسورد
    password_hash = bcrypt_hash_password(user.password)  # password_hash=هش bcrypt

    # درج رکورد جدید
    ins = UserTable.__table__.insert().values(  # ins=INSERT به users
        phone=user.phone,  # phone=شماره
        password_hash=password_hash,  # password_hash=هش
        address=user.address or "",  # address=آدرس یا خالی
        car_list=[]  # car_list=لیست خالی
    )  # پایان INSERT
    await database.execute(ins)  # اجرای INSERT

    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # return=ثبت موفق

# ——— ورود کاربر ———
@app.post("/login")  # POST=ورود
async def login_user(user: UserLoginRequest, request: Request):  # user=بدنه | request=برای آی‌پی/UA (در صورت نیاز)
    sel = UserTable.__table__.select().where(UserTable.phone == user.phone)  # sel=SELECT کاربر با phone
    db_user = await database.fetch_one(sel)  # db_user=رکورد کاربر یا None
    if not db_user:  # اگر نبود
        raise HTTPException(status_code=404, detail="User not found")  # 404=کاربر نیست

    if not verify_password_secure(user.password, db_user["password_hash"]):  # چک صحیح بودن پسورد
        raise HTTPException(status_code=401, detail="Invalid password")  # 401=رمز اشتباه

    # ارتقای هش قدیمی به bcrypt (در صورت SHA-256)
    if not db_user["password_hash"].startswith("$2"):  # اگر هش قدیمی بود
        new_hash = bcrypt_hash_password(user.password)  # new_hash=هش bcrypt جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # upd=UPDATE users
        await database.execute(upd)  # اجرای UPDATE

    # ساخت توکن‌ها
    access_token = create_access_token(db_user["phone"])  # access_token=JWT دسترسی
    refresh_token = create_refresh_token()  # refresh_token=توکن رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش رفرش
    refresh_exp = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # refresh_exp=انقضا

    # ذخیره رفرش‌توکن
    ins_rt = RefreshTokenTable.__table__.insert().values(  # ins_rt=INSERT به refresh_tokens
        user_id=db_user["id"],  # user_id=شناسه کاربر
        token_hash=refresh_hash,  # token_hash=هش
        expires_at=refresh_exp,  # expires_at=انقضا
        revoked=False  # revoked=ابطال نشده
    )
    await database.execute(ins_rt)  # اجرای INSERT

    return {  # return=پاسخ سازگار با کلاینت
        "status": "ok",  # status=موفق
        "message": "Login successful",  # message=پیام
        "token": access_token,  # token=اکسس‌توکن (سازگاری قبلی)
        "access_token": access_token,  # access_token=توکن دسترسی
        "refresh_token": refresh_token,  # refresh_token=توکن رفرش
        "user": {"phone": db_user["phone"], "address": db_user["address"]}  # user=اطلاعات کاربر
    }

# ——— رفرش توکن ———
@app.post("/auth/refresh")  # POST=رفرش access_token
async def refresh_access_token(req: dict):  # req=بدنه شامل refresh_token (ساده)
    refresh_token = req.get("refresh_token", "")  # refresh_token=خواندن از بدنه
    if not refresh_token:  # اگر خالی
        raise HTTPException(status_code=400, detail="refresh_token required")  # 400=بدنه ناقص
    token_hash = hash_refresh_token(refresh_token)  # token_hash=هش رفرش
    now = datetime.now(timezone.utc)  # now=زمان فعلی

    sel = RefreshTokenTable.__table__.select().where(  # sel=SELECT از refresh_tokens
        (RefreshTokenTable.token_hash == token_hash) &  # شرط=همسانی هش
        (RefreshTokenTable.revoked == False) &  # شرط=ابطال نشده
        (RefreshTokenTable.expires_at > now)  # شرط=منقضی نشده
    )
    rt = await database.fetch_one(sel)  # rt=رکورد رفرش
    if not rt:  # اگر نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401=نامعتبر

    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # sel_user=SELECT کاربر
    db_user = await database.fetch_one(sel_user)  # db_user=کاربر
    if not db_user:  # اگر نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401=نامعتبر

    new_access = create_access_token(db_user["phone"])  # new_access=اکسس‌توکن جدید
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # return=پاسخ

# ——— بررسی اعتبار اکسس‌توکن ———
@app.get("/verify_token/{token}")  # GET=اعتبارسنجی توکن
async def verify_token(token: str):  # token=پارامتر مسیر
    try:  # try=دیکد JWT
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode=بررسی امضا/انقضا
        return {"status": "ok", "valid": True}  # return=معتبر
    except jwt.ExpiredSignatureError:  # except=منقضی
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # return=منقضی
    except Exception:  # except=سایر
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # return=نامعتبر

# ——— ماشین‌ها ———
@app.get("/user_cars/{user_phone}")  # GET=لیست ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # user_phone=پارامتر مسیر
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # query=SELECT کاربر
    user = await database.fetch_one(query)  # user=رکورد
    if user:
        return user["car_list"] or []  # return=لیست ماشین‌ها
    raise HTTPException(status_code=404, detail="User not found")  # 404=کاربر نیست

@app.post("/user_cars")  # POST=ذخیره کل لیست ماشین‌ها
async def update_user_cars(data: CarListUpdateRequest):  # data=بدنه
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # sel=SELECT کاربر
    user = await database.fetch_one(sel)  # user=رکورد
    if not user:
        raise HTTPException(status_code=404, detail="User not found")  # 404=کاربر نیست
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(
        car_list=[car.dict() for car in data.car_list]  # car_list=لیست ماشین‌ها
    )
    await database.execute(upd)  # اجرای UPDATE
    return {"status": "ok", "message": "cars saved"}  # return=موفق

# ——— سفارش‌ها ———
@app.post("/order")  # POST=ثبت سفارش
async def create_order(order: OrderRequest):  # order=بدنه سفارش
    ins = RequestTable.__table__.insert().values(  # ins=INSERT سفارش
        user_phone=order.user_phone,  # user_phone=شماره
        latitude=order.location.latitude,  # latitude=عرض
        longitude=order.location.longitude,  # longitude=طول
        car_list=[car.dict() for car in order.car_list],  # car_list=ماشین‌ها
        address=order.address,  # address=آدرس
        service_type=order.service_type,  # service_type=سرویس
        price=order.price,  # price=قیمت
        request_datetime=order.request_datetime,  # request_datetime=زمان
        status="در انتظار",  # status=در انتظار
        driver_name="",  # driver_name=خالی
        driver_phone="",  # driver_phone=خالی
        finish_datetime="",  # finish_datetime=خالی
        payment_type=order.payment_type  # payment_type=پرداخت
    )
    await database.execute(ins)  # اجرای INSERT
    return {"status": "ok", "message": "request created"}  # return=موفق

@app.post("/cancel_order")  # POST=لغو سفارش «در انتظار»
async def cancel_order(cancel: CancelRequest):  # cancel=بدنه لغو
    upd = RequestTable.__table__.update().where(
        (RequestTable.user_phone == cancel.user_phone) &
        (RequestTable.service_type == cancel.service_type) &
        (RequestTable.status == "در انتظار")
    ).values(status="کنسل شده")  # values=تغییر وضعیت
    result = await database.execute(upd)  # result=اجرای UPDATE
    if result:
        return {"status": "ok", "message": "canceled"}  # return=لغو موفق
    raise HTTPException(status_code=404, detail="active order not found")  # 404=سفارش فعال نیست

@app.get("/user_active_services/{user_phone}")  # GET=سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # user_phone=پارامتر مسیر
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status == "در انتظار")
    )
    result = await database.fetch_all(sel)  # result=لیست
    return [dict(row) for row in result]  # return=لیست dict

@app.get("/user_orders/{user_phone}")  # GET=تاریخچه سفارش‌های کاربر
async def get_user_orders(user_phone: str):  # user_phone=پارامتر مسیر
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # sel=SELECT
    result = await database.fetch_all(sel)  # result=لیست
    return [dict(row) for row in result]  # return=لیست dict

# ——— دیباگ: لیست کاربران ———
@app.get("/debug/users")  # GET=دیباگ کاربران (فقط برای تست)
async def debug_users():
    rows = await database.fetch_all(UserTable.__table__.select())  # rows=همه کاربران
    return [{"id": r["id"], "phone": r["phone"], "address": r["address"]} for r in rows]  # return=لیست ساده
