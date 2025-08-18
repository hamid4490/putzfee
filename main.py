# -*- coding: utf-8 -*-  # -*-=اعلان کدینگ فایل | utf-8=پشتیبانی از متن فارسی
import os  # os=دسترسی به متغیرهای محیطی و مسیرها
import hashlib  # hashlib=توابع هش (برای سازگاری قدیمی یا هش رفرش‌توکن)
import secrets  # secrets=ساخت توکن‌های تصادفی امن
from datetime import datetime, timedelta, timezone  # datetime/timedelta/timezone=کار با زمان و انقضاء

import bcrypt  # bcrypt=هش امن پسوردها
import jwt  # jwt=کتابخانه JWT برای ساخت/اعتبارسنجی توکن

from typing import Optional, List  # typing=نوع‌های کمکی (Optional/List)

from fastapi import FastAPI, HTTPException, Request  # FastAPI/HTTPException/Request=چارچوب وب/اعلان خطا/دسترسی به درخواست
from fastapi.middleware.cors import CORSMiddleware  # CORSMiddleware=میان‌افزار CORS

from pydantic import BaseModel  # BaseModel=مدل‌های Pydantic برای بدنه/پاسخ

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func  # SQLAlchemy=ORM/DDL
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON مخصوص PostgreSQL
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه مدل‌های ORM
import sqlalchemy  # sqlalchemy=کتابخانه ORM/Engine

from databases import Database  # databases=کتابخانه اتصال async به دیتابیس

from dotenv import load_dotenv  # load_dotenv=بارگذاری متغیرهای .env

# ——— پیکربندی عمومی ———
load_dotenv()  # load_dotenv=خواندن متغیرهای محیطی از فایل .env (در صورت وجود)
DATABASE_URL = os.getenv("DATABASE_URL")  # DATABASE_URL=آدرس دیتابیس (postgresql+asyncpg://...)
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # JWT_SECRET=راز امضاء JWT (پیش‌فرض تغییر کند)
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # PASSWORD_PEPPER=pepper برای سخت‌تر کردن هش
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # زمان انقضاء access_token به دقیقه
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # زمان انقضاء refresh_token به روز
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # هزینه bcrypt (دورهای هش)
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # ALLOW_ORIGINS=دامنه‌های مجاز CORS (کاما جدا)

database = Database(DATABASE_URL)  # database=اتصال async به دیتابیس با libraries/databases
Base = declarative_base()  # Base=پایه تعریف مدل‌های ORM

# ——— مدل‌های ORM (جداول) ———
class UserTable(Base):  # UserTable=تعریف جدول کاربران
    __tablename__ = "users"  # __tablename__=نام جدول "users"
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی + ایندکس
    phone = Column(String, unique=True, index=True)  # phone=شماره موبایل (یکتا + ایندکس)
    password_hash = Column(String)  # password_hash=هش پسورد (bcrypt یا قدیمی)
    address = Column(String)  # address=آدرس کاربر (متن کوتاه)
    name = Column(String, default="")  # name=نام کاربر (جدید) | default="" برای سازگاری
    car_list = Column(JSONB, default=list)  # car_list=لیست ماشین‌ها به صورت JSONB
    auth_token = Column(String, nullable=True)  # auth_token=سازگاری قدیمی (در صورت عدم نیاز قابل حذف)

class DriverTable(Base):  # DriverTable=جدول راننده‌ها
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی + ایندکس
    first_name = Column(String)  # first_name=نام
    last_name = Column(String)  # last_name=نام خانوادگی
    photo_url = Column(String)  # photo_url=آدرس عکس
    id_card_number = Column(String)  # id_card_number=کد ملی
    phone = Column(String, unique=True)  # phone=شماره موبایل (یکتا)
    phone_verified = Column(Boolean, default=False)  # phone_verified=تأیید شماره؟
    is_online = Column(Boolean, default=False)  # is_online=وضعیت آنلاین
    status = Column(String, default="فعال")  # status=وضعیت راننده

class RequestTable(Base):  # RequestTable=جدول سفارش/درخواست‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی + ایندکس
    user_phone = Column(String)  # user_phone=شماره کاربر
    latitude = Column(Float)  # latitude=عرض جغرافیایی
    longitude = Column(Float)  # longitude=طول جغرافیایی
    car_list = Column(JSONB)  # car_list=لیست ماشین‌ها (JSONB)
    address = Column(String)  # address=آدرس
    home_number = Column(String, default="")  # home_number=پلاک/شماره واحد (جدید)
    service_type = Column(String)  # service_type=نوع سرویس
    price = Column(Integer)  # price=قیمت
    request_datetime = Column(String)  # request_datetime=زمان درخواست (رشته ISO - بدون میلی‌ثانیه)
    status = Column(String)  # status=وضعیت جاری سفارش
    driver_name = Column(String)  # driver_name=نام راننده
    driver_phone = Column(String)  # driver_phone=تلفن راننده
    finish_datetime = Column(String)  # finish_datetime=زمان پایان
    payment_type = Column(String)  # payment_type=روش پرداخت

class RefreshTokenTable(Base):  # RefreshTokenTable=جدول رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی + ایندکس
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع به کاربر
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش‌توکن (یکتا+ایندکس)
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=زمان انقضاء
    revoked = Column(Boolean, default=False)  # revoked=ابطال شده؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=زمان ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # __table_args__=ایندکس ترکیبی روی user_id+expires

# ——— مدل‌های Pydantic (ورودی/خروجی) ———
class CarInfo(BaseModel):  # CarInfo=مدل ماشین برای بدنه درخواست‌ها
    brand: str  # brand=برند
    model: str  # model=مدل
    plate: str  # plate=پلاک

class Location(BaseModel):  # Location=مختصات جغرافیایی
    latitude: float  # latitude=عرض
    longitude: float  # longitude=طول

class OrderRequest(BaseModel):  # OrderRequest=بدنه ایجاد سفارش (کلاینت → سرور)
    user_phone: str  # user_phone=شماره کاربر
    location: Location  # location=مختصات {latitude,longitude}
    car_list: List[CarInfo]  # car_list=لیست ماشین‌ها
    address: str  # address=آدرس
    home_number: Optional[str] = ""  # home_number=پلاک منزل (افزوده شد)
    service_type: str  # service_type=نوع سرویس
    price: int  # price=قیمت
    request_datetime: str  # request_datetime=زمان ISO بدون میلی‌ثانیه
    payment_type: str  # payment_type=روش پرداخت

class CarListUpdateRequest(BaseModel):  # CarListUpdateRequest=بدنه ذخیره لیست ماشین‌ها
    user_phone: str  # user_phone=شماره کاربر
    car_list: List[CarInfo]  # car_list=لیست ماشین‌ها

class CancelRequest(BaseModel):  # CancelRequest=بدنه لغو سفارش
    user_phone: str  # user_phone=شماره کاربر
    service_type: str  # service_type=نوع سرویس

class UserRegisterRequest(BaseModel):  # UserRegisterRequest=بدنه ثبت‌نام
    phone: str  # phone=شماره
    password: str  # password=پسورد
    address: Optional[str] = None  # address=آدرس (اختیاری)

class UserLoginRequest(BaseModel):  # UserLoginRequest=بدنه ورود
    phone: str  # phone=شماره
    password: str  # password=پسورد

class UserProfileUpdate(BaseModel):  # UserProfileUpdate=بدنه به‌روزرسانی پروفایل (جدید)
    phone: str  # phone=شماره کاربر
    name: str = ""  # name=نام (پیش‌فرض خالی)
    address: str = ""  # address=آدرس (پیش‌فرض خالی)

# ——— توابع امنیت/توکن ———
def bcrypt_hash_password(password: str) -> str:  # bcrypt_hash_password=تولید هش bcrypt برای پسورد
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # salt=ساخت نمک با هزینه تعیین‌شده
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=ترکیب پسورد با pepper و تبدیل به بایت
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # return=هش bcrypt به صورت رشته

def verify_password_secure(password: str, stored_hash: str) -> bool:  # verify_password_secure=اعتبارسنجی پسورد
    try:  # try=ایمن در برابر خطا
        if stored_hash.startswith("$2"):  # اگر هش از نوع bcrypt است
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=پسورد+pepper
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # return=نتیجه بررسی bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # old=هش قدیمی SHA-256
        return old == stored_hash  # return=بررسی برابر بودن با هش قدیمی
    except Exception:  # except=در هر خطا
        return False  # return=false (نامعتبر)

def create_access_token(phone: str) -> str:  # create_access_token=ساخت JWT دسترسی
    now = datetime.now(timezone.utc)  # now=زمان فعلی (UTC)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # exp=زمان انقضاء
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload=اطلاعات JWT
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # return=JWT امضاءشده

def create_refresh_token() -> str:  # create_refresh_token=ساخت رفرش‌توکن تصادفی
    return secrets.token_urlsafe(48)  # return=رشته امن تصادفی

def hash_refresh_token(token: str) -> str:  # hash_refresh_token=هش رفرش‌توکن جهت ذخیره
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # return=هش SHA-256

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # unified_response=پاسخ استاندارد یکپارچه
    return {"status": status, "code": code, "message": message, "data": data or {}}  # return=دیکشنری استاندارد پاسخ

# ——— اپ و CORS ———
app = FastAPI()  # app=نمونه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # allow_origins=لیست دامنه‌های مجاز CORS
app.add_middleware(  # add_middleware=افزودن میان‌افزار CORS
    CORSMiddleware,  # CORSMiddleware=کلاس میان‌افزار
    allow_origins=allow_origins,  # allow_origins=دامنه‌ها
    allow_credentials=True,  # allow_credentials=اجازه ارسال کوکی/اعتبارنامه
    allow_methods=["*"],  # allow_methods=اجازه همه متدها
    allow_headers=["*"],  # allow_headers=اجازه همه هدرها
)  # پایان add_middleware

# ——— چرخه عمر اپ ———
@app.on_event("startup")  # @on_event=اجرای کد هنگام شروع اپ
async def startup():  # startup=تابع شروع
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # engine=انجین sync برای create_all (تبدیل +asyncpg)
    Base.metadata.create_all(engine)  # create_all=ایجاد جداول در صورت عدم وجود (ستون‌های جدید در DB موجود نیاز به مایگریشن دارند)
    await database.connect()  # اتصال async به دیتابیس

@app.on_event("shutdown")  # @on_event=اجرای کد هنگام خاموشی اپ
async def shutdown():  # shutdown=تابع پایان
    await database.disconnect()  # قطع اتصال دیتابیس

# ——— روت سلامت ———
@app.get("/")  # GET=مسیر ریشه
def read_root():  # read_root=هندلر سلامت
    return {"message": "Putzfee FastAPI Server is running!"}  # return=پیام ساده سلامت

# ——— اندپوینت: بررسی وجود کاربر ———
@app.get("/users/exists")  # GET=/users/exists
async def user_exists(phone: str):  # user_exists=بررسی وجود با phone (Query)
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # q=SELECT COUNT(*) FROM users WHERE phone=...
    count = await database.fetch_val(q)  # count=دریافت مقدار شمارش
    exists = bool(count and int(count) > 0)  # exists=تبدیل به بولین
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # return=پاسخ استاندارد

# ——— اندپوینت: ثبت‌نام کاربر ———
@app.post("/register_user")  # POST=/register_user
async def register_user(user: UserRegisterRequest):  # register_user=هندلر ثبت‌نام
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # q=چک وجود شماره
    count = await database.fetch_val(q)  # count=خواندن شمارش
    if count and int(count) > 0:  # اگر قبلاً وجود دارد
        raise HTTPException(status_code=400, detail="User already exists")  # raise=خطای 400

    password_hash = bcrypt_hash_password(user.password)  # password_hash=هش bcrypt پسورد
    ins = UserTable.__table__.insert().values(  # ins=INSERT به جدول users
        phone=user.phone,  # phone=شماره
        password_hash=password_hash,  # password_hash=هش
        address=user.address or "",  # address=آدرس یا خالی
        name="",  # name=نام (ابتدا خالی؛ بعداً با پروفایل به‌روزرسانی می‌شود)
        car_list=[]  # car_list=لیست ماشین‌ها (خالی)
    )  # پایان values
    await database.execute(ins)  # اجرای INSERT
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # return=پاسخ استاندارد

# ——— اندپوینت: ورود کاربر ———
@app.post("/login")  # POST=/login
async def login_user(user: UserLoginRequest, request: Request):  # login_user=هندلر ورود
    sel = UserTable.__table__.select().where(UserTable.phone == user.phone)  # sel=SELECT کاربر با phone
    db_user = await database.fetch_one(sel)  # db_user=رکورد کاربر
    if not db_user:  # اگر کاربری با این شماره نیست
        raise HTTPException(status_code=404, detail="User not found")  # 404=کاربر یافت نشد

    if not verify_password_secure(user.password, db_user["password_hash"]):  # اگر پسورد نادرست است
        raise HTTPException(status_code=401, detail="Invalid password")  # 401=پسورد اشتباه

    if not db_user["password_hash"].startswith("$2"):  # اگر هش قدیمی (SHA-256) است
        new_hash = bcrypt_hash_password(user.password)  # new_hash=هش bcrypt جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # upd=UPDATE users
        await database.execute(upd)  # اجرای UPDATE

    access_token = create_access_token(db_user["phone"])  # access_token=ساخت JWT دسترسی
    refresh_token = create_refresh_token()  # refresh_token=ساخت رفرش‌توکن تصادفی
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش رفرش‌توکن
    refresh_exp = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # refresh_exp=انقضاء

    ins_rt = RefreshTokenTable.__table__.insert().values(  # ins_rt=INSERT به refresh_tokens
        user_id=db_user["id"],  # user_id=شناسه کاربر
        token_hash=refresh_hash,  # token_hash=هش
        expires_at=refresh_exp,  # expires_at=زمان انقضاء
        revoked=False  # revoked=ابطال نشده
    )  # پایان INSERT
    await database.execute(ins_rt)  # اجرای INSERT

    return {  # return=پاسخ ورود (سازگار با کلاینت)
        "status": "ok",  # status=موفق
        "message": "Login successful",  # message=پیام متنی
        "token": access_token,  # token=اکسس برای سازگاری
        "access_token": access_token,  # access_token=توکن دسترسی
        "refresh_token": refresh_token,  # refresh_token=توکن رفرش
        "user": {  # user=اطلاعات کاربر
            "phone": db_user["phone"],  # phone=شماره
            "address": db_user["address"] or "",  # address=آدرس
            "name": db_user.get("name", "") or ""  # name=نام (جدید؛ اگر ستون تازه اضافه شده باشد ممکن است None برگردد)
        }
    }  # پایان پاسخ

# ——— اندپوینت: رفرش اکسس‌توکن ———
@app.post("/auth/refresh")  # POST=/auth/refresh
async def refresh_access_token(req: dict):  # refresh_access_token=هندلر رفرش اکسس‌توکن
    refresh_token = req.get("refresh_token", "")  # refresh_token=خواندن از بدنه
    if not refresh_token:  # اگر خالی است
        raise HTTPException(status_code=400, detail="refresh_token required")  # 400=درخواست ناقص

    token_hash = hash_refresh_token(refresh_token)  # token_hash=هش رفرش‌توکن
    now = datetime.now(timezone.utc)  # now=زمان فعلی

    sel = RefreshTokenTable.__table__.select().where(  # sel=SELECT رفرش‌توکن معتبر
        (RefreshTokenTable.token_hash == token_hash) &  # شرط=هش برابر
        (RefreshTokenTable.revoked == False) &  # شرط=ابطال نشده
        (RefreshTokenTable.expires_at > now)  # شرط=منقضی نشده
    )  # پایان WHERE
    rt = await database.fetch_one(sel)  # rt=نتیجه
    if not rt:  # اگر یافت نشد
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401=رفرش نامعتبر

    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # sel_user=SELECT کاربر
    db_user = await database.fetch_one(sel_user)  # db_user=رکورد کاربر
    if not db_user:  # اگر کاربر یافت نشد
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # 401=نامعتبر

    new_access = create_access_token(db_user["phone"])  # new_access=ساخت اکسس‌توکن جدید
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # return=پاسخ استاندارد

# ——— اندپوینت: بررسی اعتبار توکن (سازگار قدیمی) ———
@app.get("/verify_token/{token}")  # GET=/verify_token/{token}
async def verify_token(token: str):  # verify_token=اعتبارسنجی با پارامتر مسیر
    try:  # try=دیکد JWT
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode=اعتبارسنجی امضاء/انقضاء
        return {"status": "ok", "valid": True}  # return=معتبر
    except jwt.ExpiredSignatureError:  # except=منقضی
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # return=منقضی
    except Exception:  # except=سایر خطاها
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # return=نامعتبر

# ——— اندپوینت: لیست ماشین‌های کاربر ———
@app.get("/user_cars/{user_phone}")  # GET=/user_cars/{user_phone}
async def get_user_cars(user_phone: str):  # get_user_cars=هندلر خواندن ماشین‌ها
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # query=SELECT کاربر
    user = await database.fetch_one(query)  # user=رکورد
    if user:  # اگر یافت شد
        return user["car_list"] or []  # return=لیست ماشین‌ها (یا لیست خالی)
    raise HTTPException(status_code=404, detail="User not found")  # 404=کاربر نیست

@app.post("/user_cars")  # POST=/user_cars
async def update_user_cars(data: CarListUpdateRequest):  # update_user_cars=ذخیره کل لیست ماشین‌ها
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # sel=SELECT کاربر
    user = await database.fetch_one(sel)  # user=رکورد
    if not user:  # اگر کاربر یافت نشد
        raise HTTPException(status_code=404, detail="User not found")  # 404=خطا
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(
        car_list=[car.dict() for car in data.car_list]  # values=تنظیم car_list به JSON
    )  # پایان UPDATE
    await database.execute(upd)  # اجرای UPDATE
    return {"status": "ok", "message": "cars saved"}  # return=پاسخ موفق

# ——— اندپوینت: ثبت سفارش (افزوده شدن home_number) ———
@app.post("/order")  # POST=/order
async def create_order(order: OrderRequest):  # create_order=ثبت سفارش جدید
    ins = RequestTable.__table__.insert().values(  # ins=INSERT به جدول requests
        user_phone=order.user_phone,  # user_phone=شماره کاربر
        latitude=order.location.latitude,  # latitude=عرض
        longitude=order.location.longitude,  # longitude=طول
        car_list=[car.dict() for car in order.car_list],  # car_list=تبدیل لیست ماشین‌ها به dict
        address=order.address,  # address=آدرس
        home_number=(order.home_number or ""),  # home_number=پلاک منزل (جدید)
        service_type=order.service_type,  # service_type=نوع سرویس
        price=order.price,  # price=قیمت
        request_datetime=order.request_datetime,  # request_datetime=زمان (بدون میلی‌ثانیه - همان مقدار ورودی)
        status="در انتظار",  # status=وضعیت اولیه
        driver_name="",  # driver_name=خالی
        driver_phone="",  # driver_phone=خالی
        finish_datetime="",  # finish_datetime=خالی
        payment_type=order.payment_type  # payment_type=روش پرداخت
    )  # پایان INSERT values
    await database.execute(ins)  # اجرای INSERT
    return {"status": "ok", "message": "request created"}  # return=پاسخ ساده موفق

# ——— اندپوینت: لغو سفارش ———
@app.post("/cancel_order")  # POST=/cancel_order
async def cancel_order(cancel: CancelRequest):  # cancel_order=لغو سفارش «در انتظار» کاربر/سرویس
    upd = RequestTable.__table__.update().where(
        (RequestTable.user_phone == cancel.user_phone) &  # شرط=شماره کاربر
        (RequestTable.service_type == cancel.service_type) &  # شرط=نوع سرویس
        (RequestTable.status == "در انتظار")  # شرط=فقط سفارش‌های «در انتظار»
    ).values(status="کنسل شده")  # values=تغییر وضعیت به «کنسل شده»
    result = await database.execute(upd)  # result=اجرای UPDATE
    if result:  # اگر ردیفی تغییر کرد
        return {"status": "ok", "message": "canceled"}  # return=موفق
    raise HTTPException(status_code=404, detail="active order not found")  # 404=هیچ سفارش فعالی پیدا نشد

# ——— اندپوینت: سرویس‌های فعال کاربر ———
@app.get("/user_active_services/{user_phone}")  # GET=/user_active_services/{user_phone}
async def get_user_active_services(user_phone: str):  # get_user_active_services=خواندن سفارش‌های «در انتظار»
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &  # شرط=شماره کاربر
        (RequestTable.status == "در انتظار")  # شرط=در انتظار
    )  # پایان WHERE
    result = await database.fetch_all(sel)  # result=خواندن لیست
    return [dict(row) for row in result]  # return=لیست dict از سفارش‌ها

# ——— اندپوینت: تاریخچه سفارش‌های کاربر ———
@app.get("/user_orders/{user_phone}")  # GET=/user_orders/{user_phone}
async def get_user_orders(user_phone: str):  # get_user_orders=لیست همه سفارش‌ها
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # sel=SELECT بر اساس شماره
    result = await database.fetch_all(sel)  # result=خواندن همه
    return [dict(row) for row in result]  # return=لیست dict سفارش‌ها

# ——— اندپوینت: لیست کاربران (دیباگ) ———
@app.get("/debug/users")  # GET=/debug/users
async def debug_users():  # debug_users=صرفاً برای تست/دیباگ
    rows = await database.fetch_all(UserTable.__table__.select())  # rows=خواندن همه کاربران
    return [{"id": r["id"], "phone": r["phone"], "name": r.get("name", ""), "address": r["address"]} for r in rows]  # return=لیست ساده کاربران (با name)
# ——— اندپوینت: به‌روزرسانی پروفایل (جدید) ———
@app.post("/user/profile")  # POST=/user/profile
async def update_profile(body: UserProfileUpdate):  # update_profile=ذخیره نام/آدرس کاربر
    if not body.phone.strip():  # اگر شماره خالی است
        raise HTTPException(status_code=400, detail="phone_required")  # خطای 400
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # sel=SELECT کاربر با phone
    user = await database.fetch_one(sel)  # user=رکورد کاربر
    if user is None:  # اگر کاربر موجود نیست
        ins = UserTable.__table__.insert().values(  # ins=INSERT کاربر جدید
            phone=body.phone.strip(),  # phone=شماره
            password_hash="",  # password_hash=خالی (در صورت داشتن ثبت‌نام با پسورد، تکمیل می‌شود)
            address=(body.address or "").strip(),  # address=آدرس (trim)
            name=(body.name or "").strip(),  # name=نام (trim)
            car_list=[]  # car_list=لیست خالی
        )  # پایان INSERT
        await database.execute(ins)  # اجرای INSERT
    else:  # در غیر این صورت (کاربر موجود)
        upd = UserTable.__table__.update().where(UserTable.phone == body.phone).values(  # upd=UPDATE
            name=(body.name or "").strip(),  # name=نام
            address=(body.address or "").strip()  # address=آدرس
        )  # پایان UPDATE
        await database.execute(upd)  # اجرای UPDATE
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # return=پاسخ استاندارد
