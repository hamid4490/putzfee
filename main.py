# -*- coding: utf-8 -*-  # تعیین کدینگ
import os  # ماژول سیستم‌عامل
from fastapi import FastAPI, HTTPException  # فست‌API و استثنا
from pydantic import BaseModel  # مدل پایدانتیک
from typing import Optional, List  # تایپ‌ها
from sqlalchemy import Column, Integer, String, Float, Boolean  # ستون‌ها
from sqlalchemy.dialects.postgresql import JSONB  # نوع JSONB
from sqlalchemy.ext.declarative import declarative_base  # بیس دکلراتیو
from databases import Database  # پایگاه‌داده async
from dotenv import load_dotenv  # بارگذاری env
import sqlalchemy  # SQLAlchemy
from fastapi.middleware.cors import CORSMiddleware  # میان‌افزار CORS

load_dotenv()  # بارگذاری env

DATABASE_URL = os.getenv("DATABASE_URL")  # آدرس دیتابیس

database = Database(DATABASE_URL)  # آبجکت دیتابیس
Base = declarative_base()  # بیس مدل‌ها

app = FastAPI()  # اپ فست‌API

app.add_middleware(  # افزودن CORS
    CORSMiddleware,  # میان‌افزار CORS
    allow_origins=["*"],  # اجازه همه مبداها (برای کلاینت اندروید)
    allow_credentials=True,  # اعتبارنامه
    allow_methods=["*"],  # همه متدها
    allow_headers=["*"],  # همه هدرها
)

class UserTable(Base):  # جدول کاربر
    __tablename__ = "users"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # کلید
    phone = Column(String, unique=True, index=True)  # شماره
    address = Column(String)  # آدرس
    car_list = Column(JSONB, default=list)  # لیست خودروها

class DriverTable(Base):  # جدول راننده
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # کلید
    first_name = Column(String)  # نام
    last_name = Column(String)  # نام‌خانوادگی
    photo_url = Column(String)  # عکس
    id_card_number = Column(String)  # کد ملی/کارت
    phone = Column(String, unique=True)  # شماره
    phone_verified = Column(Boolean, default=False)  # تایید شماره
    is_online = Column(Boolean, default=False)  # آنلاین بودن
    status = Column(String, default="فعال")  # وضعیت

class RequestTable(Base):  # جدول سفارش
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # کلید
    user_phone = Column(String)  # شماره کاربر
    latitude = Column(Float)  # عرض
    longitude = Column(Float)  # طول
    car_list = Column(JSONB)  # لیست خودروها
    address = Column(String)  # آدرس
    service_type = Column(String)  # سرویس
    price = Column(Integer)  # قیمت
    request_datetime = Column(String)  # زمان ثبت
    status = Column(String)  # وضعیت
    driver_name = Column(String)  # نام راننده
    driver_phone = Column(String)  # تلفن راننده
    finish_datetime = Column(String)  # زمان پایان
    payment_type = Column(String)  # پرداخت

class CarInfo(BaseModel):  # مدل ماشین
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک

class Location(BaseModel):  # مدل موقعیت
    latitude: float  # عرض
    longitude: float  # طول

class OrderRequest(BaseModel):  # بدنه ثبت سفارش
    user_phone: str  # شماره
    location: Location  # موقعیت
    car_list: List[CarInfo]  # لیست خودرو
    address: str  # آدرس
    service_type: str  # سرویس
    price: int  # قیمت
    request_datetime: str  # زمان
    payment_type: str  # پرداخت

class CarListUpdateRequest(BaseModel):  # بدنه به‌روزرسانی خودرو
    user_phone: str  # شماره
    car_list: List[CarInfo]  # خودروها

class CancelRequest(BaseModel):  # بدنه کنسل
    user_phone: str  # شماره
    service_type: str  # سرویس

class UserRegisterRequest(BaseModel):  # بدنه ثبت‌نام
    phone: str  # شماره
    address: Optional[str] = None  # آدرس اختیاری

@app.on_event("startup")  # رویداد شروع
async def startup():
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # موتور sync برای create_all
    Base.metadata.create_all(engine)  # ساخت جداول
    await database.connect()  # اتصال دیتابیس

@app.on_event("shutdown")  # رویداد پایان
async def shutdown():
    await database.disconnect()  # قطع اتصال

@app.get("/")  # روت تست
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}  # پیام

# --- مدیریت ماشین‌های کاربر ---

@app.get("/user_cars/{user_phone}")  # گرفتن لیست خودرو
async def get_user_cars(user_phone: str):
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # کوئری
    user = await database.fetch_one(query)  # اجرا
    if user:
        return user["car_list"] or []  # بازگشت لیست
    else:
        raise HTTPException(status_code=404, detail="User not found")  # خطا

@app.post("/user_cars")  # ذخیره لیست خودرو
async def update_user_cars(data: CarListUpdateRequest):
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # کوئری انتخاب
    user = await database.fetch_one(sel)  # اجرا
    if user:
        upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(
            car_list=[car.dict() for car in data.car_list]
        )  # کوئری به‌روزرسانی
        await database.execute(upd)  # اجرا
    else:
        ins = UserTable.__table__.insert().values(
            phone=data.user_phone,
            address="",
            car_list=[car.dict() for car in data.car_list]
        )  # کوئری درج
        await database.execute(ins)  # اجرا
    return {"status": "ok", "message": "لیست ماشین‌ها ذخیره شد"}  # پاسخ

# --- مدیریت سفارش‌ها ---

@app.post("/order")  # ثبت سفارش جدید
async def create_order(order: OrderRequest):
    ins = RequestTable.__table__.insert().values(
        user_phone=order.user_phone,
        latitude=order.location.latitude,
        longitude=order.location.longitude,
        car_list=[car.dict() for car in order.car_list],
        address=order.address,
        service_type=order.service_type,
        price=order.price,
        request_datetime=order.request_datetime,
        status="در انتظار",
        driver_name="",
        driver_phone"",
        finish_datetime="",
        payment_type=order.payment_type
    )  # کوئری درج
    await database.execute(ins)  # اجرا
    return {"status": "ok", "message": "درخواست ثبت شد"}  # پاسخ

@app.get("/orders")  # گرفتن همه سفارش‌ها
async def get_orders():
    query = RequestTable.__table__.select()  # انتخاب
    result = await database.fetch_all(query)  # اجرا
    return [dict(row) for row in result]  # تبدیل به دیکشنری

@app.post("/cancel_order")  # کنسل کردن سفارش
async def cancel_order(cancel: CancelRequest):
    upd = RequestTable.__table__.update().where(
        (RequestTable.user_phone == cancel.user_phone) &
        (RequestTable.service_type == cancel.service_type) &
        (RequestTable.status == "در انتظار")
    ).values(status="کنسل شده")  # کوئری
    res = await database.execute(upd)  # اجرا
    return {"status": "ok", "message": "درخواست کنسل شد"}  # پاسخ (ساده)

@app.get("/user_active_services/{user_phone}")  # سفارش‌های فعال کاربر
async def get_user_active_services(user_phone: str):
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status == "در انتظار")
    )  # کوئری
    result = await database.fetch_all(sel)  # اجرا
    return [dict(row) for row in result]  # پاسخ

@app.get("/user_orders/{user_phone}")  # سفارش‌های یک کاربر (تاریخچه)
async def get_user_orders(user_phone: str):
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # کوئری
    result = await database.fetch_all(sel)  # اجرا
    return [dict(row) for row in result]  # پاسخ

@app.post("/register_user")  # ثبت‌نام کاربر
async def register_user(user: UserRegisterRequest):
    sel = UserTable.__table__.select().where(UserTable.phone == user.phone)  # انتخاب
    existing = await database.fetch_one(sel)  # اجرا
    if existing:
        return {"status": "ok", "message": "User already exists"}  # موجود
    ins = UserTable.__table__.insert().values(
        phone=user.phone,
        address=user.address or "",
        car_list=[]
    )  # درج
    await database.execute(ins)  # اجرا
    return {"status": "ok", "message": "User registered"}  # پاسخ
