# -*- coding: utf-8 -*-  # تعیین کدینگ فایل به UTF-8
import os  # ایمپورت ماژول سیستم‌عامل برای دسترسی به متغیرهای محیطی
from fastapi import FastAPI, HTTPException  # ایمپورت FastAPI و استثنای HTTP
from pydantic import BaseModel  # ایمپورت BaseModel برای مدل‌های ورودی/خروجی
from typing import Optional, List  # ایمپورت تایپ‌های اختیاری و لیست
from sqlalchemy import Column, Integer, String, Float, Boolean  # ایمپورت انواع ستون‌های SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB  # ایمپورت نوع JSONB مخصوص پستگرس
from sqlalchemy.orm import declarative_base  # ایمپورت بیس دکلراتیو SQLAlchemy
from databases import Database  # ایمپورت لایه دیتابیس async
from dotenv import load_dotenv  # ایمپورت برای بارگذاری .env
import sqlalchemy  # ایمپورت SQLAlchemy برای ساخت engine
from fastapi.middleware.cors import CORSMiddleware  # ایمپورت میان‌افزار CORS

load_dotenv()  # بارگذاری متغیرهای محیطی از فایل .env

DATABASE_URL = os.getenv("DATABASE_URL")  # گرفتن آدرس دیتابیس از متغیر محیطی

database = Database(DATABASE_URL)  # ساخت آبجکت دیتابیس async با URL
Base = declarative_base()  # ایجاد کلاس بیس برای مدل‌های ORM

app = FastAPI()  # ساخت اپلیکیشن FastAPI

app.add_middleware(  # افزودن میان‌افزار CORS به اپ
    CORSMiddleware,  # کلاس میان‌افزار CORS
    allow_origins=["*"],  # اجازه دسترسی از همه مبداها
    allow_credentials=True,  # اجازه ارسال کوکی/اعتبارنامه
    allow_methods=["*"],  # اجازه همه متدها (GET/POST/...)
    allow_headers=["*"],  # اجازه همه هدرها
)

class UserTable(Base):  # تعریف مدل ORM جدول users
    __tablename__ = "users"  # نام جدول در دیتابیس
    id = Column(Integer, primary_key=True, index=True)  # ستون id به‌عنوان کلید اصلی با ایندکس
    phone = Column(String, unique=True, index=True)  # ستون phone یونیک و ایندکس‌شده
    address = Column(String)  # ستون آدرس
    car_list = Column(JSONB, default=list)  # ستون لیست ماشین‌ها با نوع JSONB و مقدار پیش‌فرض لیست

class DriverTable(Base):  # تعریف مدل ORM جدول drivers
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # ستون id
    first_name = Column(String)  # نام
    last_name = Column(String)  # نام خانوادگی
    photo_url = Column(String)  # آدرس عکس
    id_card_number = Column(String)  # شماره کارت/کد ملی
    phone = Column(String, unique=True)  # شماره تلفن یونیک
    phone_verified = Column(Boolean, default=False)  # وضعیت تایید تلفن
    is_online = Column(Boolean, default=False)  # وضعیت آنلاین بودن
    status = Column(String, default="فعال")  # وضعیت راننده

class RequestTable(Base):  # تعریف مدل ORM جدول requests (سفارش‌ها)
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # ستون id
    user_phone = Column(String)  # شماره تلفن کاربر سفارش‌دهنده
    latitude = Column(Float)  # عرض جغرافیایی
    longitude = Column(Float)  # طول جغرافیایی
    car_list = Column(JSONB)  # لیست ماشین‌ها به‌صورت JSONB
    address = Column(String)  # آدرس
    service_type = Column(String)  # نوع سرویس
    price = Column(Integer)  # قیمت
    request_datetime = Column(String)  # تاریخ/زمان ثبت سفارش
    status = Column(String)  # وضعیت سفارش
    driver_name = Column(String)  # نام راننده
    driver_phone = Column(String)  # تلفن راننده
    finish_datetime = Column(String)  # تاریخ/زمان پایان
    payment_type = Column(String)  # نوع پرداخت

class CarInfo(BaseModel):  # مدل پایدانتیک اطلاعات ماشین
    brand: str  # برند ماشین
    model: str  # مدل ماشین
    plate: str  # پلاک ماشین

class Location(BaseModel):  # مدل پایدانتیک موقعیت جغرافیایی
    latitude: float  # عرض جغرافیایی
    longitude: float  # طول جغرافیایی

class OrderRequest(BaseModel):  # مدل پایدانتیک بدنه ثبت سفارش
    user_phone: str  # شماره موبایل کاربر
    location: Location  # موقعیت انتخاب‌شده
    car_list: List[CarInfo]  # لیست ماشین‌ها
    address: str  # آدرس
    service_type: str  # نوع سرویس
    price: int  # قیمت
    request_datetime: str  # زمان ثبت به‌صورت رشته (مثلاً ISO)
    payment_type: str  # نوع پرداخت

class CarListUpdateRequest(BaseModel):  # مدل پایدانتیک به‌روزرسانی لیست ماشین
    user_phone: str  # شماره موبایل
    car_list: List[CarInfo]  # لیست ماشین‌ها

class CancelRequest(BaseModel):  # مدل پایدانتیک بدنه کنسل سفارش
    user_phone: str  # شماره موبایل
    service_type: str  # نوع سرویس

class UserRegisterRequest(BaseModel):  # مدل پایدانتیک بدنه ثبت‌نام کاربر
    phone: str  # شماره موبایل
    address: Optional[str] = None  # آدرس اختیاری

@app.on_event("startup")  # هندلر رویداد شروع سرویس
async def startup():  # تابع Async شروع
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # ساخت موتور Sync برای create_all (حذف asyncpg از URI)
    Base.metadata.create_all(engine)  # ساخت جداول در دیتابیس
    await database.connect()  # اتصال Async به دیتابیس

@app.on_event("shutdown")  # هندلر رویداد خاموشی
async def shutdown():  # تابع Async خاموشی
    await database.disconnect()  # قطع اتصال دیتابیس

@app.get("/")  # روت اصلی برای تست سلامت
def read_root():  # تابع همگام (Sync) ساده
    return {"message": "Putzfee FastAPI Server is running!"}  # پاسخ تست

# --- مدیریت ماشین‌های کاربر ---

@app.get("/user_cars/{user_phone}")  # گرفتن لیست ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # تابع Async با پارامتر شماره موبایل
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # ساخت کوئری انتخاب کاربر با این شماره
    user = await database.fetch_one(query)  # اجرای کوئری و دریافت یک ردیف
    if user:  # وجود کاربر
        return user["car_list"] or []  # بازگرداندن لیست ماشین‌ها یا لیست خالی
    else:  # عدم وجود کاربر
        raise HTTPException(status_code=404, detail="User not found")  # پرتاب خطای ۴۰۴

@app.post("/user_cars")  # ذخیره/به‌روزرسانی لیست ماشین‌های کاربر
async def update_user_cars(data: CarListUpdateRequest):  # تابع Async با بدنه ورودی
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # کوئری انتخاب کاربر
    user = await database.fetch_one(sel)  # اجرای کوئری
    if user:  # کاربر موجود
        upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(  # ساخت کوئری آپدیت
            car_list=[car.dict() for car in data.car_list]  # مقدار جدید ستون car_list به‌صورت لیست دیکشنری
        )
        await database.execute(upd)  # اجرای آپدیت
    else:  # کاربر موجود نیست
        ins = UserTable.__table__.insert().values(  # ساخت کوئری درج کاربر جدید
            phone=data.user_phone,  # مقدار شماره موبایل
            address="",  # آدرس خالی
            car_list=[car.dict() for car in data.car_list]  # لیست ماشین‌ها
        )
        await database.execute(ins)  # اجرای درج
    return {"status": "ok", "message": "لیست ماشین‌ها ذخیره شد"}  # پاسخ موفقیت

# --- مدیریت سفارش‌ها ---

@app.post("/order")  # ثبت سفارش جدید
async def create_order(order: OrderRequest):  # تابع Async ثبت سفارش
    ins = RequestTable.__table__.insert().values(  # ساخت کوئری درج سفارش
        user_phone=order.user_phone,  # شماره کاربر
        latitude=order.location.latitude,  # عرض جغرافیایی
        longitude=order.location.longitude,  # طول جغرافیایی
        car_list=[car.dict() for car in order.car_list],  # لیست ماشین‌ها به‌صورت JSON
        address=order.address,  # آدرس
        service_type=order.service_type,  # نوع سرویس
        price=order.price,  # قیمت
        request_datetime=order.request_datetime,  # زمان ثبت
        status="در انتظار",  # وضعیت اولیه
        driver_name="",  # نام راننده (خالی در شروع)
        driver_phone="",  # تلفن راننده (خالی در شروع)  ← ← این خط اصلاح شد (اضافه شدن علامت =)
        finish_datetime="",  # زمان پایان (خالی)
        payment_type=order.payment_type  # نوع پرداخت
    )
    await database.execute(ins)  # اجرای درج
    return {"status": "ok", "message": "درخواست ثبت شد"}  # پاسخ موفقیت

@app.get("/orders")  # گرفتن لیست همه سفارش‌ها
async def get_orders():  # تابع Async
    query = RequestTable.__table__.select()  # ساخت کوئری انتخاب همه ردیف‌ها
    result = await database.fetch_all(query)  # اجرای کوئری و دریافت همه نتایج
    return [dict(row) for row in result]  # تبدیل هر ردیف به دیکشنری و بازگشت لیست

@app.post("/cancel_order")  # کنسل کردن سفارش در انتظار
async def cancel_order(cancel: CancelRequest):  # تابع Async با بدنه کنسل
    upd = RequestTable.__table__.update().where(  # ساخت کوئری آپدیت
        (RequestTable.user_phone == cancel.user_phone) &  # شرط شماره کاربر
        (RequestTable.service_type == cancel.service_type) &  # شرط نوع سرویس
        (RequestTable.status == "در انتظار")  # فقط سفارش‌های در انتظار
    ).values(status="کنسل شده")  # تغییر وضعیت به کنسل شده
    await database.execute(upd)  # اجرای آپدیت
    return {"status": "ok", "message": "درخواست کنسل شد"}  # پاسخ موفقیت

@app.get("/user_active_services/{user_phone}")  # گرفتن سفارش‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # تابع Async
    sel = RequestTable.__table__.select().where(  # ساخت کوئری انتخاب
        (RequestTable.user_phone == user_phone) &  # شرط شماره کاربر
        (RequestTable.status == "در انتظار")  # وضعیت در انتظار
    )
    result = await database.fetch_all(sel)  # اجرای کوئری
    return [dict(row) for row in result]  # تبدیل به لیست دیکشنری و بازگشت

@app.get("/user_orders/{user_phone}")  # گرفتن همه سفارش‌های یک کاربر
async def get_user_orders(user_phone: str):  # تابع Async
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # ساخت کوئری
    result = await database.fetch_all(sel)  # اجرای کوئری
    return [dict(row) for row in result]  # بازگشت لیست سفارش‌ها

@app.post("/register_user")  # ثبت‌نام کاربر
async def register_user(user: UserRegisterRequest):  # تابع Async
    sel = UserTable.__table__.select().where(UserTable.phone == user.phone)  # کوئری بررسی وجود کاربر
    existing = await database.fetch_one(sel)  # اجرای کوئری
    if existing:  # کاربر قبلاً ثبت شده
        return {"status": "ok", "message": "User already exists"}  # پیام موجود بودن
    ins = UserTable.__table__.insert().values(  # ساخت کوئری درج کاربر جدید
        phone=user.phone,  # شماره موبایل
        address=user.address or "",  # آدرس یا رشته خالی
        car_list=[]  # لیست ماشین‌ها خالی
    )
    await database.execute(ins)  # اجرای درج
    return {"status": "ok", "message": "User registered"}  # پاسخ موفقیت
