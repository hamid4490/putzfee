# -*- coding: utf-8 -*-
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy import Column, Integer, String, Float, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
from databases import Database
from dotenv import load_dotenv
import sqlalchemy
from fastapi.middleware.cors import CORSMiddleware
import hashlib  # برای هش کردن پسورد
import secrets  # برای تولید توکن

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

database = Database(DATABASE_URL)
Base = declarative_base()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# جدول کاربران با فیلد پسورد
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True)
    password_hash = Column(String)  # هش پسورد
    address = Column(String)
    car_list = Column(JSONB, default=list)
    auth_token = Column(String, nullable=True)  # توکن احراز هویت

class DriverTable(Base):
    __tablename__ = "drivers"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    photo_url = Column(String)
    id_card_number = Column(String)
    phone = Column(String, unique=True)
    phone_verified = Column(Boolean, default=False)
    is_online = Column(Boolean, default=False)
    status = Column(String, default="فعال")

class RequestTable(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    car_list = Column(JSONB)
    address = Column(String)
    service_type = Column(String)
    price = Column(Integer)
    request_datetime = Column(String)
    status = Column(String)
    driver_name = Column(String)
    driver_phone = Column(String)
    finish_datetime = Column(String)
    payment_type = Column(String)

# مدل‌های Pydantic
class CarInfo(BaseModel):
    brand: str
    model: str
    plate: str

class Location(BaseModel):
    latitude: float
    longitude: float

class OrderRequest(BaseModel):
    user_phone: str
    location: Location
    car_list: List[CarInfo]
    address: str
    service_type: str
    price: int
    request_datetime: str
    payment_type: str

class CarListUpdateRequest(BaseModel):
    user_phone: str
    car_list: List[CarInfo]

class CancelRequest(BaseModel):
    user_phone: str
    service_type: str

# مدل ثبت‌نام با پسورد
class UserRegisterRequest(BaseModel):
    phone: str
    password: str  # پسورد اضافه شد
    address: Optional[str] = None

# مدل ورود
class UserLoginRequest(BaseModel):
    phone: str
    password: str

# تابع هش کردن پسورد
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# تابع تولید توکن
def generate_token() -> str:
    return secrets.token_urlsafe(32)

@app.on_event("startup")
async def startup():
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))
    Base.metadata.create_all(engine)
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/")
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}

# --- احراز هویت ---

@app.post("/register_user")
async def register_user(user: UserRegisterRequest):
    # چک کردن وجود کاربر
    query = UserTable.__table__.select().where(UserTable.phone == user.phone)
    existing = await database.fetch_one(query)
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # هش کردن پسورد
    password_hash = hash_password(user.password)
    
    # ثبت کاربر جدید
    query = UserTable.__table__.insert().values(
        phone=user.phone,
        password_hash=password_hash,
        address=user.address or "",
        car_list=[]
    )
    await database.execute(query)
    return {"status": "ok", "message": "User registered successfully"}

@app.post("/login")
async def login_user(user: UserLoginRequest):
    # پیدا کردن کاربر
    query = UserTable.__table__.select().where(UserTable.phone == user.phone)
    db_user = await database.fetch_one(query)
    
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # چک کردن پسورد
    password_hash = hash_password(user.password)
    if db_user["password_hash"] != password_hash:
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # تولید توکن جدید
    token = generate_token()
    
    # ذخیره توکن در دیتابیس
    update_query = UserTable.__table__.update().where(
        UserTable.phone == user.phone
    ).values(auth_token=token)
    await database.execute(update_query)
    
    return {
        "status": "ok",
        "message": "Login successful",
        "token": token,
        "user": {
            "phone": db_user["phone"],
            "address": db_user["address"]
        }
    }

# --- مدیریت ماشین‌های کاربر ---

@app.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str):
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)
    user = await database.fetch_one(query)
    if user:
        return user["car_list"] or []
    else:
        raise HTTPException(status_code=404, detail="User not found")

@app.post("/user_cars")
async def update_user_cars(data: CarListUpdateRequest):
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)
    user = await database.fetch_one(sel)
    if user:
        upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(
            car_list=[car.dict() for car in data.car_list]
        )
        await database.execute(upd)
    else:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "message": "لیست ماشین‌ها ذخیره شد"}

# --- مدیریت سفارش‌ها ---

@app.post("/order")
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
        driver_phone="",
        finish_datetime="",
        payment_type=order.payment_type
    )
    await database.execute(ins)
    return {"status": "ok", "message": "درخواست ثبت شد"}

@app.get("/orders")
async def get_orders():
    query = RequestTable.__table__.select()
    result = await database.fetch_all(query)
    return [dict(row) for row in result]

@app.post("/cancel_order")
async def cancel_order(cancel: CancelRequest):
    upd = RequestTable.__table__.update().where(
        (RequestTable.user_phone == cancel.user_phone) &
        (RequestTable.service_type == cancel.service_type) &
        (RequestTable.status == "در انتظار")
    ).values(status="کنسل شده")
    result = await database.execute(upd)
    if result:
        return {"status": "ok", "message": "درخواست کنسل شد"}
    else:
        raise HTTPException(status_code=404, detail="سفارش فعال پیدا نشد")

@app.get("/user_active_services/{user_phone}")
async def get_user_active_services(user_phone: str):
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status == "در انتظار")
    )
    result = await database.fetch_all(sel)
    return [dict(row) for row in result]

@app.get("/user_orders/{user_phone}")
async def get_user_orders(user_phone: str):
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)
    result = await database.fetch_all(sel)
    return [dict(row) for row in result]

# --- endpoint جدید برای چک کردن وضعیت احراز هویت ---
@app.get("/verify_token/{token}")
async def verify_token(token: str):
    query = UserTable.__table__.select().where(UserTable.auth_token == token)
    user = await database.fetch_one(query)
    if user:
        return {
            "status": "ok",
            "valid": True,
            "user": {
                "phone": user["phone"],
                "address": user["address"]
            }
        }
    else:
        return {"status": "error", "valid": False}
