import os
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from databases import Database
from dotenv import load_dotenv
import datetime

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

database = Database(DATABASE_URL)
Base = declarative_base()

app = FastAPI()

# SQLAlchemy Models
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True)
    address = Column(String)

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
    brand = Column(String)
    model = Column(String)
    plate = Column(String)
    address = Column(String)
    service_type = Column(String)
    price = Column(Integer)
    request_datetime = Column(String)
    status = Column(String)
    driver_name = Column(String)
    driver_phone = Column(String)
    finish_datetime = Column(String)
    payment_type = Column(String)

# Pydantic Models
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
    car_info: CarInfo
    address: str
    service_type: str
    price: int
    request_datetime: str
    payment_type: str

class User(BaseModel):
    phone: str
    address: Optional[str] = None

class Driver(BaseModel):
    first_name: str
    last_name: str
    photo_url: Optional[str] = None
    id_card_number: str
    phone: str
    phone_verified: bool = False
    is_online: bool = False
    status: str = "فعال"

@app.on_event("startup")
async def startup():
    import sqlalchemy
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))
    Base.metadata.create_all(engine)
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/")
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}

@app.post("/order")
async def create_order(order: OrderRequest):
    query = RequestTable.__table__.insert().values(
        user_phone=order.user_phone,
        latitude=order.location.latitude,
        longitude=order.location.longitude,
        brand=order.car_info.brand,
        model=order.car_info.model,
        plate=order.car_info.plate,
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
    await database.execute(query)
    return {"status": "ok", "message": "درخواست ثبت شد"}

@app.get("/orders")
async def get_orders():
    query = RequestTable.__table__.select()
    result = await database.fetch_all(query)
    return [dict(row) for row in result]