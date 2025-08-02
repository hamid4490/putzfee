# فایل: schemas.py

from pydantic import BaseModel, Field, validator
import re

class UserCreate(BaseModel):
    phone: str = Field(..., regex="^09\d{9}$")
    password: str = Field(..., min_length=6)
    name: str = ""
    address: str = ""

    @validator("phone")
    def validate_phone(cls, v):
        if not re.match(r"^09\d{9}$", v):
            raise ValueError("شماره موبایل معتبر نیست")
        return v

class CarCreate(BaseModel):
    brand: str
    model: str
    plate: str

    @validator("plate")
    def validate_plate(cls, v):
        # نمونه ساده: پلاک باید شامل عدد و حرف باشد
        if not re.match(r"^[0-9]{2,3}[A-Zآ-ی]{1,2}-[0-9]{3,4}$", v):
            raise ValueError("فرمت پلاک معتبر نیست")
        return v

class OrderCreate(BaseModel):
    user_phone: str
    car_plate: str
    service_type: str
    address: str
    price: int
    payment_type: str