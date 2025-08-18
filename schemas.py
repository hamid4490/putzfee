from pydantic import BaseModel, Field  # import=BaseModel/Field برای DTOها
from typing import List, Optional  # import=List/Optional برای تایپ‌ها

class CarInfo(BaseModel):  # class=مدل ماشین
    brand: str = Field(..., description="برند")  # brand=برند (اجباری)
    model: str = Field(..., description="مدل")  # model=مدل (اجباری)
    plate: str = Field(..., description="پلاک")  # plate=پلاک (اجباری)

class OrderCreate(BaseModel):  # class=بدنه ثبت سفارش
    user_phone: str = Field(..., description="شماره کاربر")  # user_phone=شماره
    location: dict = Field(..., description="مختصات {latitude,longitude}")  # location=مختصات دیکشنری
    car_list: List[CarInfo] = Field(default_factory=list)  # car_list=لیست ماشین‌ها
    address: str = Field(..., description="آدرس")  # address=آدرس
    home_number: str = Field("", description="پلاک منزل")  # home_number=پلاک منزل (جدید)
    service_type: str = Field(..., description="نوع سرویس")  # service_type=سرویس
    price: int = Field(..., description="قیمت")  # price=قیمت
    request_datetime: str = Field(..., description="زمان بدون میلی‌ثانیه")  # request_datetime=زمان ISO
    payment_type: str = Field("", description="روش پرداخت")  # payment_type=پرداخت

class UserProfileUpdate(BaseModel):  # class=بدنه آپدیت پروفایل
    phone: str = Field(..., description="شماره")  # phone=شماره
    name: str = Field("", description="نام")  # name=نام
    address: str = Field("", description="آدرس")  # address=آدرس

class ApiResponse(BaseModel):  # class=پاسخ استاندارد
    status: str  # status=وضعیت متن (ok/error)
    code: Optional[str] = None  # code=کد ماشین‌خوان
    message: Optional[str] = None  # message=پیام انسانی
    data: Optional[dict] = None  # data=داده خروجی
