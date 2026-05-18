# Putz Backend v2

FastAPI + PostgreSQL backend — refactored into clean modules.

## ساختار فایل‌ها

```
putz_backend/
├── main.py               # FastAPI app + lifespan
├── config.py             # تمام env variables
├── database.py           # اتصال DB + ORM models
├── schemas.py            # Pydantic request/response models
├── utils.py              # phone, time, security, auth guards
├── media.py              # image upload/resize/delete
├── push.py               # FCM v1, FCM legacy, ntfy
├── routers/
│   ├── auth.py           # register, login, refresh, logout, push tokens
│   ├── user.py           # profile, cars, photo, notifications
│   ├── orders.py         # create/list/cancel orders, reviews, public home
│   ├── scheduling.py     # slots, confirm, price, finish, cancel
│   └── admin.py          # active requests, services, promotions, reviews
├── alembic/
│   ├── env.py
│   └── versions/
│       └── 0001_initial_schema.py
├── alembic.ini
├── requirements.txt
└── .env.example
```

## نصب و راه‌اندازی

### ۱. نصب dependencies

```bash
pip install -r requirements.txt
```

### ۲. تنظیم env

```bash
cp .env.example .env
# فایل .env رو ویرایش کن
```

### ۳. اجرای migrations

```bash
# اگه دیتابیس جدید هست:
alembic upgrade head

# یا اگه ENABLE_SCHEMA_CREATE=true باشه، هنگام startup خودکار ساخته می‌شه
```

### ۴. اجرای سرور

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## Alembic — مدیریت migration

```bash
# ساخت migration جدید
alembic revision --autogenerate -m "add new column"

# اعمال migrations
alembic upgrade head

# برگشت به نسخه قبل
alembic downgrade -1
```

## API Endpoints

### Auth
| Method | Path | توضیح |
|--------|------|-------|
| POST | /register_user | ثبت‌نام |
| POST | /login | ورود کاربر |
| POST | /admin/login | ورود مدیر |
| POST | /auth/refresh | refresh token |
| POST | /logout | خروج |
| GET | /verify_token | اعتبارسنجی token |
| GET | /users/exists | چک وجود کاربر |
| POST | /push/register | ثبت device token |
| POST | /push/unregister | حذف device token |

### User
| Method | Path | توضیح |
|--------|------|-------|
| GET | /user/profile/{phone} | پروفایل |
| POST | /user/profile | آپدیت پروفایل |
| POST | /user/{phone}/photo | آپلود عکس |
| GET | /user_cars/{phone} | لیست خودروها |
| POST | /user_cars | آپدیت خودروها |
| GET | /notifications/{phone} | نوتیفیکیشن‌ها |
| POST | /notifications/{phone}/read | خوانده شده |

### Orders
| Method | Path | توضیح |
|--------|------|-------|
| POST | /order | ثبت سفارش |
| GET | /user_orders/{phone} | سفارش‌های کاربر |
| POST | /cancel_order | لغو سفارش |
| GET | /reviews | نظرات عمومی |
| POST | /order/{id}/review/submit | ثبت نظر |
| GET | /public/home | صفحه اصلی عمومی |

### Scheduling
| Method | Path | توضیح |
|--------|------|-------|
| GET | /public/busy_slots | اسلات‌های مشغول (بدون auth) |
| GET | /busy_slots | اسلات‌های مشغول (admin) |
| POST | /order/{id}/propose_slots | پیشنهاد زمان (admin) |
| GET | /order/{id}/proposed_slots | زمان‌های پیشنهادی (user) |
| POST | /order/{id}/confirm_slot | تأیید زمان (user) |
| POST | /order/{id}/reject_all_and_cancel | رد و لغو (user) |
| POST | /admin/order/{id}/price | تعیین قیمت (admin) |
| POST | /order/{id}/finish | پایان سفارش (admin) |
| POST | /admin/order/{id}/cancel | لغو توسط admin |

### Admin
| Method | Path | توضیح |
|--------|------|-------|
| GET | /admin/requests/active | سفارش‌های فعال |
| GET | /admin/reviews | مدیریت نظرات |
| POST | /admin/reviews/{id}/decide | تأیید/رد نظر |
| GET | /admin/services | لیست سرویس‌ها |
| POST | /admin/services | افزودن/ویرایش سرویس |
| GET | /admin/promotions | تخفیف‌ها |
| POST | /admin/promotions | افزودن تخفیف |
| PUT | /admin/promotions/{id} | ویرایش تخفیف |
| DELETE | /admin/promotions/{id} | حذف تخفیف |
