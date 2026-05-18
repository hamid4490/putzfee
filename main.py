# FILE: main.py
# -*- coding: utf-8 -*-

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from config import ALLOW_ORIGINS_ENV, MEDIA_DIR, MEDIA_URL_PREFIX
from database import create_all_tables, database
from routers import admin, auth, orders, scheduling, user

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("putz")

# -------------------- Media dirs --------------------
os.makedirs(MEDIA_DIR, exist_ok=True)
for sub in ("users", "promotions", "services"):
    os.makedirs(os.path.join(MEDIA_DIR, sub), exist_ok=True)


# -------------------- Lifespan --------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    create_all_tables()
    await database.connect()
    logger.info("Database connected.")
    yield
    await database.disconnect()
    logger.info("Database disconnected.")


# -------------------- App --------------------
app = FastAPI(
    title="Putz API",
    version="2.0.0",
    lifespan=lifespan,
)

# Static media
app.mount(MEDIA_URL_PREFIX, StaticFiles(directory=MEDIA_DIR), name="")

# CORS
allow_origins = (
    ["*"]
    if ALLOW_ORIGINS_ENV == "*"
    else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Routers --------------------
app.include_router(auth.router)
app.include_router(user.router)
app.include_router(orders.router)
app.include_router(scheduling.router)
app.include_router(admin.router)


# -------------------- Health --------------------
@app.get("/")
def read_root():
    return {"message": "Putz API v2 is running"}
