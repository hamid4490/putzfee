# فایل: logger.py

from loguru import logger

logger.add("logs/server_{time}.log", rotation="1 week", retention="1 month", level="INFO")