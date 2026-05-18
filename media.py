# FILE: media.py
# -*- coding: utf-8 -*-

import io
import os
import re
import secrets
from typing import Tuple

from fastapi import HTTPException, UploadFile
from PIL import Image, ImageOps, UnidentifiedImageError

from config import (
    MAX_IMAGE_BYTES,
    MEDIA_DIR,
    MEDIA_JPEG_QUALITY,
    MEDIA_SAVE_FORMAT,
    MEDIA_TARGET_HEIGHT,
    MEDIA_TARGET_WIDTH,
    MEDIA_URL_PREFIX,
    MEDIA_WEBP_QUALITY,
    PUBLIC_BASE_URL,
)

_ALLOWED_IMAGE_MIMES = {
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
    "image/heic",
    "image/heif",
}


def _safe_relpath(rel: str) -> str:
    rel = (rel or "").replace("\\", "/").strip()
    rel = re.sub(r"^\/*", "", rel)
    rel = re.sub(r"\.\.+", ".", rel)
    return rel.replace("../", "").replace("..\\", "")


def media_url(rel_path: str) -> str | None:
    rel = _safe_relpath(rel_path)
    if not rel:
        return None
    path = f"{MEDIA_URL_PREFIX}/{rel}"
    if PUBLIC_BASE_URL:
        return f"{PUBLIC_BASE_URL.rstrip('/')}{path}"
    return path


def _target_ext_and_mime() -> Tuple[str, str]:
    fmt = MEDIA_SAVE_FORMAT.upper()
    if fmt == "PNG":
        return ".png", "image/png"
    if fmt == "WEBP":
        return ".webp", "image/webp"
    return ".jpg", "image/jpeg"


def _normalize_and_encode_image(data: bytes) -> Tuple[bytes, str]:
    try:
        with Image.open(io.BytesIO(data)) as im:
            im = ImageOps.exif_transpose(im)
            target_fmt = MEDIA_SAVE_FORMAT.upper()

            if target_fmt in ("JPEG", "JPG", "WEBP"):
                if im.mode != "RGB":
                    bg = Image.new("RGB", im.size, (255, 255, 255))
                    if "A" in im.getbands():
                        bg.paste(im, mask=im.getchannel("A"))
                    else:
                        bg.paste(im)
                    im = bg
            else:
                if im.mode not in ("RGBA", "RGB"):
                    im = im.convert("RGBA")

            im.thumbnail(
                (MEDIA_TARGET_WIDTH, MEDIA_TARGET_HEIGHT), Image.Resampling.LANCZOS
            )

            out = io.BytesIO()
            if target_fmt == "PNG":
                im.save(out, format="PNG", optimize=True)
            elif target_fmt == "WEBP":
                im.save(out, format="WEBP", quality=MEDIA_WEBP_QUALITY, method=6)
            else:
                im.save(
                    out,
                    format="JPEG",
                    quality=MEDIA_JPEG_QUALITY,
                    optimize=True,
                    progressive=True,
                )

            _, mime = _target_ext_and_mime()
            return out.getvalue(), mime

    except UnidentifiedImageError:
        raise HTTPException(status_code=400, detail="invalid image file")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"image processing failed: {e}")


async def save_image_upload(
    file: UploadFile, *, subdir: str
) -> Tuple[str, str, int]:
    if not file:
        raise HTTPException(status_code=400, detail="file required")

    raw = await file.read()
    if not raw or len(raw) < 16:
        raise HTTPException(status_code=400, detail="empty file")

    if len(raw) > MAX_IMAGE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"image too large (max {MAX_IMAGE_BYTES} bytes)",
        )

    ct = (file.content_type or "").strip().lower()
    if ct and ct not in _ALLOWED_IMAGE_MIMES:
        raise HTTPException(status_code=400, detail="unsupported image type")

    encoded, mime = _normalize_and_encode_image(raw)
    ext, _ = _target_ext_and_mime()

    name = f"{secrets.token_hex(16)}{ext}"
    subdir_safe = _safe_relpath(subdir)
    abs_dir = os.path.join(MEDIA_DIR, subdir_safe)
    os.makedirs(abs_dir, exist_ok=True)

    abs_path = os.path.join(abs_dir, name)
    with open(abs_path, "wb") as f:
        f.write(encoded)

    rel_path = _safe_relpath(f"{subdir_safe}/{name}")
    return rel_path, mime, len(encoded)


def delete_media_file(rel_path: str) -> None:
    try:
        rel = _safe_relpath(rel_path)
        if not rel:
            return
        abs_path = os.path.join(MEDIA_DIR, rel)
        if os.path.isfile(abs_path):
            os.remove(abs_path)
    except Exception:
        pass
