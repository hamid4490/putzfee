"""Image upload + resize/compress utilities."""

from __future__ import annotations

import io
import os
import secrets
from pathlib import Path
from typing import Optional, Tuple

from fastapi import HTTPException, UploadFile, status
from PIL import Image, ImageOps

from .config import get_settings

_ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp"}


def media_root() -> Path:
    s = get_settings()
    root = Path(s.MEDIA_DIR).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


async def save_image(file: UploadFile, sub_dir: str = "images") -> str:
    """Validate, resize, save *file* and return its public URL path.

    Returns a URL relative to ``PUBLIC_BASE_URL`` so that the absolute
    URL can be reconstructed by callers if needed.
    """
    s = get_settings()
    if file.content_type not in _ALLOWED_MIME:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="unsupported image type",
        )
    raw = await file.read()
    if len(raw) > s.MAX_IMAGE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="image too large",
        )
    try:
        img = Image.open(io.BytesIO(raw))
        img = ImageOps.exif_transpose(img)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid image"
        ) from exc

    target = (s.MEDIA_TARGET_WIDTH, s.MEDIA_TARGET_HEIGHT)
    img.thumbnail(target)
    fmt = s.MEDIA_SAVE_FORMAT.lower()
    if fmt not in ("webp", "jpeg"):
        fmt = "webp"
    buf = io.BytesIO()
    save_kwargs: dict = {}
    if fmt == "webp":
        save_kwargs["quality"] = s.MEDIA_WEBP_QUALITY
        save_kwargs["method"] = 6
        if img.mode in ("RGBA", "LA"):
            pass  # webp supports alpha
        else:
            img = img.convert("RGB")
    else:
        save_kwargs["quality"] = s.MEDIA_JPEG_QUALITY
        save_kwargs["optimize"] = True
        if img.mode != "RGB":
            img = img.convert("RGB")
    img.save(buf, format=fmt.upper(), **save_kwargs)
    buf.seek(0)

    name = f"{secrets.token_urlsafe(12)}.{fmt}"
    sub = (media_root() / sub_dir).resolve()
    sub.mkdir(parents=True, exist_ok=True)
    out_path = sub / name
    out_path.write_bytes(buf.getvalue())
    rel = f"{s.MEDIA_URL_PREFIX.rstrip('/')}/{sub_dir}/{name}"
    return rel


def absolute_url(rel_url: Optional[str]) -> Optional[str]:
    if not rel_url:
        return None
    s = get_settings()
    base = s.PUBLIC_BASE_URL.rstrip("/")
    if rel_url.startswith("http://") or rel_url.startswith("https://"):
        return rel_url
    return f"{base}{rel_url}"


def delete_media(rel_url: Optional[str]) -> None:
    if not rel_url:
        return
    s = get_settings()
    if not rel_url.startswith(s.MEDIA_URL_PREFIX):
        return
    rel = rel_url[len(s.MEDIA_URL_PREFIX) :].lstrip("/")
    path = (media_root() / rel).resolve()
    try:
        # ensure path is within media_root
        if media_root() in path.parents:
            os.remove(path)
    except FileNotFoundError:
        pass
