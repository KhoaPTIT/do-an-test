"""Xác định IP nguồn của request (nhiệm vụ 6.1 — cần cho
scripts/impossible_travel giả lập IP nguồn khác nhau qua header khi demo).
"""

from __future__ import annotations

from fastapi import Request

from app.config import get_settings


def resolve_client_ip(request: Request) -> str:
    """Mặc định dùng IP TCP thật. Chỉ đọc X-Forwarded-For khi
    `TRUST_FORWARDED_FOR=true` được bật tường minh trong .env (xem cảnh
    báo trong app/config.py) — dùng cho demo impossible_travel cục bộ.
    """
    settings = get_settings()
    if settings.trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()

    return request.client.host if request.client else "unknown"
