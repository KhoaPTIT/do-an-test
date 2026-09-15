"""Hash mật khẩu (bcrypt) + JWT cho admin/WebSocket (nhiệm vụ 5.1).

Mật khẩu: không bao giờ lưu/so sánh plain text.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import get_settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_admin_access_token(admin_id: int, username: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(admin_id),
        "username": username,
        "role": "admin",
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_admin_access_token(token: str) -> dict | None:
    """Trả payload nếu token hợp lệ (chữ ký đúng + chưa hết hạn + role=admin),
    None nếu bất kỳ điều kiện nào sai — KHÔNG raise, để gọi được cả từ
    middleware HTTP lẫn WebSocket handshake mà không phải try/except lặp lại.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None

    if payload.get("role") != "admin":
        return None
    return payload
