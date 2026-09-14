"""Đếm login fail bằng Redis sliding window (nhiệm vụ 3.2).

Dùng sorted set (ZADD): mỗi lần fail thêm 1 phần tử với score = timestamp.
Khi đếm, xoá trước các phần tử cũ hơn cửa sổ (ZREMRANGEBYSCORE) rồi đếm còn
lại (ZCARD) — đây là sliding window "thật", chính xác hơn fixed-window
INCR+EXPIRE khi request rải không đều trong cửa sổ.

Mỗi key luôn có EXPIRE ngắn hơn không nhiều so với cửa sổ, để không leak bộ
nhớ Redis kể cả khi key không còn được động tới nữa.
"""

from __future__ import annotations

import time
import uuid

import redis

from app.config import get_settings

_settings = get_settings()
redis_client = redis.Redis.from_url(_settings.redis_url, decode_responses=True)

# ⚠️ Giả định (docs/api-contract.md mục 6) — chưa có trong tài liệu gốc.
FAIL_WINDOW_SECONDS = 5 * 60  # 5 phút


def _ttl_buffer_seconds() -> int:
    return FAIL_WINDOW_SECONDS + 60


def record_fail(key: str, client: "redis.Redis | None" = None, now: float | None = None) -> int:
    """Ghi nhận 1 lần fail vào `key`, trả về số lần fail hiện tại trong cửa sổ."""
    client = client or redis_client
    now = now if now is not None else time.time()
    # uuid4 đảm bảo member không bao giờ trùng, kể cả khi 2 lần fail rơi
    # đúng cùng 1 tick thời gian (id(object()) từng bị lỗi trùng ở đây vì
    # CPython tái sử dụng địa chỉ bộ nhớ của object vừa bị giải phóng).
    member = f"{now}:{uuid.uuid4().hex}"

    pipe = client.pipeline()
    pipe.zadd(key, {member: now})
    pipe.zremrangebyscore(key, 0, now - FAIL_WINDOW_SECONDS)
    pipe.expire(key, _ttl_buffer_seconds())
    pipe.zcard(key)
    results = pipe.execute()
    return results[-1]


def check_fail_count(key: str, client: "redis.Redis | None" = None, now: float | None = None) -> int:
    """Đếm số lần fail hiện tại trong cửa sổ mà KHÔNG ghi thêm."""
    client = client or redis_client
    now = now if now is not None else time.time()
    client.zremrangebyscore(key, 0, now - FAIL_WINDOW_SECONDS)
    return client.zcard(key)


def record_credential_stuffing_attempt(
    ip: str, username: str, client: "redis.Redis | None" = None, now: float | None = None
) -> int:
    """Ghi nhận 1 username bị thử từ `ip`, trả về số USERNAME KHÁC NHAU
    (distinct) đã thử từ IP này trong cửa sổ hiện tại.

    Dùng sorted set với member=username (tự dedup) và score=lần gần nhất
    thấy username đó — vừa đếm distinct, vừa tự "trượt" theo thời gian.
    """
    client = client or redis_client
    now = now if now is not None else time.time()
    key = f"cred_stuffing:{ip}"

    pipe = client.pipeline()
    pipe.zadd(key, {username: now})
    pipe.zremrangebyscore(key, 0, now - FAIL_WINDOW_SECONDS)
    pipe.expire(key, _ttl_buffer_seconds())
    pipe.zcard(key)
    results = pipe.execute()
    return results[-1]


def reset(key: str, client: "redis.Redis | None" = None) -> None:
    client = client or redis_client
    client.delete(key)
