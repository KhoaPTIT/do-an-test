"""Rule-based detection tầng 1 (nhiệm vụ 3.3): brute force, credential
stuffing, impossible travel.

Ngưỡng impossible travel (~900 km/h) lấy trực tiếp từ checklist gốc mục
3.3. Ngưỡng brute force / credential stuffing là ⚠️ giả định — xem
docs/api-contract.md mục 6, cần đối chiếu khi có tài liệu "Kế hoạch đồ án".
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from datetime import datetime

from app.detection.rate_counter import (
    FAIL_WINDOW_SECONDS,
    check_fail_count,
    record_credential_stuffing_attempt,
    record_fail,
)
from app.utils.time import ensure_utc

EARTH_RADIUS_KM = 6371.0

# Lấy nguyên văn từ checklist gốc mục 3.3.
IMPOSSIBLE_TRAVEL_SPEED_KMH = 900.0

# ⚠️ Giả định — docs/api-contract.md mục 6.
BRUTE_FORCE_THRESHOLD = 5
CREDENTIAL_STUFFING_FAIL_THRESHOLD = 10
CREDENTIAL_STUFFING_MIN_DISTINCT_USERNAMES = 5


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Khoảng cách great-circle giữa 2 toạ độ (km)."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


@dataclass
class GeoPoint:
    latitude: float | None
    longitude: float | None
    timestamp: datetime


def is_impossible_travel(previous: GeoPoint | None, current: GeoPoint) -> bool:
    """So 2 lần đăng nhập gần nhất; bỏ qua (trả False) nếu thiếu GeoIP ở
    1 trong 2 lần — đúng yêu cầu checklist, không được báo nhầm khi thiếu dữ liệu.
    """
    if previous is None:
        return False
    if previous.latitude is None or previous.longitude is None:
        return False
    if current.latitude is None or current.longitude is None:
        return False

    # ⚠️ Bug thật phát hiện ở MR13 (không phải giả thuyết): `previous.timestamp` đọc lại từ SQLite (test) mất tzinfo
    # (naive, bị hiểu ngầm là UTC) trong khi `current.timestamp` vừa gán trong Python vẫn còn aware — trừ hai loại
    # datetime khác nhau raise TypeError. Trên Postgres thật (TIMESTAMP WITH TIME ZONE) không xảy ra (cả hai đều
    # aware), nhưng ĐÂY LÀ Ổ GÀ CHỜ SẴN — cùng lớp lỗi đã sửa ở MR9 (replay.py) và MR12 (app/utils/time.ensure_utc),
    # applying ở nguồn cụ thể của lỗi đó thay vì né bằng dữ liệu test khác.
    elapsed_hours = (ensure_utc(current.timestamp) - ensure_utc(previous.timestamp)).total_seconds() / 3600
    if elapsed_hours <= 0:
        return False  # timestamp không hợp lệ / trùng nhau, không kết luận được

    distance_km = haversine_distance(previous.latitude, previous.longitude, current.latitude, current.longitude)
    speed_kmh = distance_km / elapsed_hours
    return speed_kmh > IMPOSSIBLE_TRAVEL_SPEED_KMH


def register_login_failure(username: str, ip: str, *, now: float | None = None) -> None:
    """Gọi sau MỖI lần đăng nhập thất bại để cập nhật các counter Redis. `now`: epoch giây của SỰ KIỆN — mặc định
    `None` dùng `time.time()` thật (đúng cho luồng sống); BẮT BUỘC truyền `now` khi phát lại/mô phỏng với timestamp
    KHÔNG PHẢI giờ hiện tại thật, nếu không cửa sổ Redis (TTL thật) đếm theo tốc độ CHẠY SCRIPT chứ không theo tốc độ
    tấn công mô phỏng — bug thật tự phát hiện ở MR18 (`ml/attack_scenarios.py`: kịch bản "rải mật khẩu chậm" cách nhau
    hàng chục phút THEO TIMESTAMP MÔ PHỎNG vẫn bị `credential_stuffing` bắt nhầm vì cả 18 lần gọi Redis xảy ra trong
    vài GIÂY THẬT khi script chạy)."""
    record_fail(f"fail:{username}", now=now)
    record_fail(f"fail_ip:{ip}", now=now)
    record_credential_stuffing_attempt(ip, username, now=now)


def is_brute_force(username: str, *, now: float | None = None) -> bool:
    """Nhiều lần fail liên tiếp trên CÙNG một tài khoản. `now`: xem docstring `register_login_failure`."""
    return check_fail_count(f"fail:{username}", now=now) >= BRUTE_FORCE_THRESHOLD


def is_credential_stuffing(ip: str, *, now: float | None = None) -> bool:
    """Nhiều username KHÁC NHAU bị thử từ CÙNG một IP trong thời gian ngắn. `now`: xem docstring `register_login_failure`."""
    from app.detection.rate_counter import redis_client

    now_value = now if now is not None else time.time()
    redis_client.zremrangebyscore(f"cred_stuffing:{ip}", 0, now_value - FAIL_WINDOW_SECONDS)  # trượt cửa sổ TRƯỚC khi đếm distinct
    distinct_usernames = redis_client.zcard(f"cred_stuffing:{ip}")
    total_fails = check_fail_count(f"fail_ip:{ip}", now=now)
    return (
        total_fails >= CREDENTIAL_STUFFING_FAIL_THRESHOLD
        and distinct_usernames >= CREDENTIAL_STUFFING_MIN_DISTINCT_USERNAMES
    )
