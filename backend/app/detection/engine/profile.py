"""Tiện ích HỒ SƠ HÀNH VI dùng chung (Milestone C — C1) cho các luật nhóm "Hồ sơ hành vi": unusual_device,
unusual_location, unusual_hour, login_velocity_spike. Hàm THUẦN trên `AccountHistory` (đã được `record_success` cập nhật
chỉ từ lần đăng nhập THÀNH CÔNG — xem types.py).

Một định nghĩa trưởng thành duy nhất: hồ sơ chỉ được coi là đủ tin cậy để nói "lạ" khi có ≥ `min_successes` lần thành
công VÀ tuổi (từ lần thành công đầu) ≥ `min_profile_days` ngày; chưa trưởng thành thì luật không cảnh báo."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone

from app.detection.engine.registry import Param
from app.detection.engine.types import AccountHistory

DAY = 86_400.0

# Tham số trưởng thành chung — mọi luật hồ sơ khai báo CÙNG hai tham số này (mặc định giống nhau)
MATURITY_PARAMS = (
    Param("min_successes", 10, "số lần đăng nhập thành công tối thiểu để hồ sơ được coi là trưởng thành", "lần", 1, 10_000),
    Param("min_profile_days", 7, "tuổi hồ sơ tối thiểu (từ lần thành công đầu tiên)", "ngày", 0, 3650),
)


def iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


@dataclass(frozen=True)
class Maturity:
    mature: bool
    successful_login_count: int
    profile_age_days: float


def maturity(history: AccountHistory | None, now_ts: float, *, min_successes: int, min_profile_days: float) -> Maturity:
    if history is None or history.first_success_ts is None:
        return Maturity(False, 0, 0.0)
    age = (now_ts - history.first_success_ts) / DAY
    return Maturity(history.n_success >= min_successes and age >= min_profile_days, history.n_success, age)


def hour_of_day(ts: float) -> float:
    """Giờ trong ngày (0–24, UTC) của một thời điểm epoch."""
    return (ts % DAY) / 3600


def circular_hour_distance(a: float, b: float) -> float:
    """Khoảng cách giữa hai giờ trên đồng hồ 24h (23:30 và 00:30 cách nhau 1 giờ, không phải 23)."""
    d = abs(a - b) % 24
    return min(d, 24 - d)


@dataclass(frozen=True)
class HourProfile:
    center: float  # giờ trung tâm (trung bình vòng tròn)
    concentration: float  # độ dài vector kết quả R ∈ [0,1]: 1 = luôn cùng một giờ, ~0 = rải đều/hai cực
    spread_hours: float  # độ lệch chuẩn vòng tròn sqrt(-2 ln R), quy ra giờ
    sample_count: int


def hour_profile(history: AccountHistory) -> HourProfile | None:
    n = history.n_success
    if n <= 0:
        return None
    s, c = history.hour_sin_sum, history.hour_cos_sum
    r = min(math.hypot(s, c) / n, 1.0)  # sai số dấu phẩy động có thể cho R > 1 một chút khi mọi giờ trùng nhau (log dương -> lỗi miền)
    center = (math.degrees(math.atan2(s, c)) % 360) / 15.0
    spread = math.sqrt(-2 * math.log(r)) * 24 / (2 * math.pi) if r > 1e-12 else float("inf")
    return HourProfile(center=center, concentration=r, spread_hours=spread, sample_count=n)
