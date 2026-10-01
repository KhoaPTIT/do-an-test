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


# ------------------------------------------------------------------------------------------------ hồ sơ giờ thực nghiệm (Milestone C.1)

@dataclass(frozen=True)
class HourAssessment:
    """Giờ hiện tại so với PHÂN BỐ THỰC NGHIỆM giờ đăng nhập thành công của chính tài khoản (histogram 24 ô, làm mượt vòng tròn).

    status: USUAL (thuộc một khung giờ đã thiết lập) | UNUSUAL (ngoài mọi khung giờ đã thiết lập) | NOT_APPLICABLE (hồ sơ quá phân
    tán — không có khung giờ rõ ràng thì không thể có "giờ bất thường" đáng tin cậy)."""

    status: str
    current_hour: float
    hour_probability: float  # khối xác suất ĐÃ LÀM MƯỢT ở ô giờ hiện tại (tổng 24 ô = 1)
    usual_hour_ranges: tuple[str, ...]  # các khung giờ đã thiết lập (ô có xác suất làm mượt > 0), dạng "HH:00-HH:00"
    coverage: float  # tỉ lệ 24 giờ thuộc khung giờ đã thiết lập
    nearest_usual_hours_away: float  # khoảng cách (giờ, vòng tròn) tới lần thành công gần nhất trong histogram (theo tâm ô)
    sample_count: int
    histogram: tuple[int, ...]


def smoothed_hour_probabilities(counts: tuple[int, ...], smoothing_hours: int) -> tuple[float, ...]:
    """Làm mượt VÒNG TRÒN bằng nhân tam giác bán kính `smoothing_hours` ô (bán kính 2: trọng số 1,2,3,2,1 cho h−2..h+2 —
    23h và 0h là hai ô kề nhau), chuẩn hoá thành xác suất. Ô h nhận khối từ các lần thành công ở các ô cách ≤ bán kính."""
    n = sum(counts)
    if n == 0:
        return (0.0,) * 24
    weights = [(k, smoothing_hours + 1 - abs(k)) for k in range(-smoothing_hours, smoothing_hours + 1)]
    total_w = sum(w for _, w in weights)
    return tuple(sum(w * counts[(h - k) % 24] for k, w in weights) / (total_w * n) for h in range(24))


def hour_ranges(probabilities: tuple[float, ...]) -> tuple[str, ...]:
    """Các dải ô liên tiếp (vòng tròn) có xác suất > 0, dạng "HH:00-HH:00" (giờ kết thúc không tính)."""
    inside = [p > 0 for p in probabilities]
    if all(inside):
        return ("00:00-24:00",)
    if not any(inside):
        return ()
    start = next(h for h in range(24) if not inside[h])  # bắt đầu quét từ một ô trống để dải qua nửa đêm không bị cắt đôi
    ranges, run_start = [], None
    for step in range(1, 25):
        h = (start + step) % 24
        if inside[h] and run_start is None:
            run_start = h
        if run_start is not None and (not inside[h] or step == 24):
            end = h if not inside[h] else (h + 1) % 24
            ranges.append(f"{run_start:02d}:00-{end:02d}:00")
            run_start = None
    return tuple(ranges)


def assess_hour(history: AccountHistory, ts: float, *, smoothing_hours: int, max_coverage: float) -> HourAssessment | None:
    counts = history.hour_counts
    if not counts or sum(counts) == 0:
        return None
    probabilities = smoothed_hour_probabilities(counts, smoothing_hours)
    current = hour_of_day(ts)
    p = probabilities[int(current) % 24]
    coverage = sum(1 for q in probabilities if q > 0) / 24
    nearest = min(circular_hour_distance(current, h + 0.5) for h in range(24) if counts[h])
    if coverage > max_coverage:
        status = "NOT_APPLICABLE"
    else:
        status = "USUAL" if p > 0 else "UNUSUAL"
    return HourAssessment(status, current, p, hour_ranges(probabilities), coverage, nearest, sum(counts), tuple(counts))
