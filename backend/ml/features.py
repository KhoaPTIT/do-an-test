"""Trích xuất đặc trưng hành vi cho ML tầng 3 (nhiệm vụ 7.1).

8 đặc trưng, PHẦN LỚN TÁI SỬ DỤNG chính tín hiệu đã có ở tầng 2
(app/detection/baseline.py, app/detection/rules.py) — khác biệt cốt lõi:
tầng 2 gán TRỌNG SỐ THỦ CÔNG cho từng tín hiệu (mục 4.2), tầng 3 để mô hình
TỰ HỌC cách kết hợp (kể cả tương tác phi tuyến giữa các tín hiệu) từ dữ
liệu, không cần con người chọn ngưỡng tay — đây là phần so sánh chính ở
docs/ml-evaluation.md.

QUAN TRỌNG — tránh rò rỉ dữ liệu tương lai (data leakage): mọi đặc trưng
CHỈ được tính từ lịch sử TRƯỚC thời điểm đăng nhập hiện tại. `UserHistoryState`
mô phỏng đúng những gì hệ thống "biết" tại thời điểm đó — dùng được cả khi
trích xuất offline từ dữ liệu lịch sử (ml/extract_features.py) lẫn khi tính
real-time (app/detection/ml_model.py), đảm bảo train và suy luận nhất quán.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.detection.rules import haversine_distance
from app.utils.time import ensure_utc

FEATURE_NAMES = [
    "hour_sin",
    "hour_cos",
    "day_of_week",
    "hour_deviation_from_avg",
    "is_new_location",
    "is_new_device",
    "minutes_since_last_login",
    "logins_last_24h",
    "distance_km_from_home",
]

# Giá trị mặc định khi user chưa có lịch sử (lần đăng nhập đầu tiên) — coi
# như "đã lâu không đăng nhập", không có gì để so deviation/distance.
_NO_HISTORY_MINUTES_SINCE_LAST = 24 * 60.0


@dataclass
class UserHistoryState:
    """Trạng thái tích luỹ của 1 user, cập nhật TUẦN TỰ theo thời gian tăng dần."""

    known_locations: set = field(default_factory=set)  # {(country, city)}
    known_devices: set = field(default_factory=set)  # {device_fingerprint}
    login_hours: list = field(default_factory=list)  # giờ (float) các lần login trước đó
    recent_timestamps: list = field(default_factory=list)  # datetime các lần login trước đó
    home_location: tuple | None = None  # (lat, lon) — vị trí lần đăng nhập ĐẦU TIÊN có geo


def compute_features(
    state: UserHistoryState,
    *,
    country: str | None,
    city: str | None,
    latitude: float | None,
    longitude: float | None,
    device_fingerprint: str | None,
    created_at: datetime,
) -> dict:
    """Tính vector đặc trưng cho MỘT lần đăng nhập, dựa trên `state` (lịch sử
    TRƯỚC thời điểm này — gọi update_state() SAU khi tính xong, không phải trước).
    """
    hour = created_at.hour + created_at.minute / 60
    hour_sin = math.sin(2 * math.pi * hour / 24)
    hour_cos = math.cos(2 * math.pi * hour / 24)
    day_of_week = float(created_at.weekday())

    if state.login_hours:
        avg_hour = sum(state.login_hours) / len(state.login_hours)
        diff = abs(hour - avg_hour)
        hour_deviation = min(diff, 24 - diff)
    else:
        hour_deviation = 0.0

    location_key = (country, city)
    is_new_location = 0.0 if (country is None or location_key in state.known_locations) else 1.0
    is_new_device = 0.0 if (device_fingerprint is None or device_fingerprint in state.known_devices) else 1.0

    if state.recent_timestamps:
        minutes_since_last = max((created_at - state.recent_timestamps[-1]).total_seconds() / 60, 0.0)
    else:
        minutes_since_last = _NO_HISTORY_MINUTES_SINCE_LAST

    window_start = created_at - timedelta(hours=24)
    logins_last_24h = float(sum(1 for ts in state.recent_timestamps if ts >= window_start))

    if state.home_location is not None and latitude is not None and longitude is not None:
        distance_km = haversine_distance(state.home_location[0], state.home_location[1], latitude, longitude)
    else:
        distance_km = 0.0

    return {
        "hour_sin": hour_sin,
        "hour_cos": hour_cos,
        "day_of_week": day_of_week,
        "hour_deviation_from_avg": hour_deviation,
        "is_new_location": is_new_location,
        "is_new_device": is_new_device,
        "minutes_since_last_login": minutes_since_last,
        "logins_last_24h": logins_last_24h,
        "distance_km_from_home": distance_km,
    }


def update_state(
    state: UserHistoryState,
    *,
    country: str | None,
    city: str | None,
    latitude: float | None,
    longitude: float | None,
    device_fingerprint: str | None,
    created_at: datetime,
) -> None:
    """Gọi SAU compute_features() cho cùng 1 sự kiện, để lần tính TIẾP THEO
    phản ánh đúng lịch sử (bao gồm cả sự kiện vừa xử lý)."""
    if country is not None:
        state.known_locations.add((country, city))
    if device_fingerprint is not None:
        state.known_devices.add(device_fingerprint)

    hour = created_at.hour + created_at.minute / 60
    state.login_hours.append(hour)
    state.recent_timestamps.append(created_at)

    if state.home_location is None and latitude is not None and longitude is not None:
        state.home_location = (latitude, longitude)


def compute_realtime_features(
    db,
    *,
    user_id: int,
    baseline,
    country: str | None,
    city: str | None,
    latitude: float | None,
    longitude: float | None,
    device_fingerprint: str | None,
    created_at: datetime,
) -> dict:
    """Bản REAL-TIME của compute_features() — dùng cho suy luận ML khi có
    request thật (app/detection/pipeline.py), tính TRỰC TIẾP từ database
    thay vì UserHistoryState (chỉ dùng khi trích xuất offline theo lô).

    PHẢI cho ra Ý NGHĨA giống hệt compute_features()/update_state() để mô
    hình suy luận đúng trên cùng phân phối đã học — gọi TRƯỚC khi
    update_baseline_after_successful_login()/record_known_device_if_new()/
    record_known_location_if_new() cập nhật dữ liệu của chính lần đăng nhập
    này (nếu không, is_new_location/is_new_device sẽ luôn sai vì tự thấy
    "đã biết" ngay chính lần đầu ghi nhận).
    """
    # Import trễ để tránh vòng lặp import (app.detection.baseline không
    # import ngược lại ml.*, nhưng để rõ ràng vẫn import cục bộ ở đây).
    from app.detection.baseline import is_known_device, is_known_location
    from app.models import LoginEvent

    hour = created_at.hour + created_at.minute / 60
    hour_sin = math.sin(2 * math.pi * hour / 24)
    hour_cos = math.cos(2 * math.pi * hour / 24)
    day_of_week = float(created_at.weekday())

    if baseline is not None and getattr(baseline, "avg_login_hour", None) is not None:
        diff = abs(hour - baseline.avg_login_hour)
        hour_deviation = min(diff, 24 - diff)
    else:
        hour_deviation = 0.0

    is_new_location = 0.0 if is_known_location(db, user_id, country, city) else 1.0
    is_new_device = 0.0 if is_known_device(db, user_id, device_fingerprint) else 1.0

    previous_event = (
        db.query(LoginEvent)
        .filter(LoginEvent.user_id == user_id, LoginEvent.success.is_(True))
        .order_by(LoginEvent.created_at.desc())
        .first()
    )
    if previous_event is not None:
        # MR18: previous_event.created_at đọc lại từ SQLite (test/mô phỏng) mất tzinfo trong khi created_at (tham số,
        # vừa dựng ở lời gọi) vẫn aware — CÙNG lớp bug naive-vs-aware datetime đã gặp (và sửa bằng ensure_utc()) ở
        # is_impossible_travel (app/detection/rules.py, MR13) và nhiều nơi khác — lần này ở compute_realtime_features
        # (tầng 3), tự phát hiện khi dựng ml/attack_scenarios.py (MR18: kịch bản có lịch sử/baseline TRƯỚC đó).
        minutes_since_last = max((ensure_utc(created_at) - ensure_utc(previous_event.created_at)).total_seconds() / 60, 0.0)
    else:
        minutes_since_last = _NO_HISTORY_MINUTES_SINCE_LAST

    window_start = created_at - timedelta(hours=24)
    logins_last_24h = float(
        db.query(LoginEvent)
        .filter(
            LoginEvent.user_id == user_id,
            LoginEvent.success.is_(True),
            LoginEvent.created_at >= window_start,
            LoginEvent.created_at < created_at,
        )
        .count()
    )

    first_event_with_geo = (
        db.query(LoginEvent)
        .filter(LoginEvent.user_id == user_id, LoginEvent.success.is_(True), LoginEvent.latitude.isnot(None))
        .order_by(LoginEvent.created_at.asc())
        .first()
    )
    if first_event_with_geo is not None and latitude is not None and longitude is not None:
        distance_km = haversine_distance(first_event_with_geo.latitude, first_event_with_geo.longitude, latitude, longitude)
    else:
        distance_km = 0.0

    return {
        "hour_sin": hour_sin,
        "hour_cos": hour_cos,
        "day_of_week": day_of_week,
        "hour_deviation_from_avg": hour_deviation,
        "is_new_location": is_new_location,
        "is_new_device": is_new_device,
        "minutes_since_last_login": minutes_since_last,
        "logins_last_24h": logins_last_24h,
        "distance_km_from_home": distance_km,
    }
