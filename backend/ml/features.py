"""Đặc tả DUY NHẤT của đặc trưng mô hình bất thường (Phase 4.1 — `ml/` v3), dùng chung cho:

  - trích xuất OFFLINE từ dataset tổng hợp (`ml/build_features.py`);
  - trích xuất RUNTIME từ bảng `login_events` cho luồng /login (`app/detection/ml_runtime.py`).

Hai nơi gọi CÙNG một hàm thuần `compute_features(prior, current)` trên CÙNG một kiểu dữ liệu (`LoginRecord`) — test
`tests/test_ml_feature_parity.py` chứng minh hai đường cho ra cùng vector trên cùng lịch sử + sự kiện.

Quy ước (sửa các lỗi lệch train/serve tìm được ở audit Phase 4.0):
  - `prior` = các lần đăng nhập THÀNH CÔNG của CHÍNH tài khoản, xảy ra TRƯỚC HẲN sự kiện hiện tại (không bao giờ gồm chính
    nó — lỗi cũ: sự kiện vừa flush bị coi là "lần trước" nên `minutes_since_last_login` luôn = 0 lúc chạy thật);
  - chỉ chấm lần đăng nhập THÀNH CÔNG của tài khoản có hồ sơ TRƯỞNG THÀNH (≥ 10 lần thành công, ≥ 7 ngày — cùng định
    nghĩa với các luật hồ sơ hành vi, `app/detection/engine/profile.py`); lần thất bại để 20 detector luật xử lý;
  - thiết bị = HỌ thiết bị chuẩn hoá (`device_family_of`: loại | HĐH | trình duyệt, bỏ phiên bản) — Chrome 120 và
    Chrome 121 trên cùng máy là CÙNG thiết bị, giống luật `unusual_device`;
  - giờ tính theo UTC, độ lệch giờ là khoảng cách VÒNG TRÒN tới giờ trung bình vòng tròn của lịch sử.

Không đặc trưng nào dùng nhãn, loại tấn công hay kết quả của luật."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Sequence

from app.detection.engine.types import device_family_of
from app.detection.rules import haversine_distance
from app.utils.device import parse_user_agent
from app.utils.time import ensure_utc

FEATURE_VERSION = "v3"
FEATURE_NAMES: list[str] = [
    "hour_deviation",  # khoảng cách vòng tròn (giờ, 0–12) tới giờ trung bình vòng tròn của các lần thành công trước
    "is_new_location",  # (quốc gia, thành phố) chưa từng đăng nhập thành công
    "is_new_device",  # họ thiết bị chuẩn hoá chưa từng đăng nhập thành công
    "log_minutes_since_last_success",  # log(1 + phút) kể từ lần thành công gần nhất
    "logins_last_24h",  # số lần thành công trong 24 giờ trước đó
    "log_distance_km_from_home",  # log(1 + km) tới vị trí của lần thành công ĐẦU TIÊN có toạ độ
    "log_travel_speed_kmh",  # log(1 + km/h) từ vị trí lần thành công GẦN NHẤT có toạ độ
]

# Phạm vi chấm — giống mặc định MATURITY_PARAMS của các luật hồ sơ hành vi (app/detection/engine/profile.py)
MIN_PRIOR_SUCCESSES = 10
MIN_PROFILE_DAYS = 7
_MIN_ELAPSED_HOURS = 1 / 60  # hai lần cách nhau < 1 phút: coi như 1 phút khi tính tốc độ (tránh chia cho 0)


def feature_signature() -> str:
    """Dấu vân tay phiên bản + danh sách + thứ tự đặc trưng; model lưu chữ ký lúc train, runtime từ chối model lệch chữ ký."""
    return hashlib.sha1(f"{FEATURE_VERSION}:{','.join(FEATURE_NAMES)}".encode("utf-8")).hexdigest()[:12]


def device_family_for_user_agent(user_agent: str | None) -> str:
    """Họ thiết bị chuẩn hoá của một User-Agent — CÙNG hàm với luật `unusual_device` và lịch sử dựng từ DB."""
    parsed = parse_user_agent(user_agent)
    return device_family_of(user_agent, parsed.device_type, parsed.os, parsed.browser)


@dataclass(frozen=True)
class LoginRecord:
    """Những gì mô hình biết về MỘT lần đăng nhập (không có nhãn)."""

    ts: datetime  # có múi giờ (UTC)
    country: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    device_family: str


def make_record(ts: datetime, *, country: str | None, city: str | None, latitude: float | None, longitude: float | None, user_agent: str | None) -> LoginRecord:
    """Dựng `LoginRecord` từ giá trị THÔ của một lần đăng nhập — đường DUY NHẤT cho cả offline (`ml/build_features.py`) lẫn
    runtime (`app/detection/ml_runtime.py`), để thiết bị/thời gian được chuẩn hoá giống hệt nhau."""
    return LoginRecord(
        ts=ensure_utc(ts), country=country, city=city, latitude=latitude, longitude=longitude,
        device_family=device_family_for_user_agent(user_agent),
    )


def _hour(ts: datetime) -> float:
    ts = ensure_utc(ts)
    return ts.hour + ts.minute / 60 + ts.second / 3600


def _circular_distance(a: float, b: float) -> float:
    d = abs(a - b) % 24
    return min(d, 24 - d)


def in_scope(prior: Sequence[LoginRecord], current: LoginRecord) -> bool:
    """Mô hình chỉ chấm khi hồ sơ đã trưởng thành: đủ lần thành công VÀ đủ tuổi (tính từ lần thành công đầu tiên)."""
    if len(prior) < MIN_PRIOR_SUCCESSES:
        return False
    return ensure_utc(current.ts) - ensure_utc(prior[0].ts) >= timedelta(days=MIN_PROFILE_DAYS)


def compute_features(prior: Sequence[LoginRecord], current: LoginRecord) -> dict[str, float]:
    """Vector đặc trưng của `current` từ `prior` (lần thành công TRƯỚC HẲN `current`, sắp tăng dần theo thời gian). Hàm thuần."""
    now = ensure_utc(current.ts)
    prior = [p for p in prior if ensure_utc(p.ts) < now]

    hour = _hour(now)
    if prior:
        s = sum(math.sin(2 * math.pi * _hour(p.ts) / 24) for p in prior)
        c = sum(math.cos(2 * math.pi * _hour(p.ts) / 24) for p in prior)
        mean_hour = (math.degrees(math.atan2(s, c)) % 360) / 15.0 if math.hypot(s, c) > 1e-9 else hour
        hour_deviation = _circular_distance(hour, mean_hour)
    else:
        hour_deviation = 0.0

    known_locations = {(p.country, p.city) for p in prior if p.country}
    is_new_location = 1.0 if current.country and (current.country, current.city) not in known_locations else 0.0
    known_devices = {p.device_family for p in prior}
    is_new_device = 1.0 if current.device_family and current.device_family not in known_devices else 0.0

    minutes_since_last = max((now - ensure_utc(prior[-1].ts)).total_seconds() / 60, 0.0) if prior else 0.0
    logins_last_24h = float(sum(1 for p in prior if ensure_utc(p.ts) > now - timedelta(hours=24)))

    with_coords = [p for p in prior if p.latitude is not None and p.longitude is not None]
    has_coords = current.latitude is not None and current.longitude is not None
    distance_home = speed = 0.0
    if has_coords and with_coords:
        home, last = with_coords[0], with_coords[-1]
        distance_home = haversine_distance(home.latitude, home.longitude, current.latitude, current.longitude)
        hours = max((now - ensure_utc(last.ts)).total_seconds() / 3600, _MIN_ELAPSED_HOURS)
        speed = haversine_distance(last.latitude, last.longitude, current.latitude, current.longitude) / hours

    return {
        "hour_deviation": hour_deviation,
        "is_new_location": is_new_location,
        "is_new_device": is_new_device,
        "log_minutes_since_last_success": math.log1p(minutes_since_last),
        "logins_last_24h": logins_last_24h,
        "log_distance_km_from_home": math.log1p(distance_home),
        "log_travel_speed_kmh": math.log1p(speed),
    }


def feature_vector(features: dict[str, float]) -> list[float]:
    return [float(features[name]) for name in FEATURE_NAMES]


@dataclass(frozen=True)
class RawLogin:
    """Một dòng sự kiện thô của dataset (`ml/data/.../events.csv`) — KHÔNG có nhãn."""

    event_id: int
    username: str
    ts: datetime
    success: bool
    country: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    user_agent: str | None
    ip: str | None = None  # chỉ để truy vết/demo — không phải đặc trưng


def extract_offline(events: Sequence[RawLogin]) -> list[tuple[int, dict[str, float]]]:
    """Trích đặc trưng OFFLINE theo lô: xử lý tuần tự theo thời gian riêng từng tài khoản, mỗi lần thành công thuộc phạm vi
    được chấm từ các lần thành công TRƯỚC HẲN nó — đúng điều runtime thấy khi sự kiện xảy ra. Trả [(event_id, đặc trưng)]."""
    by_user: dict[str, list[RawLogin]] = {}
    for e in events:
        by_user.setdefault(e.username, []).append(e)
    out: list[tuple[int, dict[str, float]]] = []
    for user_events in by_user.values():
        prior: list[LoginRecord] = []
        for e in sorted(user_events, key=lambda x: (ensure_utc(x.ts), x.event_id)):
            if not e.success:
                continue
            current = make_record(e.ts, country=e.country, city=e.city, latitude=e.latitude, longitude=e.longitude, user_agent=e.user_agent)
            earlier = [p for p in prior if p.ts < current.ts]
            if in_scope(earlier, current):
                out.append((e.event_id, compute_features(earlier, current)))
            prior.append(current)
    return sorted(out)
