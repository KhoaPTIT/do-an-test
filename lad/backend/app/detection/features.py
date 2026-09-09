"""Xây dựng bối cảnh lịch sử và vector đặc trưng cho một sự kiện đăng nhập.

Module này được dùng ở CẢ HAI nơi: lúc huấn luyện offline và lúc chấm điểm
trực tuyến. Dùng chung một đoạn mã là cách tránh train/serve skew, tức là
tình trạng mô hình được huấn luyện trên đặc trưng tính theo một kiểu nhưng
lúc chạy thật lại nhận đặc trưng tính theo kiểu khác.
"""
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional

# Tốc độ di chuyển tối đa hợp lý của con người, tính cả máy bay thương mại.
MAX_PLAUSIBLE_SPEED_KMH = 900


@dataclass
class EventData:
    """Biểu diễn thống nhất của một sự kiện đăng nhập."""
    username: str
    ip_address: str
    timestamp: datetime
    login_successful: bool = True
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    network_type: str = "unknown"
    device_fingerprint: str = ""
    device_type: str = "unknown"
    user_agent: str = ""
    is_attack: bool = False
    attack_type: Optional[str] = None


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Khoảng cách giữa hai điểm trên mặt cầu, đơn vị km."""
    if None in (lat1, lon1, lat2, lon2):
        return 0.0
    lat1, lon1, lat2, lon2 = map(math.radians, (lat1, lon1, lat2, lon2))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = (math.sin(dlat / 2) ** 2
         + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2)
    return 6371.0 * 2 * math.asin(math.sqrt(a))


def compute_context(event: EventData,
                    history: List[EventData],
                    failed_last_15min: int,
                    distinct_users_same_ip_1h: int) -> dict:
    """Hàm thuần: gom lịch sử thành các đại lượng phục vụ rule và ML.

    history: các lần đăng nhập THÀNH CÔNG trước đó của cùng user,
             sắp xếp mới nhất trước. Chỉ chứa sự kiện có thời gian
             nhỏ hơn event.timestamp để tránh rò rỉ dữ liệu tương lai.
    """
    hours = [h.timestamp.hour for h in history]
    last_ok = history[0] if history else None

    ctx = {
        "history_count": len(history),
        "known_ips": {h.ip_address for h in history},
        "known_countries": {h.country for h in history if h.country},
        "known_devices": {h.device_fingerprint for h in history},
        "typical_hours": set(hours),
        "failed_last_15min": failed_last_15min,
        "distinct_users_same_ip_1h": distinct_users_same_ip_1h,
    }

    # Tần suất quốc gia hiện tại trong lịch sử của user
    if history and event.country:
        same = sum(1 for h in history if h.country == event.country)
        ctx["country_freq_for_user"] = same / len(history)
    else:
        ctx["country_freq_for_user"] = 1.0

    # Đặc trưng di chuyển: so với lần đăng nhập thành công gần nhất
    if last_ok:
        gap_h = (event.timestamp - last_ok.timestamp).total_seconds() / 3600.0
        dist = haversine_km(last_ok.latitude, last_ok.longitude,
                            event.latitude, event.longitude)
        ctx["hours_since_last_login"] = max(gap_h, 0.0)
        ctx["travel_distance_km"] = dist
        # Khoảng cách thời gian quá nhỏ thì tốc độ tiến tới vô cùng,
        # chặn trên để giá trị không phá vỡ việc chuẩn hóa đặc trưng.
        ctx["travel_speed_kmh"] = min(dist / gap_h, 99999.0) if gap_h > 0.01 else (
            99999.0 if dist > 1 else 0.0)
    else:
        ctx["hours_since_last_login"] = 0.0
        ctx["travel_distance_km"] = 0.0
        ctx["travel_speed_kmh"] = 0.0

    return ctx


# Thứ tự các cột phải giữ nguyên giữa lúc huấn luyện và lúc chạy thật.
FEATURE_NAMES = [
    "hour_sin",                   # giờ mã hóa vòng tròn, 23h và 0h gần nhau
    "hour_cos",
    "is_weekend",
    "is_new_country",
    "is_new_device",
    "is_new_ip",
    "is_bot_agent",
    "is_risky_network",           # hosting hoặc tor
    "login_failed",
    "travel_speed_log",           # log để nén khoảng giá trị rất rộng
    "travel_distance_log",
    "failed_last_15min",
    "distinct_users_same_ip_1h",
    "hours_since_last_login_log",
    "country_freq_for_user",
    "hour_deviation",             # lệch bao nhiêu giờ so với thói quen
]


def extract_features(event: EventData, ctx: dict) -> List[float]:
    """Chuyển sự kiện và bối cảnh thành vector số theo FEATURE_NAMES."""
    h = event.timestamp.hour

    if ctx["typical_hours"]:
        # Khoảng cách vòng tròn tới giờ quen thuộc gần nhất
        hour_dev = min(min(abs(h - t), 24 - abs(h - t))
                       for t in ctx["typical_hours"])
    else:
        hour_dev = 0.0

    return [
        math.sin(2 * math.pi * h / 24),
        math.cos(2 * math.pi * h / 24),
        1.0 if event.timestamp.weekday() >= 5 else 0.0,
        1.0 if (ctx["known_countries"] and event.country
                and event.country not in ctx["known_countries"]) else 0.0,
        1.0 if (ctx["known_devices"]
                and event.device_fingerprint not in ctx["known_devices"]) else 0.0,
        1.0 if (ctx["known_ips"]
                and event.ip_address not in ctx["known_ips"]) else 0.0,
        1.0 if event.device_type == "bot" else 0.0,
        1.0 if event.network_type in ("hosting", "tor") else 0.0,
        0.0 if event.login_successful else 1.0,
        math.log1p(ctx["travel_speed_kmh"]),
        math.log1p(ctx["travel_distance_km"]),
        float(ctx["failed_last_15min"]),
        float(ctx["distinct_users_same_ip_1h"]),
        math.log1p(ctx["hours_since_last_login"]),
        float(ctx["country_freq_for_user"]),
        float(hour_dev),
    ]


# --- Truy vấn cơ sở dữ liệu, dùng lúc chạy thật ---

def build_context_from_db(db, event: EventData, lookback_days: int = 90) -> dict:
    """Lấy lịch sử từ database rồi gọi compute_context().

    Chỉ lấy những lần đăng nhập ĐÁNG TIN, tức là thành công và không bị
    rule engine gắn cờ. Nếu đưa cả những lần đã bị chặn vào hồ sơ hành vi,
    kẻ tấn công chỉ cần đăng nhập một lần từ nước ngoài là quốc gia đó
    trở thành quen thuộc, và những lần sau sẽ trót lọt. Đây là kiểu tấn công
    đầu độc hồ sơ hành vi, và cách chặn là không bao giờ học từ dữ liệu
    chưa được xác thực.
    """
    from app.config import THRESHOLD_CHALLENGE
    from app.models import LoginEvent  # import trễ để tránh vòng lặp import

    since = event.timestamp - timedelta(days=lookback_days)

    rows = (db.query(LoginEvent)
              .filter(LoginEvent.username == event.username,
                      LoginEvent.login_successful.is_(True),
                      LoginEvent.rule_score < THRESHOLD_CHALLENGE,
                      LoginEvent.timestamp >= since,
                      LoginEvent.timestamp < event.timestamp)
              .order_by(LoginEvent.timestamp.desc())
              .limit(500)
              .all())

    history = [EventData(
        username=r.username, ip_address=r.ip_address, timestamp=r.timestamp,
        login_successful=True, country=r.country, city=r.city,
        latitude=r.latitude, longitude=r.longitude,
        network_type=r.network_type or "unknown",
        device_fingerprint=r.device_fingerprint or "",
        device_type=r.device_type or "unknown",
    ) for r in rows]

    failed_15 = (db.query(LoginEvent)
                   .filter(LoginEvent.username == event.username,
                           LoginEvent.login_successful.is_(False),
                           LoginEvent.timestamp >= event.timestamp - timedelta(minutes=15),
                           LoginEvent.timestamp < event.timestamp)
                   .count())

    distinct_users = (db.query(LoginEvent.username)
                        .filter(LoginEvent.ip_address == event.ip_address,
                                LoginEvent.timestamp >= event.timestamp - timedelta(hours=1),
                                LoginEvent.timestamp < event.timestamp)
                        .distinct().count())

    return compute_context(event, history, failed_15, distinct_users)
