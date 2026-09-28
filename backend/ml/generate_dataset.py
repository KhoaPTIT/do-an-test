"""Sinh tập dữ liệu HUẤN LUYỆN cho ML tầng 3 (nhiệm vụ 7.1) — RIÊNG khỏi
tập dữ liệu demo dashboard (user001-030, scripts/generate_labeled_anomalies.py)
để không xáo trộn số liệu đã ghi trong docs các tuần trước. Dùng user101-140.

So với bản Tuần 3, thêm:
  - Đa dạng THIẾT BỊ: mỗi user có 1-2 thiết bị quen thuộc (User-Agent thật,
    không phải chuỗi cố định) — cần thiết để đặc trưng is_new_device có ý
    nghĩa (backend/ml/features.py).
  - 5 KIỂU bất thường thay vì 2: unusual_hour, unusual_location,
    unusual_device (mới), rapid_fire (mới — nhiều lần đăng nhập dồn dập bất
    thường so với thói quen), combined (mới — kết hợp 2 tín hiệu cùng lúc,
    ca khó nhất, gần với tấn công thật hơn: kẻ tấn công vừa đổi vị trí vừa
    đổi thiết bị).
  - Nhiều user + nhiều bản ghi hơn (90 ngày, 30-140 user) để có đủ dữ liệu
    cho train/test split theo thời gian mà không quá ít mẫu.

Nhãn ground-truth lưu ở backend/ml/data/labels.csv (tách biệt khỏi
login_events — không cheat khi đánh giá).

Chạy:
    cd backend
    venv\\Scripts\\python.exe -m ml.generate_dataset --reset
"""

from __future__ import annotations

import argparse
import csv
import os
import random
from datetime import datetime, timedelta, timezone

from app.database import Base, SessionLocal, engine
from app.models import LoginEvent, User
from app.security import hash_password
from app.utils.device import compute_device_fingerprint
from scripts.generate_historical_data import LOCATIONS, LOCATION_WEIGHTS, random_ip

USER_ID_START = 101
TOTAL_USERS = 40  # user101-user140
EXTENDED_DAYS_BACK = 90
NORMAL_LOGINS_PER_USER_RANGE = (30, 55)
SINGLE_ANOMALIES_PER_USER_RANGE = (1, 2)  # mỗi kiểu unusual_hour/location/device/combined
RAPID_FIRE_BURSTS_PER_USER_RANGE = (0, 1)
RAPID_FIRE_BURST_SIZE_RANGE = (3, 4)  # số lần đăng nhập dồn dập trong 1 đợt
DEFAULT_PASSWORD = "Demo@12345"

FAR_LOCATIONS = [
    ("RU", "Moscow", 55.75, 37.62),
    ("US", "New York", 40.71, -74.01),
    ("BR", "Sao Paulo", -23.55, -46.63),
    ("NG", "Lagos", 6.52, 3.38),
]

# User-Agent thật của vài trình duyệt/thiết bị phổ biến — dùng làm "thiết bị"
# để is_new_device có ý nghĩa thay vì luôn là 1 chuỗi cố định.
DEVICE_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/120.0.0.0 Safari/537.36",
]

LABELS_PATH = os.path.join(os.path.dirname(__file__), "data", "labels.csv")


def make_user_profile(index: int) -> dict:
    devices = random.sample(DEVICE_POOL, k=random.choice([1, 1, 2]))  # đa số 1 thiết bị, 1 phần có 2
    return {
        "username": f"user{index:03d}",
        "home_hour": random.uniform(6, 22),
        "home_ip": random_ip(),
        "home_location": random.choices(LOCATIONS, weights=LOCATION_WEIGHTS, k=1)[0],
        "devices": devices,
    }


def _jitter_hour(home_hour: float) -> float:
    return min(max(home_hour + random.gauss(0, 1.2), 0), 23.98)


def _apply_time(ts: datetime, hour: float) -> datetime:
    return ts.replace(hour=int(hour), minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)


def make_normal_events(user: User, profile: dict, count: int) -> list[LoginEvent]:
    events = []
    now = datetime.now(timezone.utc)
    country, city, lat, lon = profile["home_location"]

    for _ in range(count):
        ts = _apply_time(now - timedelta(days=random.uniform(0, EXTENDED_DAYS_BACK)), _jitter_hour(profile["home_hour"]))
        device_ua = random.choice(profile["devices"])
        events.append(
            LoginEvent(
                user_id=user.id,
                attempted_username=user.username,
                success=True,
                ip_address=profile["home_ip"],
                user_agent=device_ua,
                device_fingerprint=compute_device_fingerprint(device_ua),
                country=country,
                city=city,
                latitude=lat,
                longitude=lon,
                is_synthetic=True,
                created_at=ts,
            )
        )
    return events


def _make_single_anomaly(user: User, profile: dict, anomaly_type: str, now: datetime) -> tuple[LoginEvent, str]:
    """anomaly_type: 'unusual_hour' | 'unusual_location' | 'unusual_device' | 'combined'."""
    country, city, lat, lon = profile["home_location"]
    ev_country, ev_city, ev_lat, ev_lon = country, city, lat, lon
    ev_ip = profile["home_ip"]
    device_ua = random.choice(profile["devices"])
    hour = _jitter_hour(profile["home_hour"])

    signals = {anomaly_type} if anomaly_type != "combined" else set(random.sample(["unusual_hour", "unusual_location", "unusual_device"], k=2))

    if "unusual_hour" in signals:
        hour = (profile["home_hour"] + 12 + random.uniform(-1, 1)) % 24
    if "unusual_location" in signals:
        far = random.choice([loc for loc in FAR_LOCATIONS if loc[0] != country])
        ev_country, ev_city, ev_lat, ev_lon = far
        ev_ip = random_ip()
    if "unusual_device" in signals:
        # Thiết bị KHÔNG nằm trong danh sách quen thuộc của user.
        unknown_pool = [d for d in DEVICE_POOL if d not in profile["devices"]]
        device_ua = random.choice(unknown_pool)

    ts = _apply_time(now - timedelta(days=random.uniform(0, EXTENDED_DAYS_BACK)), hour)
    label = "+".join(sorted(signals))

    event = LoginEvent(
        user_id=user.id,
        attempted_username=user.username,
        success=True,
        ip_address=ev_ip,
        user_agent=device_ua,
        device_fingerprint=compute_device_fingerprint(device_ua),
        country=ev_country,
        city=ev_city,
        latitude=ev_lat,
        longitude=ev_lon,
        is_synthetic=True,
        created_at=ts,
    )
    return event, label


DORMANT_GAP_DAYS = 35  # KHÔNG dùng 90 (ngưỡng của dormant_account_login, MR9) — tier-3 không có ngưỡng cứng, chỉ cần
# lệch RÕ RỆT so với khoảng cách 2-3 ngày/lần thường thấy (30-55 lần/90 ngày) để mô hình học được, không cần khớp con
# số của một luật khác tầng hoàn toàn.
DORMANT_REACTIVATION_PROBABILITY = 0.4  # MR18: không phải user nào cũng có kiểu bất thường này (mẫu tương tự SINGLE_ANOMALIES_PER_USER_RANGE)
IMPOSSIBLE_TRAVEL_GEO_PROBABILITY = 0.4


def _make_dormant_reactivation_anomaly(user: User, profile: dict, now: datetime) -> tuple[LoginEvent, str]:
    """MR18 "mô hình B" — kiểu bất thường MỚI (không có ở Tuần 7): đăng nhập THÀNH CÔNG NGAY BÂY GIỜ (mới nhất trong
    toàn bộ lịch sử user) sau khi bị lọc bỏ mọi sự kiện trong `DORMANT_GAP_DAYS` ngày gần nhất (xem main()) — tín hiệu
    CHÍNH là `minutes_since_last_login`/`logins_last_24h` cực đoan (KHÔNG PHẢI is_new_location/is_new_device như 3
    kiểu gốc), kèm vị trí MỚI (khác `unusual_location`: ở đó không có yêu cầu gì về thời gian kể từ lần trước)."""
    country, _city, _lat, _lon = profile["home_location"]
    far = random.choice([loc for loc in FAR_LOCATIONS if loc[0] != country])
    ev_country, ev_city, ev_lat, ev_lon = far
    device_ua = random.choice(profile["devices"])
    event = LoginEvent(
        user_id=user.id, attempted_username=user.username, success=True, ip_address=random_ip(), user_agent=device_ua,
        device_fingerprint=compute_device_fingerprint(device_ua), country=ev_country, city=ev_city, latitude=ev_lat,
        longitude=ev_lon, is_synthetic=True, created_at=now,
    )
    return event, "dormant_reactivation"


def _make_impossible_travel_geo_anomaly(user: User, profile: dict, now: datetime) -> list[tuple[LoginEvent, str | None]]:
    """MR18 "mô hình B" — kiểu bất thường MỚI: 1 lần đăng nhập THÀNH CÔNG bình thường (nhãn False — chỉ để có một mốc
    "vừa mới đăng nhập" ngay trước đó) rồi NGAY SAU ĐÓ vài phút một lần THÀNH CÔNG khác từ vị trí RẤT XA — tín hiệu
    CHÍNH là TỔ HỢP `minutes_since_last_login` cực nhỏ VÀ `distance_km_from_home` cực lớn CÙNG LÚC (khác
    `unusual_location` một mình: ở đó không có ràng buộc về thời gian kể từ lần trước, có thể xảy ra sau nhiều ngày)."""
    country, city, lat, lon = profile["home_location"]
    far = random.choice([loc for loc in FAR_LOCATIONS if loc[0] != country])
    ts_reference = _apply_time(now - timedelta(days=random.uniform(1, 5)), _jitter_hour(profile["home_hour"]))
    ts_travel = ts_reference + timedelta(minutes=random.uniform(5, 15))
    device_ua = random.choice(profile["devices"])

    reference = LoginEvent(
        user_id=user.id, attempted_username=user.username, success=True, ip_address=profile["home_ip"], user_agent=device_ua,
        device_fingerprint=compute_device_fingerprint(device_ua), country=country, city=city, latitude=lat, longitude=lon,
        is_synthetic=True, created_at=ts_reference,
    )
    travel = LoginEvent(
        user_id=user.id, attempted_username=user.username, success=True, ip_address=random_ip(), user_agent=device_ua,
        device_fingerprint=compute_device_fingerprint(device_ua), country=far[0], city=far[1], latitude=far[2], longitude=far[3],
        is_synthetic=True, created_at=ts_travel,
    )
    return [(reference, None), (travel, "impossible_travel_geo")]


def _make_rapid_fire_burst(user: User, profile: dict, burst_size: int, now: datetime) -> list[tuple[LoginEvent, str | None]]:
    """1 lần đăng nhập bình thường rồi (burst_size - 1) lần dồn dập ngay sau
    (vài chục giây - vài phút/lần) — bất thường về TỐC ĐỘ, không phải giờ/vị
    trí/thiết bị. Chỉ các lần SAU lần đầu mới gắn nhãn bất thường (lần đầu
    tự nó không có gì lạ, chỉ lạ khi có quá nhiều lần theo ngay sau).
    """
    country, city, lat, lon = profile["home_location"]
    device_ua = random.choice(profile["devices"])
    base_ts = _apply_time(now - timedelta(days=random.uniform(0, EXTENDED_DAYS_BACK)), _jitter_hour(profile["home_hour"]))

    results: list[tuple[LoginEvent, str | None]] = []
    ts = base_ts
    for i in range(burst_size):
        event = LoginEvent(
            user_id=user.id,
            attempted_username=user.username,
            success=True,
            ip_address=profile["home_ip"],
            user_agent=device_ua,
            device_fingerprint=compute_device_fingerprint(device_ua),
            country=country,
            city=city,
            latitude=lat,
            longitude=lon,
            is_synthetic=True,
            created_at=ts,
        )
        results.append((event, None if i == 0 else "rapid_fire"))
        ts = ts + timedelta(seconds=random.uniform(20, 90))
    return results


def reset_synthetic_data(db) -> None:
    usernames = [f"user{i:03d}" for i in range(USER_ID_START, USER_ID_START + TOTAL_USERS)]
    user_ids = [u.id for u in db.query(User.id).filter(User.username.in_(usernames)).all()]
    if user_ids:
        db.query(LoginEvent).filter(LoginEvent.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(user_ids)).delete(synchronize_session=False)
        db.commit()
        print(f"Đã xoá {len(user_ids)} user (ML dataset) + toàn bộ login_events liên quan.")


def main(reset: bool) -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    labels: list[tuple[int, str, bool, str]] = []
    now = datetime.now(timezone.utc)

    try:
        if reset:
            reset_synthetic_data(db)

        total_normal = 0
        total_anomaly = 0

        for i in range(USER_ID_START, USER_ID_START + TOTAL_USERS):
            profile = make_user_profile(i)
            username = profile["username"]

            user = db.query(User).filter(User.username == username).first()
            if user is None:
                user = User(username=username, password_hash=hash_password(DEFAULT_PASSWORD))
                db.add(user)
                db.flush()

            normal_events = make_normal_events(user, profile, random.randint(*NORMAL_LOGINS_PER_USER_RANGE))

            # MR18 "mô hình B": lọc bỏ mọi sự kiện GẦN ĐÂY trước khi thêm tái kích hoạt "ngủ đông" — nếu không, sự
            # kiện bình thường ngẫu nhiên rơi vào đúng vài chục ngày gần nhất (hoàn toàn có thể, normal_events rải đều
            # trên 90 ngày) sẽ làm hỏng đúng tín hiệu "im lặng lâu ngày" mà kiểu bất thường này cần thể hiện.
            gets_dormant = random.random() < DORMANT_REACTIVATION_PROBABILITY
            if gets_dormant:
                normal_events = [e for e in normal_events if (now - e.created_at).days >= DORMANT_GAP_DAYS]

            db.add_all(normal_events)
            db.flush()
            labels.extend((ev.id, username, False, "") for ev in normal_events)
            total_normal += len(normal_events)

            if gets_dormant:
                event, label = _make_dormant_reactivation_anomaly(user, profile, now)
                db.add(event)
                db.flush()
                labels.append((event.id, username, True, label))
                total_anomaly += 1

            if random.random() < IMPOSSIBLE_TRAVEL_GEO_PROBABILITY:
                for event, label in _make_impossible_travel_geo_anomaly(user, profile, now):
                    db.add(event)
                    db.flush()
                    if label is None:
                        labels.append((event.id, username, False, ""))
                        total_normal += 1
                    else:
                        labels.append((event.id, username, True, label))
                        total_anomaly += 1

            for anomaly_type in ["unusual_hour", "unusual_location", "unusual_device", "combined"]:
                for _ in range(random.randint(*SINGLE_ANOMALIES_PER_USER_RANGE)):
                    event, label = _make_single_anomaly(user, profile, anomaly_type, now)
                    db.add(event)
                    db.flush()
                    labels.append((event.id, username, True, label))
                    total_anomaly += 1

            for _ in range(random.randint(*RAPID_FIRE_BURSTS_PER_USER_RANGE)):
                burst = _make_rapid_fire_burst(user, profile, random.randint(*RAPID_FIRE_BURST_SIZE_RANGE), now)
                for event, label in burst:
                    db.add(event)
                    db.flush()
                    if label is None:
                        labels.append((event.id, username, False, ""))
                        total_normal += 1
                    else:
                        labels.append((event.id, username, True, label))
                        total_anomaly += 1

        db.commit()

        os.makedirs(os.path.dirname(LABELS_PATH), exist_ok=True)
        with open(LABELS_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["login_event_id", "username", "is_anomaly", "anomaly_type"])
            writer.writerows(labels)

        total = total_normal + total_anomaly
        print(f"Đã tạo {TOTAL_USERS} user (user{USER_ID_START:03d}-user{USER_ID_START + TOTAL_USERS - 1:03d}), {total} bản ghi.")
        print(f"  Bình thường: {total_normal} ({total_normal / total:.1%})")
        print(f"  Bất thường:  {total_anomaly} ({total_anomaly / total:.1%})")
        print(f"Đã lưu nhãn vào {os.path.abspath(LABELS_PATH)} — tách biệt hoàn toàn khỏi login_events.")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="Xoá dữ liệu ML cũ trước khi tạo lại")
    args = parser.parse_args()
    main(reset=args.reset)
