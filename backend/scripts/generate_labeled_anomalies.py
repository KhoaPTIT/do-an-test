"""Mở rộng dữ liệu lịch sử giả lập + gắn nhãn is_anomaly (nhiệm vụ 3.5).

Sinh lại TOÀN BỘ tập dữ liệu synthetic (user001-user025, 20 kế thừa từ
Tuần 2 + 5 user mới) từ đầu: log trải dài hơn (60 ngày thay vì 30) và có
chèn có chủ đích các ca bất thường (giờ lạ / vị trí lạ).

Nhãn ground-truth (is_anomaly) được lưu ở file CSV RIÊNG
(backend/ml/data/labels.csv) — KHÔNG thêm cột vào login_events, để nhãn
không "rò rỉ" vào dữ liệu mà detection engine sẽ đọc (tránh cheat khi đánh
giá precision/recall ở Tuần 7).

Chạy:
    cd backend
    venv\\Scripts\\python.exe -m scripts.generate_labeled_anomalies --reset
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
from scripts.generate_historical_data import LOCATIONS, LOCATION_WEIGHTS, random_ip

TOTAL_USERS = 25  # 20 kế thừa tuần 2.3 (user001-020) + 5 user mới (user021-025)
EXTENDED_DAYS_BACK = 60
NORMAL_LOGINS_PER_USER_RANGE = (20, 45)
ANOMALIES_PER_USER_RANGE = (3, 6)
DEFAULT_PASSWORD = "Demo@12345"

# Vị trí "lạ" dùng riêng cho ca bất thường — khác hẳn LOCATIONS (nơi ở quen thuộc).
FAR_LOCATIONS = [
    ("RU", "Moscow", 55.75, 37.62),
    ("US", "New York", 40.71, -74.01),
    ("BR", "Sao Paulo", -23.55, -46.63),
    ("NG", "Lagos", 6.52, 3.38),
]

LABELS_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "data", "labels.csv")


def make_user_profile(index: int) -> dict:
    return {
        "username": f"user{index:03d}",
        "home_hour": random.uniform(6, 22),
        "home_ip": random_ip(),
        "home_location": random.choices(LOCATIONS, weights=LOCATION_WEIGHTS, k=1)[0],
    }


def make_normal_events(user: User, profile: dict, count: int) -> list[LoginEvent]:
    events = []
    now = datetime.now(timezone.utc)
    country, city, lat, lon = profile["home_location"]

    for _ in range(count):
        day_offset = random.uniform(0, EXTENDED_DAYS_BACK)
        hour = min(max(profile["home_hour"] + random.gauss(0, 1.2), 0), 23.98)
        ts = now - timedelta(days=day_offset)
        ts = ts.replace(hour=int(hour), minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)

        events.append(
            LoginEvent(
                user_id=user.id,
                attempted_username=user.username,
                success=True,
                ip_address=profile["home_ip"],
                user_agent="synthetic-seed-script/1.0",
                country=country,
                city=city,
                latitude=lat,
                longitude=lon,
                is_synthetic=True,
                created_at=ts,
            )
        )
    return events


def make_anomalous_events(user: User, profile: dict, count: int) -> list[tuple[LoginEvent, str]]:
    """Trả về list (event, anomaly_type). anomaly_type CHỈ dùng để ghi nhãn
    ra file riêng — cố tình KHÔNG lưu bất kỳ dấu hiệu nào vào chính bản ghi
    LoginEvent (user_agent giống hệt dữ liệu bình thường) để không lộ nhãn
    vào dữ liệu detection engine sẽ đọc.
    """
    events = []
    now = datetime.now(timezone.utc)
    country, city, lat, lon = profile["home_location"]

    for _ in range(count):
        anomaly_type = random.choice(["unusual_hour", "unusual_location"])
        ts = now - timedelta(days=random.uniform(0, EXTENDED_DAYS_BACK))

        if anomaly_type == "unusual_hour":
            # Giờ đối lập hoàn toàn với khung giờ quen thuộc (VD quen ban ngày -> đăng nhập lúc 2-4h sáng).
            odd_hour = (profile["home_hour"] + 12 + random.uniform(-1, 1)) % 24
            ts = ts.replace(hour=int(odd_hour), minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)
            ev_country, ev_city, ev_lat, ev_lon, ev_ip = country, city, lat, lon, profile["home_ip"]
        else:  # unusual_location
            far = random.choice([loc for loc in FAR_LOCATIONS if loc[0] != country])
            ev_country, ev_city, ev_lat, ev_lon = far
            ev_ip = random_ip()
            hour = min(max(profile["home_hour"] + random.gauss(0, 1.2), 0), 23.98)
            ts = ts.replace(hour=int(hour), minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)

        events.append(
            (
                LoginEvent(
                    user_id=user.id,
                    attempted_username=user.username,
                    success=True,
                    ip_address=ev_ip,
                    user_agent="synthetic-seed-script/1.0",
                    country=ev_country,
                    city=ev_city,
                    latitude=ev_lat,
                    longitude=ev_lon,
                    is_synthetic=True,
                    created_at=ts,
                ),
                anomaly_type,
            )
        )
    return events


def reset_synthetic_data(db) -> None:
    usernames = [f"user{i:03d}" for i in range(1, TOTAL_USERS + 1)]
    user_ids = [u.id for u in db.query(User.id).filter(User.username.in_(usernames)).all()]
    if user_ids:
        db.query(LoginEvent).filter(LoginEvent.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(user_ids)).delete(synchronize_session=False)
        db.commit()
        print(f"Đã xoá {len(user_ids)} user + toàn bộ login_events liên quan để tạo lại từ đầu.")


def main(reset: bool) -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    labels: list[tuple[int, str, bool, str]] = []

    try:
        if reset:
            reset_synthetic_data(db)

        total_normal = 0
        total_anomaly = 0

        for i in range(1, TOTAL_USERS + 1):
            profile = make_user_profile(i)
            username = profile["username"]

            user = db.query(User).filter(User.username == username).first()
            if user is None:
                user = User(username=username, password_hash=hash_password(DEFAULT_PASSWORD))
                db.add(user)
                db.flush()

            normal_events = make_normal_events(user, profile, random.randint(*NORMAL_LOGINS_PER_USER_RANGE))
            db.add_all(normal_events)
            db.flush()
            labels.extend((ev.id, username, False, "") for ev in normal_events)
            total_normal += len(normal_events)

            anomalous = make_anomalous_events(user, profile, random.randint(*ANOMALIES_PER_USER_RANGE))
            db.add_all(ev for ev, _ in anomalous)
            db.flush()
            labels.extend((ev.id, username, True, anomaly_type) for ev, anomaly_type in anomalous)
            total_anomaly += len(anomalous)

        db.commit()

        os.makedirs(os.path.dirname(LABELS_PATH), exist_ok=True)
        with open(LABELS_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["login_event_id", "username", "is_anomaly", "anomaly_type"])
            writer.writerows(labels)

        total = total_normal + total_anomaly
        print(f"Đã tạo {TOTAL_USERS} user, {total} bản ghi login_events ({total_normal} bình thường, {total_anomaly} bất thường).")
        print(f"Tỷ lệ bình thường: {total_normal / total:.1%} (mục tiêu 80-90%, mục 11 tài liệu chính).")
        print(f"Đã lưu nhãn vào {os.path.abspath(LABELS_PATH)} — tách biệt hoàn toàn khỏi bảng login_events.")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="Xoá dữ liệu giả lập cũ trước khi tạo lại")
    args = parser.parse_args()
    main(reset=args.reset)
