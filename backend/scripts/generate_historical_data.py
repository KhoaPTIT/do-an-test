"""Sinh dữ liệu đăng nhập lịch sử giả lập ban đầu (nhiệm vụ 2.3).

Tạo ~20 user mẫu, mỗi user có một khung giờ đăng nhập "quen thuộc" riêng
(không random đều 0-23h) và một vị trí/IP chủ yếu cố định, trải dài trên
nhiều ngày — để baseline hành vi ở Tuần 4 có ý nghĩa thật.

Insert trực tiếp vào DB (nhanh hơn qua API, và checklist cho phép cả hai
cách). Tất cả bản ghi được gắn is_synthetic=True để tách khỏi dữ liệu demo
thật.

Chạy:
    cd backend
    venv\\Scripts\\python.exe -m scripts.generate_historical_data [--reset]
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone

from app.database import Base, SessionLocal, engine
from app.models import LoginEvent, User
from app.security import hash_password

NUM_USERS = 20
DAYS_BACK = 30
LOGINS_PER_USER_RANGE = (15, 40)
DEFAULT_PASSWORD = "Demo@12345"

# Đa số user ở Việt Nam (đúng khuyến nghị mục 3.5: "đa số cùng một khu vực,
# không random hoàn toàn"), một số ít ở nước ngoài để dữ liệu không đơn điệu.
LOCATIONS = [
    ("VN", "Hanoi", 21.03, 105.85),
    ("VN", "Ho Chi Minh City", 10.78, 106.70),
    ("VN", "Da Nang", 16.05, 108.20),
    ("VN", "Can Tho", 10.05, 105.75),
    ("SG", "Singapore", 1.35, 103.82),
    ("JP", "Tokyo", 35.68, 139.69),
]
# Trọng số: 85% rơi vào nhóm VN (3 thành phố đầu), phần còn lại rải cho vùng khác.
LOCATION_WEIGHTS = [28, 28, 22, 12, 5, 5]


def random_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def make_user_profile(index: int) -> dict:
    return {
        "username": f"user{index:03d}",
        "home_hour": random.uniform(6, 22),  # giờ đăng nhập quen thuộc, ban ngày
        "home_ip": random_ip(),
        "home_location": random.choices(LOCATIONS, weights=LOCATION_WEIGHTS, k=1)[0],
    }


def make_login_events(user: User, profile: dict, count: int) -> list[LoginEvent]:
    events = []
    now = datetime.now(timezone.utc)
    country, city, lat, lon = profile["home_location"]

    for _ in range(count):
        day_offset = random.uniform(0, DAYS_BACK)
        # Phần lớn quanh home_hour (độ lệch chuẩn ~1.2h) => có "thói quen" rõ,
        # không rải đều ngẫu nhiên trên cả ngày.
        hour = profile["home_hour"] + random.gauss(0, 1.2)
        hour = min(max(hour, 0), 23.98)

        ts = now - timedelta(days=day_offset)
        ts = ts.replace(
            hour=int(hour),
            minute=random.randint(0, 59),
            second=random.randint(0, 59),
            microsecond=0,
        )

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


def reset_synthetic_data(db) -> None:
    usernames = [f"user{i:03d}" for i in range(1, NUM_USERS + 1)]
    user_ids = [u.id for u in db.query(User.id).filter(User.username.in_(usernames)).all()]
    if user_ids:
        db.query(LoginEvent).filter(LoginEvent.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(user_ids)).delete(synchronize_session=False)
        db.commit()
        print(f"Đã xoá {len(user_ids)} user giả lập cũ và toàn bộ login_events liên quan.")


def main(reset: bool) -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if reset:
            reset_synthetic_data(db)

        total_events = 0
        created_users = 0
        for i in range(1, NUM_USERS + 1):
            profile = make_user_profile(i)
            username = profile["username"]

            if db.query(User).filter(User.username == username).first():
                print(f"Bỏ qua {username} (đã tồn tại — dùng --reset để tạo lại từ đầu).")
                continue

            user = User(username=username, password_hash=hash_password(DEFAULT_PASSWORD))
            db.add(user)
            db.flush()  # cần user.id trước khi tạo login_events
            created_users += 1

            count = random.randint(*LOGINS_PER_USER_RANGE)
            db.add_all(make_login_events(user, profile, count))
            total_events += count

        db.commit()
        print(f"Đã tạo {created_users} user mới (mật khẩu chung: {DEFAULT_PASSWORD}).")
        print(f"Đã tạo {total_events} bản ghi login_events giả lập (is_synthetic=True).")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="Xoá dữ liệu giả lập cũ trước khi tạo lại")
    args = parser.parse_args()
    main(reset=args.reset)
