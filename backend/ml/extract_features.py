"""Trích xuất ma trận đặc trưng từ login_events (user101-140) + nhãn
labels.csv → ml/data/features.csv (nhiệm vụ 7.1).

Xử lý TUẦN TỰ theo thời gian, RIÊNG cho từng user (giống hệt cách hệ thống
thật sẽ thấy dữ liệu real-time) — đây là bước quan trọng nhất để tránh rò
rỉ dữ liệu tương lai vào đặc trưng (xem ml/features.py).

Ngoài 9 đặc trưng cho ML, còn ghi thêm 4 cột "ngữ cảnh" (avg/stddev giờ,
số lần đăng nhập, lần đầu tiên) — KHÔNG dùng làm input cho ML, chỉ để
ml/evaluate.py dựng lại đúng `UserBaseline` và gọi THẲNG hàm
`compute_risk_score()` thật của tầng 2 (app/detection/scoring.py), đảm bảo
so sánh tầng 2 vs tầng 3 công bằng trên cùng 1 hàm sản xuất thật, không
phải bản viết lại song song có thể lệch nhau.

Chạy (sau khi đã chạy ml/generate_dataset.py):
    cd backend
    venv\\Scripts\\python.exe -m ml.extract_features
"""

from __future__ import annotations

import csv
import os
import statistics

from app.database import SessionLocal
from app.models import LoginEvent, User
from ml.features import FEATURE_NAMES, UserHistoryState, compute_features, update_state
from ml.generate_dataset import TOTAL_USERS, USER_ID_START

LABELS_PATH = os.path.join(os.path.dirname(__file__), "data", "labels.csv")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "data", "features.csv")


def _load_labels() -> dict[int, tuple[bool, str]]:
    labels: dict[int, tuple[bool, str]] = {}
    with open(LABELS_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            labels[int(row["login_event_id"])] = (row["is_anomaly"] == "True", row["anomaly_type"])
    return labels


def main() -> None:
    labels = _load_labels()
    usernames = [f"user{i:03d}" for i in range(USER_ID_START, USER_ID_START + TOTAL_USERS)]

    db = SessionLocal()
    rows: list[dict] = []

    try:
        for username in usernames:
            user = db.query(User).filter(User.username == username).first()
            if user is None:
                continue

            events = (
                db.query(LoginEvent)
                .filter(LoginEvent.user_id == user.id, LoginEvent.success.is_(True))
                .order_by(LoginEvent.created_at.asc())
                .all()
            )

            state = UserHistoryState()
            for event in events:
                if event.id not in labels:
                    continue  # bản ghi không thuộc tập ML (VD dữ liệu dashboard cũ)

                is_anomaly, anomaly_type = labels[event.id]
                features = compute_features(
                    state,
                    country=event.country,
                    city=event.city,
                    latitude=event.latitude,
                    longitude=event.longitude,
                    device_fingerprint=event.device_fingerprint,
                    created_at=event.created_at,
                )

                # Ngữ cảnh cho tầng 2 thật (xem docstring đầu file) — TÍNH TỪ
                # LỊCH SỬ TRƯỚC sự kiện này, giống hệt nguyên tắc chống rò rỉ
                # dữ liệu tương lai áp dụng cho đặc trưng ML.
                if len(state.login_hours) >= 2:
                    avg_hour_so_far = sum(state.login_hours) / len(state.login_hours)
                    stddev_hour_so_far = statistics.pstdev(state.login_hours)
                elif len(state.login_hours) == 1:
                    avg_hour_so_far = state.login_hours[0]
                    stddev_hour_so_far = 0.0
                else:
                    avg_hour_so_far = None
                    stddev_hour_so_far = None

                row = {
                    "login_event_id": event.id,
                    "username": username,
                    "created_at": event.created_at.isoformat(),
                    "is_anomaly": int(is_anomaly),
                    "anomaly_type": anomaly_type,
                    "login_hour": event.created_at.hour + event.created_at.minute / 60,
                    "successful_login_count_so_far": len(state.login_hours),
                    "avg_login_hour_so_far": avg_hour_so_far,
                    "stddev_login_hour_so_far": stddev_hour_so_far,
                    "first_login_at_so_far": state.recent_timestamps[0].isoformat() if state.recent_timestamps else None,
                    **features,
                }
                rows.append(row)

                update_state(
                    state,
                    country=event.country,
                    city=event.city,
                    latitude=event.latitude,
                    longitude=event.longitude,
                    device_fingerprint=event.device_fingerprint,
                    created_at=event.created_at,
                )
    finally:
        db.close()

    os.makedirs(os.path.dirname(FEATURES_PATH), exist_ok=True)
    fieldnames = [
        "login_event_id", "username", "created_at", "is_anomaly", "anomaly_type", "login_hour",
        "successful_login_count_so_far", "avg_login_hour_so_far", "stddev_login_hour_so_far", "first_login_at_so_far",
        *FEATURE_NAMES,
    ]
    with open(FEATURES_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    anomaly_count = sum(r["is_anomaly"] for r in rows)
    print(f"Đã trích xuất {len(rows)} dòng đặc trưng ({anomaly_count} bất thường, {anomaly_count / len(rows):.1%}).")
    print(f"Lưu tại {os.path.abspath(FEATURES_PATH)}")


if __name__ == "__main__":
    main()
