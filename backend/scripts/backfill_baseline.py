"""Batch job tính lại baseline cho toàn bộ user từ lịch sử login_events có
sẵn (nhiệm vụ 4.1 — checklist cho phép baseline "chạy theo lịch hoặc
realtime"; POST /login đã cập nhật REALTIME, script này là phần "theo lịch").

Cần thiết vì dữ liệu login_events của user001-025 được nạp TRỰC TIẾP vào DB
bởi scripts/generate_historical_data.py và generate_labeled_anomalies.py
(Tuần 2-3), không đi qua API /login, nên chưa từng chạy qua
update_baseline_after_successful_login().

Chạy:
    cd backend
    venv\\Scripts\\python.exe -m scripts.backfill_baseline
"""

from __future__ import annotations

from app.database import SessionLocal
from app.detection.baseline import update_baseline_after_successful_login
from app.models import LoginEvent, User, UserBaseline


def main() -> None:
    db = SessionLocal()
    try:
        users = db.query(User).all()
        updated = 0

        for user in users:
            events = (
                db.query(LoginEvent)
                .filter(LoginEvent.user_id == user.id, LoginEvent.success.is_(True))
                .order_by(LoginEvent.created_at.asc())
                .all()
            )
            if not events:
                continue

            # Xoá baseline cũ để tính lại từ đầu — tránh cộng dồn nếu chạy script nhiều lần.
            db.query(UserBaseline).filter(UserBaseline.user_id == user.id).delete()
            db.flush()

            for event in events:
                update_baseline_after_successful_login(db, user, event)
            updated += 1

        db.commit()
        print(f"Đã tính lại baseline cho {updated} user (từ {len(users)} user tổng).")
    finally:
        db.close()


if __name__ == "__main__":
    main()
