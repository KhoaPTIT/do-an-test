"""Baseline hành vi user (nhiệm vụ 4.1).

Cập nhật REALTIME ngay sau mỗi lần đăng nhập THÀNH CÔNG (checklist cho
phép "chạy theo lịch hoặc realtime" — chọn realtime vì đơn giản hơn cho
quy mô đồ án, không cần thêm job nền/cron).

"Chế độ học": user có < 10 lần đăng nhập HOẶC chưa đủ 7 ngày kể từ lần đầu
thì CHƯA áp dụng rule phụ thuộc baseline (unusual_hour, unknown_location ở
scoring.py) — lấy nguyên văn ngưỡng từ checklist gốc mục 4.1.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import KnownDevice, KnownLocation, LoginEvent, User, UserBaseline

LEARNING_MODE_MIN_LOGINS = 10
LEARNING_MODE_MIN_DAYS = 7


def is_in_learning_mode(baseline: UserBaseline | None) -> bool:
    """True nếu user CHƯA đủ dữ liệu để áp rule phụ thuộc baseline."""
    if baseline is None:
        return True
    if baseline.successful_login_count < LEARNING_MODE_MIN_LOGINS:
        return True
    if baseline.first_login_at is None:
        return True

    first_login_at = baseline.first_login_at
    if first_login_at.tzinfo is None:  # SQLite (test) trả naive datetime
        first_login_at = first_login_at.replace(tzinfo=timezone.utc)

    days_since_first = (datetime.now(timezone.utc) - first_login_at).days
    return days_since_first < LEARNING_MODE_MIN_DAYS


def update_baseline_after_successful_login(db: Session, user: User, event: LoginEvent) -> UserBaseline:
    """Gọi sau khi đã flush login_events cho MỘT lần đăng nhập THÀNH CÔNG."""
    baseline = db.query(UserBaseline).filter(UserBaseline.user_id == user.id).first()
    if baseline is None:
        baseline = UserBaseline(user_id=user.id, successful_login_count=0, first_login_at=event.created_at)
        db.add(baseline)
        # Session dùng autoflush=False (app/database.py) — flush ngay để lần
        # gọi TIẾP THEO trong cùng session (VD vòng lặp backfill nhiều sự
        # kiện của cùng 1 user) nhìn thấy bản ghi này qua query thay vì tạo
        # trùng khoá chính user_id (đã ăn UniqueViolation thật khi test).
        db.flush()

    if baseline.first_login_at is None:
        baseline.first_login_at = event.created_at

    baseline.successful_login_count += 1

    # Tính lại avg/stddev từ TOÀN BỘ lịch sử thành công — đơn giản, đủ tốt
    # cho quy mô đồ án (không cần công thức incremental online).
    hours = [
        ev_created_at.hour + ev_created_at.minute / 60
        for (ev_created_at,) in db.query(LoginEvent.created_at).filter(
            LoginEvent.user_id == user.id, LoginEvent.success.is_(True)
        )
    ]
    if len(hours) >= 2:
        baseline.avg_login_hour = statistics.mean(hours)
        baseline.stddev_login_hour = statistics.pstdev(hours)
    elif len(hours) == 1:
        baseline.avg_login_hour = hours[0]
        baseline.stddev_login_hour = 0.0

    return baseline


def is_known_device(db: Session, user_id: int, device_fingerprint: str | None) -> bool:
    """Chỉ đọc — KHÔNG ghi. Dùng cho cả rule fail lẫn success."""
    if not device_fingerprint:
        return True  # thiếu dữ liệu, không kết luận được -> coi như không lạ (tránh false positive)
    return (
        db.query(KnownDevice)
        .filter(KnownDevice.user_id == user_id, KnownDevice.device_fingerprint == device_fingerprint)
        .first()
        is not None
    )


def is_known_location(db: Session, user_id: int, country: str | None, city: str | None) -> bool:
    """Chỉ đọc — KHÔNG ghi."""
    if not country:
        return True  # thiếu GeoIP, không kết luận được -> coi như không lạ
    return (
        db.query(KnownLocation)
        .filter(KnownLocation.user_id == user_id, KnownLocation.country == country, KnownLocation.city == city)
        .first()
        is not None
    )


def record_known_device_if_new(db: Session, user: User, device_fingerprint: str | None, user_agent: str | None) -> None:
    """Ghi nhận thiết bị — CHỈ gọi khi đăng nhập THÀNH CÔNG."""
    if not device_fingerprint:
        return
    known = (
        db.query(KnownDevice)
        .filter(KnownDevice.user_id == user.id, KnownDevice.device_fingerprint == device_fingerprint)
        .first()
    )
    if known is not None:
        known.last_seen_at = datetime.now(timezone.utc)
        return
    db.add(KnownDevice(user_id=user.id, device_fingerprint=device_fingerprint, user_agent=user_agent))
    db.flush()  # tránh insert trùng nếu gọi lại trong cùng session (xem ghi chú ở update_baseline_after_successful_login)


def record_known_location_if_new(db: Session, user: User, country: str | None, city: str | None) -> None:
    """Ghi nhận vị trí — CHỈ gọi khi đăng nhập THÀNH CÔNG."""
    if not country:
        return
    known = (
        db.query(KnownLocation)
        .filter(KnownLocation.user_id == user.id, KnownLocation.country == country, KnownLocation.city == city)
        .first()
    )
    if known is not None:
        known.last_seen_at = datetime.now(timezone.utc)
        return
    db.add(KnownLocation(user_id=user.id, country=country, city=city))
    db.flush()  # tránh insert trùng nếu gọi lại trong cùng session
