"""Mô hình bất thường lúc chạy thật (Phase 4.1): trích đặc trưng từ DB bằng ĐÚNG đặc tả offline (`ml/features.py`).

Phần trích đặc trưng ở đây chỉ làm một việc: dựng danh sách `LoginRecord` cho các lần đăng nhập THÀNH CÔNG của tài khoản xảy
ra TRƯỚC HẲN sự kiện đang chấm — loại trừ tường minh chính sự kiện đó (đã `flush` vào DB trước khi chấm, xem
`app/detection/pipeline.py`) — rồi gọi `compute_features` dùng chung với offline."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import LoginEvent
from app.utils.time import ensure_utc
from ml.features import LoginRecord, compute_features, in_scope, make_record


def record_from_event(event) -> LoginRecord:
    """`event`: hàng `LoginEvent` (hoặc bất kỳ đối tượng nào có cùng các cột)."""
    return make_record(
        event.created_at, country=event.country, city=event.city, latitude=event.latitude, longitude=event.longitude, user_agent=event.user_agent,
    )


def prior_successes(db: Session, user_id: int, before: datetime, exclude_event_id: int | None = None) -> list[LoginRecord]:
    """Lần THÀNH CÔNG của tài khoản có `created_at` TRƯỚC HẲN `before`, tăng dần — không bao giờ gồm `exclude_event_id`."""
    query = select(LoginEvent).where(LoginEvent.user_id == user_id, LoginEvent.success.is_(True), LoginEvent.created_at < before)
    if exclude_event_id is not None:
        query = query.where(LoginEvent.id != exclude_event_id)
    rows = db.execute(query.order_by(LoginEvent.created_at, LoginEvent.id)).scalars().all()
    return [record_from_event(row) for row in rows]


def runtime_features(db: Session, event) -> tuple[bool, dict[str, float] | None]:
    """(thuộc phạm vi chấm?, đặc trưng) cho MỘT sự kiện đã ghi vào DB. Ngoài phạm vi (thất bại, tài khoản không tồn tại, hồ sơ
    chưa trưởng thành) thì không tính đặc trưng — mô hình chỉ học và chỉ chấm lần thành công của hồ sơ trưởng thành."""
    if not event.success or event.user_id is None:
        return False, None
    current = record_from_event(event)
    prior = prior_successes(db, event.user_id, ensure_utc(event.created_at), exclude_event_id=event.id)
    if not in_scope(prior, current):
        return False, None
    return True, compute_features(prior, current)
