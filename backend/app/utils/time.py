"""Xử lý datetime nhất quán múi giờ khi đọc lại từ DB (MR12).

SQLite (dùng cho test, `tests/conftest.py`) KHÔNG giữ tzinfo khi lưu/đọc lại cột `DateTime(timezone=True)` — đọc lại
luôn là datetime NAIVE dù giá trị gốc là UTC (Postgres thật giữ đúng tzinfo, không cần hàm này). Toàn hệ thống luôn ghi
giờ UTC (`datetime.now(timezone.utc)` ở `app/routers/auth.py`, `func.now()` ở DB) nên một datetime KHÔNG có tzinfo đọc
từ DB được hiểu là UTC, KHÔNG PHẢI giờ địa phương của máy đang chạy — nếu không coi chừng, `.timestamp()` trên một
datetime naive sẽ bị Python hiểu theo giờ địa phương, lệch hàng giờ so với ý nghĩa thật (đã bắt được lỗi này ở
MR9's `app.detection.engine.replay.attempt_from_event` khi đọc `login_events` qua SQLite; cùng lỗi lặp lại ở MR12 khi
tính đặc trưng RBA và lịch sử tài khoản từ DB — sửa MỘT CHỖ DÙNG CHUNG thay vì hai chỗ riêng lẻ)."""

from __future__ import annotations

from datetime import datetime, timezone


def ensure_utc(moment: datetime) -> datetime:
    """`moment` có tzinfo thì giữ nguyên; không có thì coi là UTC (xem docstring module)."""
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)
