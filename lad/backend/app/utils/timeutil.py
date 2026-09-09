"""Hàm lấy thời gian hiện tại theo giờ UTC.

datetime.utcnow() đã bị đánh dấu loại bỏ từ Python 3.12. Toàn hệ thống
dùng datetime không gắn múi giờ nhưng luôn hiểu là UTC, nên hàm này
trả về đúng dạng đó để không phải sửa lại toàn bộ kiểu dữ liệu.
"""
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
