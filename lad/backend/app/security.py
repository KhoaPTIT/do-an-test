"""Bảo vệ chính API này.

Hệ thống phát hiện xâm nhập mà bản thân nó lại hở thì vô nghĩa,
nên phần này cần có mặt trong báo cáo. Ba lớp bảo vệ tối thiểu:
  1. Xác thực bằng API key, so sánh theo kiểu chống tấn công phân tích thời gian
  2. Giới hạn tần suất gọi
  3. Kiểm tra dữ liệu đầu vào (đã làm trong schemas.py bằng Pydantic)
"""
import secrets
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, status

from app.config import API_KEY, RATE_LIMIT_PER_MINUTE

# Bộ đếm tần suất trong bộ nhớ. Đủ cho đồ án và môi trường một tiến trình.
# Khi chạy nhiều tiến trình cần chuyển sang Redis.
_hits = defaultdict(deque)


def _rate_limit(key: str):
    now = time.time()
    q = _hits[key]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Vượt quá giới hạn số request mỗi phút",
        )
    q.append(now)


def require_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    """Dependency dùng cho mọi endpoint cần bảo vệ."""
    # compare_digest so sánh trong thời gian không đổi, tránh để kẻ tấn công
    # dò từng ký tự khóa dựa vào chênh lệch thời gian phản hồi.
    if not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key không hợp lệ",
        )
    _rate_limit(x_api_key)
    return x_api_key
