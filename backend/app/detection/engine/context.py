"""Lịch sử tài khoản và thống kê toàn hệ thống cho rule engine v2 (MR9).

Luồng thật (MR12) cài hai giao diện này bằng DB; replay và test dùng bản trong bộ nhớ ở đây, được engine cập nhật SAU KHI chấm mỗi lần thử
(nên khi chấm lần thử thứ n, lịch sử chỉ chứa n−1 lần trước — cùng ngữ nghĩa "chỉ nhìn quá khứ" như đặc trưng ở ml/rba/features.py).
"""

from __future__ import annotations

import sys
from collections import Counter
from typing import Protocol

from app.detection.engine.types import AccountHistory, LoginAttempt


class HistoryProvider(Protocol):
    def get(self, user_key: str | None) -> AccountHistory | None:
        """Quá khứ của tài khoản trước lần thử đang chấm, None nếu tài khoản không tồn tại hoặc chưa có lịch sử."""

    def update(self, attempt: LoginAttempt) -> None:
        """Ghi nhận lần thử vừa chấm xong (bản DB có thể để trống: pipeline tự cập nhật bảng)."""


class GlobalStats(Protocol):
    @property
    def total_successes(self) -> int: ...

    def asn_successes(self, asn: int) -> int: ...

    def update(self, attempt: LoginAttempt) -> None: ...


class MemoryHistory:
    def __init__(self) -> None:
        self._accounts: dict[str, AccountHistory] = {}

    def __len__(self) -> int:
        """Số tài khoản đang có lịch sử (chẩn đoán bộ nhớ khi replay)."""
        return len(self._accounts)

    def get(self, user_key: str | None) -> AccountHistory | None:
        return None if user_key is None else self._accounts.get(user_key)

    def update(self, attempt: LoginAttempt) -> None:
        if attempt.user_key is None:
            return
        h = self._accounts.setdefault(attempt.user_key, AccountHistory())
        h.last_event_ts = attempt.ts
        h.last_event_lat, h.last_event_lon = attempt.latitude, attempt.longitude
        if attempt.success:  # hồ sơ CHỈ học từ lần thành công (AccountHistory.record_success)
            h.record_success(
                attempt.ts, lat=attempt.latitude, lon=attempt.longitude, country=attempt.country, city=attempt.city,
                device_family=attempt.device_family, agent_hash=attempt.ua_hash, asn=attempt.asn,
            )


class MemoryGlobalStats:
    """Đếm đăng nhập THÀNH CÔNG vào tài khoản có thật, theo ASN — nền cho luật "nhà mạng cực hiếm" (share = số lần của ASN / tổng)."""

    def __init__(self) -> None:
        self._total = 0
        self._by_asn: Counter[int] = Counter()

    @property
    def total_successes(self) -> int:
        return self._total

    def asn_successes(self, asn: int) -> int:
        return self._by_asn.get(asn, 0)

    def update(self, attempt: LoginAttempt) -> None:
        if attempt.success and attempt.user_key is not None and attempt.asn is not None:
            self._total += 1
            self._by_asn[attempt.asn] += 1
