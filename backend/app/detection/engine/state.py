"""Kho cửa sổ thời gian cho rule engine v2 (MR9): đếm sự kiện và giá trị KHÁC NHAU trong một khoảng thời gian gần đây.

Hai loại khoá:
  - NHẬT KÝ (`log_*`): mỗi lần `log_add` thêm một mốc thời gian; hỏi "có bao nhiêu mốc sau thời điểm `since`" và "N mốc gần nhất".
    Dùng để đếm số lần thất bại của một tài khoản/IP và để đo độ đều của nhịp thử.
  - TẬP (`set_*`): mỗi giá trị chỉ xuất hiện một lần, nhớ lần thấy CUỐI CÙNG; hỏi "có bao nhiêu giá trị khác nhau được thấy sau `since`".
    Dùng để đếm tên đăng nhập / IP / User-Agent khác nhau (cùng cách với `rate_counter.record_credential_stuffing_attempt`).

Cửa sổ là (since, hiện tại] — mốc đúng bằng `since` KHÔNG được tính, giống các cửa sổ ở ml/rba/features.py. Thời gian luôn là thời gian của SỰ KIỆN
(replay log cũ phải cho cùng kết quả), và các lần `*_add` của cùng một khoá phải đến theo thứ tự thời gian không giảm (luồng thật và replay đều thế).

Hai cài đặt cho CÙNG một hợp đồng (tests/test_rule_engine_state.py chạy cả hai với cùng một bộ test):
  - `MemoryStore`: trong bộ nhớ, dùng cho replay và test. Truy vấn nhật ký O(log n) (tìm nhị phân); truy vấn tập chạy từ mốc mới nhất lùi về và DỪNG
    khi đủ `cap` (luật chỉ cần biết "≥ ngưỡng"), nên chi phí mỗi sự kiện bị chặn bởi ngưỡng chứ không bởi độ dài cửa sổ — IP tấn công có hàng chục
    nghìn sự kiện mỗi ngày vẫn replay được.
  - `RedisStore`: cho luồng thật, sorted set của Redis (ZADD/ZCOUNT), dùng tiền tố khoá riêng `rule:` để không đụng khoá của rate_counter.py.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from bisect import bisect_left, bisect_right, insort
from collections import OrderedDict

KEY_PREFIX = "rule:"
_EXPIRE_SLACK_SECONDS = 60


class WindowStore(ABC):
    @abstractmethod
    def log_add(self, key: str, ts: float, ttl: float) -> None:
        """Thêm một mốc thời gian vào nhật ký `key`; mốc cũ hơn `ttl` giây so với `ts` bị bỏ."""

    @abstractmethod
    def log_count(self, key: str, since: float) -> int:
        """Số mốc có thời gian > `since`."""

    @abstractmethod
    def log_recent(self, key: str, n: int) -> list[float]:
        """`n` mốc gần nhất, xếp tăng dần theo thời gian."""

    @abstractmethod
    def set_add(self, key: str, ts: float, value: str, ttl: float) -> None:
        """Ghi nhận thấy `value` lúc `ts` (giá trị đã có thì cập nhật lần thấy cuối)."""

    @abstractmethod
    def set_count(self, key: str, since: float, cap: int | None = None) -> int:
        """Số giá trị KHÁC NHAU có lần thấy cuối > `since`; nếu có `cap` thì trả `min(số thật, cap)`."""

    @abstractmethod
    def set_values(self, key: str, since: float, limit: int = 100) -> list[str]:
        """Tối đa `limit` giá trị (mới nhất trước) có lần thấy cuối > `since`."""


class MemoryStore(WindowStore):
    """`sweep_every`: xoá các khoá đã quá hạn hoàn toàn sau mỗi chừng này lần ghi (và không ít hơn số khoá còn lại sau lần dọn trước, để chi phí quét
    luôn chia đều O(1) cho mỗi lần ghi dù tốc độ tạo khoá mới thế nào). Không có bước này, replay hàng triệu sự kiện giữ mãi mọi IP/tên đăng nhập từng
    gặp (mỗi khoá chỉ được cắt tỉa khi CÓ THÊM sự kiện cùng khoá). 0 = không dọn."""

    def __init__(self, sweep_every: int = 100_000) -> None:
        self._logs: dict[str, list[float]] = {}
        self._sets: dict[str, OrderedDict[str, float]] = {}
        self._expiry: dict[str, float] = {}  # khoá -> thời điểm của mốc mới nhất + ttl: sau đó khoá không còn nằm trong cửa sổ hợp lệ nào
        self._clock = float("-inf")  # thời gian SỰ KIỆN lớn nhất đã thấy (đồng hồ của luồng, không phải giờ hệ thống)
        self._sweep_every, self._writes, self._threshold = sweep_every, 0, sweep_every

    def _touch(self, key: str, ts: float, ttl: float) -> None:
        expiry = ts + ttl
        if expiry > self._expiry.get(key, float("-inf")):
            self._expiry[key] = expiry
        if ts > self._clock:
            self._clock = ts
        self._writes += 1
        if self._sweep_every and self._writes >= self._threshold:
            self.sweep()

    def sweep(self) -> int:
        """Xoá khoá mà mọi mốc đã quá hạn hơn `ttl` (+ độ trễ cho phép như Redis): chúng không thể nằm trong cửa sổ nào của luật nữa nên số đếm không đổi.
        Trả về số khoá đã xoá."""
        limit = self._clock - _EXPIRE_SLACK_SECONDS
        dead = [key for key, expiry in self._expiry.items() if expiry < limit]
        for key in dead:
            del self._expiry[key]
            self._logs.pop(key, None)
            self._sets.pop(key, None)
        self._writes, self._threshold = 0, max(self._sweep_every, len(self._expiry))  # lần dọn sau: khi số lần ghi bằng số khoá còn giữ
        return len(dead)

    def log_add(self, key: str, ts: float, ttl: float) -> None:
        times = self._logs.setdefault(key, [])
        if times and ts < times[-1]:
            insort(times, ts)  # trễ vài mili-giây giữa hai tiến trình: giữ mảng có thứ tự
        else:
            times.append(ts)
        cutoff = ts - ttl
        if times[0] < cutoff:
            del times[: bisect_left(times, cutoff)]
        self._touch(key, ts, ttl)

    def log_count(self, key: str, since: float) -> int:
        times = self._logs.get(key)
        return 0 if not times else len(times) - bisect_right(times, since)

    def log_recent(self, key: str, n: int) -> list[float]:
        times = self._logs.get(key)
        return [] if not times or n <= 0 else times[-n:]

    def set_add(self, key: str, ts: float, value: str, ttl: float) -> None:
        seen = self._sets.setdefault(key, OrderedDict())
        seen.pop(value, None)
        seen[value] = ts  # cuối OrderedDict = mới nhất
        cutoff = ts - ttl
        while seen:
            oldest = next(iter(seen.values()))
            if oldest >= cutoff:
                break
            seen.popitem(last=False)
        self._touch(key, ts, ttl)

    def set_count(self, key: str, since: float, cap: int | None = None) -> int:
        seen = self._sets.get(key)
        if not seen:
            return 0
        count = 0
        for last_seen in reversed(seen.values()):
            if last_seen <= since or (cap is not None and count >= cap):
                break
            count += 1
        return count

    def set_values(self, key: str, since: float, limit: int = 100) -> list[str]:
        seen = self._sets.get(key)
        if not seen:
            return []
        out: list[str] = []
        for value, last_seen in reversed(seen.items()):
            if last_seen <= since or len(out) >= limit:
                break
            out.append(value)
        return out

    def keys(self) -> int:
        """Số khoá đang giữ (chẩn đoán bộ nhớ khi replay)."""
        return len(self._expiry)


class RedisStore(WindowStore):
    """Cài đặt trên Redis (sorted set). `client` là `redis.Redis(decode_responses=True)` hoặc fakeredis."""

    def __init__(self, client, prefix: str = KEY_PREFIX) -> None:
        self.client, self.prefix = client, prefix

    def _key(self, key: str) -> str:
        return f"{self.prefix}{key}"

    def _write(self, key: str, mapping: dict[str, float], ts: float, ttl: float) -> None:
        full = self._key(key)
        pipe = self.client.pipeline()
        pipe.zadd(full, mapping)
        pipe.zremrangebyscore(full, "-inf", ts - ttl - 1e-9)  # bỏ mốc < ts - ttl
        pipe.expire(full, int(ttl) + _EXPIRE_SLACK_SECONDS)
        pipe.execute()

    def log_add(self, key: str, ts: float, ttl: float) -> None:
        self._write(key, {f"{ts}:{uuid.uuid4().hex}": ts}, ts, ttl)  # uuid: hai lần thất bại cùng một tích tắc không bị gộp

    def log_count(self, key: str, since: float) -> int:
        return int(self.client.zcount(self._key(key), f"({since}", "+inf"))

    def log_recent(self, key: str, n: int) -> list[float]:
        if n <= 0:
            return []
        rows = self.client.zrevrange(self._key(key), 0, n - 1, withscores=True)
        return sorted(float(score) for _, score in rows)

    def set_add(self, key: str, ts: float, value: str, ttl: float) -> None:
        self._write(key, {value: ts}, ts, ttl)  # zadd ghi đè điểm: nhớ lần thấy cuối

    def set_count(self, key: str, since: float, cap: int | None = None) -> int:
        count = int(self.client.zcount(self._key(key), f"({since}", "+inf"))
        return count if cap is None else min(count, cap)

    def set_values(self, key: str, since: float, limit: int = 100) -> list[str]:
        return list(self.client.zrevrangebyscore(self._key(key), "+inf", f"({since}", start=0, num=limit))


def now() -> float:
    """Giờ hệ thống — chỉ dùng cho luồng thật; replay luôn truyền thời gian của sự kiện."""
    return time.time()
