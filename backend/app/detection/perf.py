"""Đo độ trễ trong tiến trình (MR12: "đo độ trễ p50/p95/p99 và tải").

Vòng đệm có giới hạn (`deque(maxlen=...)`) theo từng "giai đoạn" (`stage`) — không giữ vô hạn số đo, không cần DB/Redis
riêng. Dùng ở `app/detection/pipeline.py` để đo TOÀN BỘ pipeline nền (`"pipeline"`) và từng bước con (`"rba_features"`,
`"rule_engine"`, `"hybrid"`) để biết bước nào chiếm thời gian nhất khi cần tối ưu.

    from app.detection.perf import timer, snapshot

    with timer("pipeline"):
        ...

    snapshot()  # {"pipeline": {"count": 120, "mean_ms": 4.2, "p50_ms": 3.1, "p95_ms": 9.8, "p99_ms": 14.0, "max_ms": 22.1}, ...}

Không thread-safe tuyệt đối (không khoá `deque`) — CPython's GIL khiến `append`/đọc không xen kẽ nửa chừng nên đủ an
toàn cho mục đích đo lường gần đúng; sai số nếu có chỉ là một vài số đo bị bỏ lỡ, không bao giờ raise hay làm sai luồng
đăng nhập (đúng triết lý phần còn lại của module `detection`)."""

from __future__ import annotations

import time
from collections import deque
from contextlib import contextmanager
from typing import Iterator

MAX_SAMPLES = 5_000

_samples: dict[str, deque[float]] = {}


def record(stage: str, ms: float) -> None:
    bucket = _samples.get(stage)
    if bucket is None:
        bucket = _samples[stage] = deque(maxlen=MAX_SAMPLES)
    bucket.append(ms)


@contextmanager
def timer(stage: str) -> Iterator[None]:
    """`with timer("rule_engine"): ...` — ghi thời gian thực thi của khối lệnh (kể cả khi khối lệnh raise: đo lỗi cũng
    là số đo có ích khi tìm nghẽn, và không được nuốt lỗi ở đây — nơi gọi tự quyết định có bắt lỗi hay không)."""
    started = time.perf_counter()
    try:
        yield
    finally:
        record(stage, (time.perf_counter() - started) * 1000)


def _percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, int(round(q * (len(sorted_values) - 1))))
    return sorted_values[idx]


def percentiles(stage: str) -> dict[str, float] | None:
    bucket = _samples.get(stage)
    if not bucket:
        return None
    values = sorted(bucket)
    return {
        "count": len(values), "mean_ms": round(sum(values) / len(values), 3), "p50_ms": round(_percentile(values, 0.50), 3),
        "p95_ms": round(_percentile(values, 0.95), 3), "p99_ms": round(_percentile(values, 0.99), 3), "max_ms": round(values[-1], 3),
    }


def snapshot() -> dict[str, dict[str, float]]:
    """Percentile của MỌI giai đoạn đã ghi, dùng cho báo cáo hoặc endpoint chẩn đoán."""
    return {stage: stats for stage in list(_samples) if (stats := percentiles(stage)) is not None}


def reset() -> None:
    """Xoá toàn bộ số đo — dùng giữa các lần đo trong test/benchmark để không lẫn dữ liệu cũ."""
    _samples.clear()
