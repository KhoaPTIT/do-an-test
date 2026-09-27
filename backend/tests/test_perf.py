"""MR12 — app/detection/perf.py: đo độ trễ trong tiến trình (p50/p95/p99), không lẫn giữa các giai đoạn, không raise khi rỗng."""

import time

import pytest

from app.detection import perf


@pytest.fixture(autouse=True)
def clean_perf():
    perf.reset()
    yield
    perf.reset()


def test_percentiles_return_none_when_nothing_recorded_for_that_stage():
    assert perf.percentiles("no_such_stage") is None
    assert perf.snapshot() == {}


def test_percentiles_compute_the_right_shape_and_bounds():
    for ms in [1, 2, 3, 4, 5, 6, 7, 8, 9, 100]:
        perf.record("stage", ms)
    stats = perf.percentiles("stage")
    assert stats["count"] == 10 and stats["mean_ms"] == pytest.approx(14.5)
    assert stats["p50_ms"] <= stats["p95_ms"] <= stats["p99_ms"] <= stats["max_ms"] == 100


def test_stages_are_independent():
    perf.record("a", 1.0)
    perf.record("b", 999.0)
    assert perf.percentiles("a")["max_ms"] == 1.0 and perf.percentiles("b")["max_ms"] == 999.0
    assert set(perf.snapshot()) == {"a", "b"}


def test_timer_records_the_elapsed_time_of_the_block():
    with perf.timer("block"):
        time.sleep(0.01)
    stats = perf.percentiles("block")
    assert stats["count"] == 1 and stats["mean_ms"] >= 10.0


def test_timer_still_records_when_the_block_raises():
    with pytest.raises(ValueError):
        with perf.timer("failing"):
            raise ValueError("boom")
    assert perf.percentiles("failing")["count"] == 1


def test_the_ring_buffer_drops_the_oldest_samples_once_full():
    small_cap = 5
    original = perf.MAX_SAMPLES
    perf.MAX_SAMPLES = small_cap
    try:
        perf.reset()
        for ms in range(20):
            perf.record("bounded", float(ms))
        stats = perf.percentiles("bounded")
        assert stats["count"] == small_cap and stats["max_ms"] == 19.0  # chỉ 5 mẫu MỚI NHẤT còn lại (15..19)
    finally:
        perf.MAX_SAMPLES = original
        perf.reset()


def test_reset_clears_every_stage():
    perf.record("x", 1.0)
    perf.reset()
    assert perf.snapshot() == {} and perf.percentiles("x") is None
