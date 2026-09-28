"""MR19 — kiểm tra phần THUẦN (gộp cửa sổ thời gian, viết báo cáo) của scripts/soak_test.py bằng `Sample` tự dựng,
KHÔNG gọi `run()` thật (đó là script gọi HTTP thật, độc lập, xem docs/soak-test.md kết quả đã ghi)."""

from scripts.soak_test import Sample, _bucket_stats, render


def _login(t_sec, status, latency_ms) -> Sample:
    return Sample(t_sec=t_sec, kind="login", status=status, latency_ms=latency_ms)


def test_bucket_stats_groups_by_two_minute_windows_by_default_call():
    samples = [_login(0, 200, 100), _login(10, 200, 200), _login(125, 200, 300)]
    buckets = _bucket_stats(samples, bucket_seconds=120.0)
    assert [b["window_start_min"] for b in buckets] == [0.0, 2.0]
    assert buckets[0]["n"] == 2 and buckets[1]["n"] == 1


def test_bucket_stats_counts_locked_and_unexpected_status_separately():
    samples = [_login(0, 200, 100), _login(1, 401, 100), _login(2, 423, 100), _login(3, 500, 100)]
    buckets = _bucket_stats(samples, bucket_seconds=120.0)
    assert buckets[0]["n_locked_423"] == 1
    assert buckets[0]["n_unexpected_status"] == 1  # chỉ 500 là lạ; 200/401/423 đều là kết quả mong đợi


def test_bucket_stats_ignores_health_samples():
    samples = [_login(0, 200, 100), Sample(t_sec=1, kind="health", status=200, latency_ms=5)]
    buckets = _bucket_stats(samples, bucket_seconds=120.0)
    assert sum(b["n"] for b in buckets) == 1


def test_bucket_stats_returns_empty_list_when_no_login_samples():
    assert _bucket_stats([Sample(t_sec=0, kind="health", status=200, latency_ms=5)], bucket_seconds=120.0) == []


def test_render_round_trips_without_crashing_and_reports_zero_errors_when_all_expected():
    samples = [_login(t, 200 if t % 3 else 401, 100 + t) for t in range(0, 300, 5)]
    markdown = render(samples, minutes=5, rps=1.0)
    assert "Soak test" in markdown
    assert "Request `/login` có status KHÔNG mong đợi (khác 200/401/423): **0**" in markdown


def test_render_surfaces_unexpected_status_count():
    samples = [_login(0, 200, 100), _login(60, 500, 100), _login(120, -1, 100)]
    markdown = render(samples, minutes=2, rps=1.0)
    assert "**2**" in markdown  # 2 status lạ (500 và -1, lỗi kết nối)
