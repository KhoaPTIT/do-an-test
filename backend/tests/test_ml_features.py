"""Đặc tả đặc trưng mô hình bất thường v3 (`ml/features.py`) — hàm thuần, dùng chung offline/runtime.

Phase 4.1 thay bộ đặc trưng tầng 3 cũ (Tuần 7): các test của bản cũ (`UserHistoryState`, `compute_realtime_features`, giờ trung
bình CỘNG, thiết bị = băm toàn bộ User-Agent) được thay bằng các test dưới đây — thay đổi thiết kế có chủ ý để sửa lệch
train/serve tìm được ở audit Phase 4.0."""

import math
from datetime import datetime, timedelta, timezone

from ml.features import FEATURE_NAMES, LoginRecord, compute_features, feature_signature, feature_vector, in_scope, make_record

T = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)
CHROME_120 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
CHROME_121 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36"
FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"


def rec(ts, ua=CHROME_120, country="VN", city="Hanoi", lat=21.03, lon=105.85):
    return make_record(ts, country=country, city=city, latitude=lat, longitude=lon, user_agent=ua)


def history(days=12, hour=9):
    return [rec(T - timedelta(days=d) + timedelta(hours=hour - 9)) for d in range(days, 0, -1)]


def test_feature_names_are_fixed_and_signed():
    assert len(FEATURE_NAMES) == 7 and len(feature_signature()) == 12
    assert set(compute_features(history(), rec(T))) == set(FEATURE_NAMES)
    assert not any(word in name for name in FEATURE_NAMES for word in ("label", "attack", "anomaly", "rule", "risk"))


def test_known_context_gives_zero_novelty():
    f = compute_features(history(), rec(T))
    assert f["is_new_location"] == 0.0 and f["is_new_device"] == 0.0 and f["hour_deviation"] < 0.01
    assert f["log_distance_km_from_home"] == 0.0 and f["log_travel_speed_kmh"] == 0.0


def test_browser_version_update_is_the_same_device_but_another_browser_is_new():
    """Thiết bị chuẩn hoá giống luật `unusual_device`: Chrome 120 → 121 cùng máy KHÔNG phải thiết bị mới."""
    assert make_record(T, country=None, city=None, latitude=None, longitude=None, user_agent=CHROME_120).device_family == \
        make_record(T, country=None, city=None, latitude=None, longitude=None, user_agent=CHROME_121).device_family
    assert compute_features(history(), rec(T, ua=CHROME_121))["is_new_device"] == 0.0
    assert compute_features(history(), rec(T, ua=FIREFOX))["is_new_device"] == 1.0


def test_new_location_distance_and_travel_speed():
    f = compute_features(history(), rec(T, country="US", city="New York", lat=40.71, lon=-74.01))
    assert f["is_new_location"] == 1.0
    assert 12_000 < math.expm1(f["log_distance_km_from_home"]) < 14_000
    assert 400 < math.expm1(f["log_travel_speed_kmh"]) < 700  # ~13.000 km sau 24 giờ


def test_minutes_since_last_success_and_24h_count():
    prior = history() + [rec(T - timedelta(minutes=300))]
    f = compute_features(prior, rec(T))
    assert abs(math.expm1(f["log_minutes_since_last_success"]) - 300) < 1e-6
    # cửa sổ (t − 24h, t) mở ở đầu cũ: 09:00 hôm qua nằm ĐÚNG biên nên không tính, 04:00 hôm nay được tính
    assert f["logins_last_24h"] == 1.0
    assert compute_features(history(), rec(T - timedelta(seconds=1)))["logins_last_24h"] == 1.0


def test_hour_deviation_is_circular():
    prior = [rec(T - timedelta(days=d) + timedelta(hours=h - 9)) for d, h in zip(range(12, 0, -1), [23, 0, 23.5, 0.5] * 3)]
    assert compute_features(prior, rec(T + timedelta(hours=15)))["hour_deviation"] < 0.5  # 00:00 so với hồ sơ 23:00–00:30
    assert compute_features(prior, rec(T + timedelta(hours=3)))["hour_deviation"] > 11  # 12:00


def test_events_at_or_after_the_current_time_are_ignored():
    """Chống rò rỉ: lịch sử truyền vào có lẫn sự kiện cùng lúc/sau sự kiện hiện tại thì bị bỏ qua."""
    assert compute_features(history() + [rec(T), rec(T + timedelta(hours=1))], rec(T)) == compute_features(history(), rec(T))


def test_scope_requires_a_mature_profile():
    assert in_scope(history(12), rec(T))
    assert not in_scope(history(9), rec(T))  # < 10 lần
    young = [rec(T - timedelta(hours=h)) for h in range(60, 0, -5)]  # 12 lần trong 2,5 ngày
    assert not in_scope(young, rec(T))


def test_missing_geo_and_user_agent_are_neutral():
    f = compute_features(history(), make_record(T, country=None, city=None, latitude=None, longitude=None, user_agent=None))
    assert f["is_new_location"] == 0.0 and f["is_new_device"] == 0.0 and f["log_distance_km_from_home"] == 0.0


def test_feature_vector_order():
    f = compute_features(history(), rec(T))
    assert feature_vector(f) == [f[name] for name in FEATURE_NAMES]
    assert isinstance(rec(T), LoginRecord)
