"""Kiểm tra nhiệm vụ 3.1 — GeoIP wrapper không bao giờ crash."""

from app.detection import geoip


def test_private_ip_returns_none_without_crash():
    assert geoip.lookup_ip("192.168.1.10") is None
    assert geoip.lookup_ip("127.0.0.1") is None
    assert geoip.lookup_ip("10.0.0.5") is None


def test_invalid_ip_returns_none_without_crash():
    assert geoip.lookup_ip("khong-phai-ip") is None


def test_mock_public_ip_returns_plausible_location():
    result = geoip.lookup_ip("8.8.8.8")
    assert result is not None
    assert result.country == "US"


def test_failure_count_increments_on_first_lookup_of_a_new_ip():
    # Dùng IP chưa từng gọi ở test nào khác — nhiệm vụ 5.2 thêm cache TTL,
    # gọi lại CÙNG một IP trong thời gian ngắn KHÔNG tính thêm lần thất bại
    # (xem test_lookup_result_is_cached_for_same_ip bên dưới).
    before = geoip.failure_count
    geoip.lookup_ip("172.16.55.1")
    assert geoip.failure_count == before + 1


def test_lookup_result_is_cached_for_same_ip():
    # Nhiệm vụ 5.2 — cache TTL: gọi lại cùng 1 IP trong cửa sổ cache không
    # tính thêm lần thất bại (không "tra lại" thật sự).
    ip = "172.16.55.2"
    geoip.lookup_ip(ip)
    before = geoip.failure_count
    geoip.lookup_ip(ip)
    assert geoip.failure_count == before  # không tăng thêm — lấy từ cache
