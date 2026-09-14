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


def test_failure_count_increments_and_is_countable():
    before = geoip.failure_count
    geoip.lookup_ip("127.0.0.1")
    assert geoip.failure_count == before + 1
