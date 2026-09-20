"""MR1 — lookup_asn(): không bao giờ raise, thiếu DB thì trả None/mock."""

import geoip2.errors
import pytest

from app.detection import geoip


@pytest.fixture()
def asn_mock_mode(monkeypatch):
    """Ép chế độ mock (chưa có file GeoLite2-ASN.mmdb) bất kể máy đang có file hay không."""
    monkeypatch.setattr(geoip, "_asn_reader", None)
    monkeypatch.setattr(geoip, "_asn_reader_loaded", True)
    monkeypatch.setattr(geoip, "_asn_cache", {})


class _FakeResponse:
    def __init__(self, asn, organization):
        self.autonomous_system_number = asn
        self.autonomous_system_organization = organization


class _FakeReader:
    def __init__(self, behaviour):
        self._behaviour = behaviour

    def asn(self, ip):
        if isinstance(self._behaviour, Exception):
            raise self._behaviour
        return self._behaviour


def _use_reader(monkeypatch, behaviour):
    monkeypatch.setattr(geoip, "_asn_reader", _FakeReader(behaviour))
    monkeypatch.setattr(geoip, "_asn_reader_loaded", True)
    monkeypatch.setattr(geoip, "_asn_cache", {})


def test_private_and_invalid_ip_return_none(asn_mock_mode):
    assert geoip.lookup_asn("192.168.1.10") is None
    assert geoip.lookup_asn("127.0.0.1") is None
    assert geoip.lookup_asn("khong-phai-ip") is None


def test_mock_mode_knows_a_few_public_ips_and_none_else(asn_mock_mode):
    result = geoip.lookup_asn("8.8.8.8")
    assert result is not None and result.asn == 15169
    assert geoip.lookup_asn("203.119.101.100") is None


def test_real_reader_result_is_mapped(monkeypatch):
    _use_reader(monkeypatch, _FakeResponse(60117, "Some Hosting Ltd"))
    result = geoip.lookup_asn("194.87.207.6")
    assert result == geoip.AsnResult(asn=60117, organization="Some Hosting Ltd")


def test_ip_not_in_database_returns_none(monkeypatch):
    _use_reader(monkeypatch, geoip2.errors.AddressNotFoundError("khong co"))
    assert geoip.lookup_asn("194.87.207.7") is None


def test_unexpected_reader_error_is_swallowed(monkeypatch):
    _use_reader(monkeypatch, RuntimeError("file hong"))
    assert geoip.lookup_asn("194.87.207.8") is None


def test_result_is_cached_for_same_ip(monkeypatch, asn_mock_mode):
    calls = []

    def counting_lookup(ip):
        calls.append(ip)
        return geoip.AsnResult(64500, None)

    monkeypatch.setattr(geoip, "_lookup_asn_uncached", counting_lookup)
    geoip.lookup_asn("194.87.207.9")
    geoip.lookup_asn("194.87.207.9")
    assert calls == ["194.87.207.9"]
