"""Kiểm tra nhiệm vụ 6.1 — resolve_client_ip chỉ tin X-Forwarded-For khi
TRUST_FORWARDED_FOR được bật tường minh (mặc định phải là False)."""

from types import SimpleNamespace

from app.utils.network import resolve_client_ip


class _FakeClient:
    host = "9.9.9.9"


def _fake_request(forwarded_for: str) -> SimpleNamespace:
    return SimpleNamespace(headers={"x-forwarded-for": forwarded_for}, client=_FakeClient())


def test_uses_real_tcp_ip_by_default(monkeypatch):
    monkeypatch.setattr("app.utils.network.get_settings", lambda: SimpleNamespace(trust_forwarded_for=False))
    assert resolve_client_ip(_fake_request("1.2.3.4")) == "9.9.9.9"


def test_trusts_forwarded_header_only_when_enabled(monkeypatch):
    monkeypatch.setattr("app.utils.network.get_settings", lambda: SimpleNamespace(trust_forwarded_for=True))
    assert resolve_client_ip(_fake_request("1.2.3.4, 5.6.7.8")) == "1.2.3.4"


def test_falls_back_to_real_ip_when_header_missing_even_if_enabled(monkeypatch):
    monkeypatch.setattr("app.utils.network.get_settings", lambda: SimpleNamespace(trust_forwarded_for=True))
    request = SimpleNamespace(headers={}, client=_FakeClient())
    assert resolve_client_ip(request) == "9.9.9.9"
