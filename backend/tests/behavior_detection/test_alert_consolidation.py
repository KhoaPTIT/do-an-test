"""Milestone B — B0: xử lý nhiễu cảnh báo. Một chuỗi sự kiện = MỘT cảnh báo chiến dịch; detector đặc hiệu nhất làm chính,
các tín hiệu khác vào `secondary_signals` (không mất bằng chứng). Luật chưa kiểm chứng không tự tạo cảnh báo."""

import dataclasses
from datetime import timedelta

import pytest

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import JP_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA, CURL_UA, FIREFOX_UA, PY_REQUESTS_UA, SAFARI_UA, EDGE_UA, MOBILE_UA


@pytest.fixture()
def scripted_verified(monkeypatch):
    """Giả lập trạng thái SAU khi scripted_client đã qua kiểm chứng (được tự tạo cảnh báo) — để chứng minh việc gộp
    chiến dịch vẫn giữ MỘT cảnh báo ngay cả khi tín hiệu phụ đủ tư cách tự báo."""
    monkeypatch.setitem(REGISTRY, "scripted_client", dataclasses.replace(REGISTRY["scripted_client"], verification="verified"))


def _victims(env, n, prefix="sp"):
    names = [f"{prefix}_{i:02d}" for i in range(n)]
    for name in names:
        seed_user(env, name, days=3)
    return names


def _spray(env, names, *, ip=US_IP, gap_min=25, user_agent=PY_REQUESTS_UA, start=T0):
    for i, name in enumerate(names):
        env.login(name, success=False, ip=ip, ts=start + timedelta(minutes=i * gap_min), user_agent=user_agent)


def test_password_spray_with_scripted_client_is_one_campaign_alert(env, scripted_verified):
    _spray(env, _victims(env, 18))

    alerts = env.detection_alerts()
    assert len(alerts) == 1, [a.rule_id for a in alerts]  # trước B0: 14 cảnh báo scripted_client + cảnh báo rải mật khẩu
    exp = alerts[0].explanation
    assert alerts[0].rule_id == "password_spray_slow" and exp["primary_detector"] == "password_spray_slow"
    assert "scripted_client" in exp["secondary_signals"]
    assert exp["superseded_detectors"] == ["scripted_client"]  # cảnh báo mở bởi tín hiệu phụ, detector đặc hiệu tiếp quản
    assert alerts[0].occurrence_count == 18  # mọi lần thử của chiến dịch được đếm, không bị bỏ


def test_password_spray_with_an_unverified_scripted_client_never_alerts_on_the_marker(env):
    assert not REGISTRY["scripted_client"].is_verified
    _spray(env, _victims(env, 18))

    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == ["password_spray_slow"]
    assert "scripted_client" in alerts[0].explanation["secondary_signals"]


def test_username_enumeration_then_credential_stuffing_is_one_alert_led_by_stuffing(env):
    for i in range(12):
        env.login(f"leaked_{i}", success=False, ip=US_IP, ts=T0 + timedelta(seconds=i * 20))

    alerts = env.detection_alerts()
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert alerts[0].rule_id == "credential_stuffing"
    assert exp["superseded_detectors"] == ["username_enumeration"] and "username_enumeration" in exp["secondary_signals"]


def test_two_sources_spraying_at_the_same_time_stay_two_campaigns(env):
    names = _victims(env, 16)
    _spray(env, names, ip=US_IP, user_agent=CHROME_UA)
    _spray(env, names, ip=JP_IP, user_agent=CHROME_UA, start=T0 + timedelta(minutes=3))

    alerts = env.detector_alerts("password_spray_slow")
    assert len(alerts) == 2
    assert {a.explanation["evidence"]["ip"] for a in alerts} == {US_IP, JP_IP}


def test_unrelated_behaviors_on_the_same_account_are_not_merged(env):
    # tài khoản ngủ đông đăng nhập lại (ngữ cảnh) rồi 2 giờ sau bị brute force (đoán mật khẩu): hai chuỗi khác nhau.
    seed_user(env, "victim", days=5, end=T0 - timedelta(days=150) + timedelta(days=1))
    env.login("victim", success=True, ip=JP_IP, ts=T0, user_agent=SAFARI_UA)
    for i in range(5):
        env.login("victim", success=False, ip=US_IP, ts=T0 + timedelta(hours=2, seconds=i * 20))

    assert sorted(a.rule_id for a in env.detection_alerts()) == ["brute_force", "dormant_account_login"]


def test_marker_alerts_far_apart_in_time_are_separate_campaigns(env, scripted_verified):
    seed_user(env, "a")
    env.login("a", success=True, ip=US_IP, ts=T0, user_agent=CURL_UA)
    env.login("a", success=True, ip=US_IP, ts=T0 + timedelta(minutes=30), user_agent=CURL_UA)  # trong 1 giờ: gộp
    env.login("a", success=True, ip=US_IP, ts=T0 + timedelta(hours=3), user_agent=CURL_UA)  # quá cửa sổ trượt: chiến dịch mới

    alerts = env.detector_alerts("scripted_client")
    assert [a.occurrence_count for a in alerts] == [2, 1]


def test_an_unverified_enforce_rule_alone_is_recorded_but_does_not_alert(env, monkeypatch):
    # Cơ chế B0.1 (độc lập với trạng thái registry hiện tại): một luật enforce ở trạng thái experimental khớp -> ghi
    # matched_rules, KHÔNG có cảnh báo riêng. Dùng ua_rotation làm ví dụ và ép nó về experimental.
    monkeypatch.setitem(REGISTRY, "ua_rotation", dataclasses.replace(REGISTRY["ua_rotation"], verification="experimental", default_mode="enforce"))
    names = _victims(env, 2, prefix="rot")
    agents = (CHROME_UA, FIREFOX_UA, SAFARI_UA, EDGE_UA, MOBILE_UA)
    for i in range(9):
        env.login(names[i % 2], success=False, ip=US_IP, ts=T0 + timedelta(seconds=i * 70), user_agent=agents[i % 5])

    assert any("ua_rotation" in v.matched_rules for v in env.verdicts)
    assert any("ua_rotation" in v.experimental_rules for v in env.verdicts)
    assert env.detector_alerts("ua_rotation") == []


def test_missing_user_agent_is_a_telemetry_gap_not_a_scripted_client(env):
    seed_user(env, "victim")
    for i in range(6):
        env.login("victim", success=False, ip=US_IP, ts=T0 + timedelta(seconds=i * 20), user_agent=None)

    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == ["brute_force"]
    exp = alerts[0].explanation
    assert "scripted_client" not in exp["matched_rules"]
    assert exp["telemetry_gaps"] == ["missing_user_agent"]


def test_registry_verified_status_matches_committed_verification_evidence():
    """`verification="verified"` trên một luật PHẢI có bằng chứng runner tự sinh với trạng thái VERIFIED — không ai được
    nâng trạng thái trong registry mà không qua kiểm chứng (và ngược lại, bằng chứng VERIFIED nào cũng phải phản ánh ở registry)."""
    import json
    from pathlib import Path

    evidence_dir = Path(__file__).resolve().parents[3] / "artifacts" / "behavior_verification"
    verified_by_evidence = set()
    for path in evidence_dir.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("detector") in REGISTRY and data.get("status") == "VERIFIED":
            verified_by_evidence.add(data["detector"])
    verified_in_registry = {rule_id for rule_id, spec in REGISTRY.items() if spec.is_verified}
    assert verified_in_registry == verified_by_evidence
