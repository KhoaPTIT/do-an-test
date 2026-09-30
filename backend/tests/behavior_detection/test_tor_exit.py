"""tor_exit — đăng nhập từ IP nằm trong danh sách Tor exit node.

Danh sách dùng ở đây là TEST FIXTURE (`verification/fixtures/threat_intel/`, dải tài liệu RFC 5737) — chứng minh luật +
pipeline + attribution hoạt động đúng KHI có danh sách; KHÔNG phải bằng chứng về độ phủ của danh sách Tor thật. Luật
không chứa IP nào: nó chỉ tra danh sách đã nạp."""

from datetime import timedelta

import pytest

from app.detection.engine.intel import ThreatIntel
from tests.behavior_detection.conftest import HOME_IP, T0, TOR_IP, TOR_NEIGHBOUR_IP, seed_user
from verification.fixtures import THREAT_INTEL_FIXTURE_DIR
from verification.harness import PY_REQUESTS_UA

RULE = "tor_exit"
LAST_LISTED_IP, FIRST_UNLISTED_IP = "198.51.100.40", "198.51.100.41"  # biên của danh sách fixture (.1–.40)


def test_positive_successful_login_from_a_tor_exit_node(env):
    seed_user(env, "alice")
    env.login("alice", success=True, ip=TOR_IP, ts=T0)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "tor_login"
    assert exp["evidence"] == {"ip": TOR_IP, "list": "tor"}
    assert alerts[0].severity == "medium" and exp["action"] == "allow"


def test_positive_failed_login_for_an_unknown_username_from_tor(env):
    env.login("ai_do", success=False, ip=TOR_IP, ts=T0)
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and alerts[0].user_id is None


def test_negative_same_hosting_range_but_not_a_listed_exit_node(env):
    seed_user(env, "alice")
    env.login("alice", success=True, ip=TOR_NEIGHBOUR_IP, ts=T0)
    env.login("alice", success=True, ip=HOME_IP, ts=T0 + timedelta(hours=8))
    assert env.detector_alerts(RULE) == []


def test_boundary_last_listed_address_and_first_unlisted_address(env):
    seed_user(env, "a")
    seed_user(env, "b")
    env.login("a", success=True, ip=LAST_LISTED_IP, ts=T0)
    env.login("b", success=True, ip=FIRST_UNLISTED_IP, ts=T0)

    alerts = env.detector_alerts(RULE)
    assert [a.user_id for a in alerts] == [env.user_id("a")]


def test_without_a_loaded_list_the_rule_is_skipped_not_guessed(env, monkeypatch):
    import app.detection.rule_engine_runtime as runtime_module

    monkeypatch.setattr(runtime_module, "_THREAT_INTEL", ThreatIntel())  # không nạp danh sách nào
    seed_user(env, "alice")
    env.login("alice", success=True, ip=TOR_IP, ts=T0)
    assert env.detector_alerts(RULE) == []


def test_attribution_scripted_client_through_tor_keeps_tor_as_primary(env):
    env.login("ai_do", success=False, ip=TOR_IP, ts=T0, user_agent=PY_REQUESTS_UA)
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    assert "scripted_client" in alerts[0].explanation["matched_rules"]


def test_attribution_brute_force_through_tor_is_attributed_to_brute_force(env):
    # Tor là DẤU HIỆU hạ tầng; khi một HÀNH VI (dò mật khẩu) khớp cùng lúc, detector chính là hành vi — tor vẫn ghi ở matched_rules.
    seed_user(env, "alice")
    for i in range(5):
        env.login("alice", success=False, ip=TOR_IP, ts=T0 + timedelta(seconds=i * 20))

    brute = env.detector_alerts("brute_force")
    assert len(brute) == 1 and "tor_exit" in brute[0].explanation["matched_rules"]


# ------------------------------------------------------------------------------------------ nạp dữ liệu runtime/demo/fixture


def test_fixture_directory_is_labelled_as_fixture():
    status = ThreatIntel.load(THREAT_INTEL_FIXTURE_DIR).status()
    assert status["data_kind"] == "fixture" and status["loaded"]["tor"] is True


def test_demo_directory_is_labelled_as_demo_and_loaded_from_config(monkeypatch):
    import app.detection.rule_engine_runtime as runtime_module
    from app.config import get_settings

    monkeypatch.setenv("THREAT_INTEL_DIR", "threat_intel_demo")
    get_settings.cache_clear()
    try:
        intel = runtime_module.load_threat_intel_at_startup()
    finally:
        get_settings.cache_clear()
        monkeypatch.setattr(runtime_module, "_THREAT_INTEL", None)
    status = intel.status()
    assert status["data_kind"] == "demo"
    assert status["source_dir"].endswith("threat_intel_demo")
    assert status["entries"]["tor"] > 0


@pytest.mark.parametrize("missing", ["khong_ton_tai_thu_muc"])
def test_missing_directory_loads_nothing(tmp_path, missing):
    status = ThreatIntel.load(tmp_path / missing).status()
    assert status["data_kind"] == "none" and not any(status["loaded"].values())
