"""scripted_client — đăng nhập bằng User-Agent của một công cụ HTTP/dò quét ĐÃ BIẾT (python-requests, curl, wget, HTTPie...).
Tín hiệu tự động hoá YẾU (mức low). UA trống KHÔNG phải client kịch bản (B0.2); okhttp (ứng dụng Android) không bị coi là kịch bản.
Khi một hành vi tấn công cụ thể cùng khớp, hành vi đó làm detector chính."""

from datetime import timedelta

import pytest

from tests.behavior_detection.conftest import HOME_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA, EDGE_UA, FIREFOX_UA, MOBILE_UA, SAFARI_UA
from verification.scenarios import SCRIPTED_TOOL_UAS

RULE = "scripted_client"


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


@pytest.mark.parametrize("ua", ["python-requests/2.31.0", "curl/8.7.1", "Wget/1.21.4", "HTTPie/3.2.2"])
def test_positive_known_tool_user_agents(env, ua):
    seed_user(env, "alice")
    env.login("alice", success=True, ip=US_IP, ts=T0, user_agent=ua)
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "scripted_client"
    assert alerts[0].severity == "low" and exp["action"] == "allow"


@pytest.mark.parametrize("ua", [CHROME_UA, FIREFOX_UA, EDGE_UA, SAFARI_UA, MOBILE_UA, "okhttp/4.12.0", None, "", "   "])
def test_negative_browsers_android_app_and_missing_user_agent(env, ua):
    seed_user(env, "alice")
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=ua)
    assert env.detector_alerts(RULE) == []
    if not (ua or "").strip():
        assert all("scripted_client" not in v.matched_rules for v in env.verdicts)


def test_boundary_marker_must_be_a_known_tool_not_a_lookalike(env):
    seed_user(env, "alice")
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent="MyCurlyBrowser/1.0 (Windows NT 10.0)")  # chứa "curl" nhưng không phải "curl/"
    assert env.detector_alerts(RULE) == []
    env.login("alice", success=True, ip=HOME_IP, ts=T0 + timedelta(hours=2), user_agent="curl/7.88.1")
    assert len(env.detector_alerts(RULE)) == 1


def test_repeated_tool_logins_from_one_source_are_one_campaign_alert(env):
    seed_user(env, "alice")
    for j in range(5):
        env.login("alice", success=True, ip=US_IP, ts=T0 + timedelta(minutes=j * 10), user_agent=SCRIPTED_TOOL_UAS[0])
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and alerts[0].occurrence_count == 5


@pytest.mark.parametrize("attack", ["brute_force", "credential_stuffing"])
def test_attribution_specific_attack_wins_and_scripted_client_is_secondary(env, attack):
    if attack == "brute_force":
        seed_user(env, "victim")
        for j in range(6):
            env.login("victim", success=False, ip=US_IP, ts=T0 + timedelta(seconds=j * 20), user_agent="python-requests/2.31.0")
    else:
        names = [f"kh{i}" for i in range(6)]
        for name in names:
            seed_user(env, name, days=2)
        for j in range(12):
            env.login(names[j % 6], success=False, ip=US_IP, ts=T0 + timedelta(seconds=j * 15), user_agent="python-requests/2.31.0")
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == [attack]  # MỘT cảnh báo chiến dịch, không có scripted_client riêng lẻ
    assert "scripted_client" in alerts[0].explanation["secondary_signals"]
