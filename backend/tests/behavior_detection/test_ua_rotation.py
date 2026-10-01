"""ua_rotation — một IP thất bại nhiều lần với nhiều HỌ User-Agent khác nhau trong thời gian ngắn, gần như không có lần
thành công (ngưỡng mặc định: `min_fails`=8, `min_distinct_ua`=5 họ chuẩn hoá, `window_s`=600s, tỉ lệ thành công ≤ 0,2).

Là tín hiệu ĐÁNH DẤU (tự động hoá): khi nhồi thông tin/brute force cũng khớp, hành vi đó làm detector chính."""

from datetime import timedelta

import pytest

from tests.behavior_detection.conftest import HOME_IP, MOBILE_IP, OFFICE_NAT_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA, FIREFOX_UA, MOBILE_UA
from verification.scenarios import ROTATION_UAS, chrome_version_ua

RULE = "ua_rotation"


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def _rotate(env, names, n, families, *, gap_s=60, ip=US_IP, agents=ROTATION_UAS, start=T0):
    for j in range(n):
        env.login(names[j % len(names)], success=False, ip=ip, ts=start + timedelta(seconds=j * gap_s), user_agent=agents[j % families])


def test_positive_rotating_agents_against_two_accounts(env):
    for name in ("a", "b"):
        seed_user(env, name)
    _rotate(env, ["a", "b"], 9, 6)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "user_agent_rotation"
    assert exp["evidence"]["distinct_user_agents"] >= 5 and exp["evidence"]["canonical"] is True
    assert exp["action"] == "allow"


def test_negative_chrome_to_firefox_and_laptop_to_mobile(env):
    seed_user(env, "owner")
    env.login("owner", success=False, ip=HOME_IP, ts=T0, user_agent=CHROME_UA)
    env.login("owner", success=False, ip=HOME_IP, ts=T0 + timedelta(seconds=40), user_agent=FIREFOX_UA)
    env.login("owner", success=False, ip=MOBILE_IP, ts=T0 + timedelta(seconds=90), user_agent=MOBILE_UA)
    env.login("owner", success=True, ip=MOBILE_IP, ts=T0 + timedelta(seconds=120), user_agent=MOBILE_UA)
    assert env.detector_alerts(RULE) == []


def test_negative_browser_version_updates_are_one_family(env):
    for name in ("a", "b"):
        seed_user(env, name)
    _rotate(env, ["a", "b"], 10, 10, agents=[chrome_version_ua(115 + j) for j in range(10)])
    assert env.detector_alerts(RULE) == []


def test_negative_shared_nat_with_many_browsers_mostly_succeeding(env):
    for k in range(10):
        name, ua = f"nv{k}", ROTATION_UAS[k]
        seed_user(env, name, ip=OFFICE_NAT_IP, user_agent=ua)
        env.login(name, success=False, ip=OFFICE_NAT_IP, ts=T0 + timedelta(seconds=k * 40), user_agent=ua)
        env.login(name, success=True, ip=OFFICE_NAT_IP, ts=T0 + timedelta(seconds=k * 40 + 15), user_agent=ua)
    assert env.detector_alerts(RULE) == []


def test_boundary_families_and_failures(env):
    for name in ("a", "b", "c", "d", "e", "f"):
        seed_user(env, name)
    _rotate(env, ["a", "b"], 10, 4)  # 10 lần sai, 4 họ (ngưỡng − 1)
    assert env.detector_alerts(RULE) == []
    _rotate(env, ["c", "d"], 7, 7, ip="198.51.100.210", start=T0 + timedelta(hours=2))  # 7 lần sai (ngưỡng − 1), 7 họ
    assert env.detector_alerts(RULE) == []
    _rotate(env, ["e", "f"], 8, 5, ip="198.51.100.220", start=T0 + timedelta(hours=4))  # đúng ngưỡng: 8 lần sai, 5 họ
    assert len(env.detector_alerts(RULE)) == 1


def test_attribution_rotation_inside_credential_stuffing_is_a_secondary_signal(env):
    names = [f"kh{i}" for i in range(6)]
    for name in names:
        seed_user(env, name, days=2)
    _rotate(env, names, 12, 6, gap_s=15)  # nhanh, 6 tài khoản: nhồi thông tin (đặc hiệu hơn) làm detector chính
    stuffing = env.detector_alerts("credential_stuffing")
    assert len(stuffing) == 1 and "ua_rotation" in stuffing[0].explanation["secondary_signals"]
    assert env.detector_alerts(RULE) == []
