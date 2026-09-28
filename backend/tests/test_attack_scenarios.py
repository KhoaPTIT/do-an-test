"""MR18 — kiểm chứng THUẦN (không đụng DB/pipeline) rằng mỗi ScenarioSpec thực sự vượt đúng ngưỡng luật nó nhắm tới —
đối chiếu TRỰC TIẾP với REGISTRY (không hard-code lại số, tự lệch nếu ai đó đổi ngưỡng mặc định của luật mà quên cập
nhật kịch bản). Hành vi "có phát hiện được thật không qua pipeline thật" đo ở scripts/attack_scenario_runner.py
(không chạy trong pytest — cùng lý do scripts/alert_intelligence_sim.py không chạy trong pytest, xem docstring ở đó)."""

import random

import pytest

from app.detection.engine.registry import REGISTRY
from ml.attack_scenarios import BUILDERS, all_scenarios


def _param(rule_id, name):
    return next(p.default for p in REGISTRY[rule_id].params if p.name == name)


@pytest.fixture()
def rng():
    return random.Random(0)


@pytest.fixture()
def specs(rng):
    return {s.id: s for s in all_scenarios(rng)}


def test_every_builder_produces_a_unique_id_with_at_least_one_attack_step(rng):
    built = [b(rng) for b in BUILDERS]
    ids = [s.id for s in built]
    assert len(ids) == len(set(ids)) == 9
    for s in built:
        assert len(s.attack_attempts) >= 1


def test_slow_password_spray_beats_its_own_rule_but_not_credential_stuffing(specs):
    s = specs["slow_password_spray"]
    attempts = s.attack_attempts
    distinct_users = {a.username for a in attempts}
    ips = {a.ip for a in attempts}
    assert len(ips) == 1  # 1 IP duy nhất, đúng "rải" chứ không phải botnet
    assert len(distinct_users) >= _param("password_spray_slow", "min_users")
    span = max(a.offset_s for a in attempts) - min(a.offset_s for a in attempts)
    assert span <= _param("password_spray_slow", "window_s")
    fails_per_user = sum(1 for a in attempts if not a.success) / len(distinct_users)
    assert fails_per_user <= _param("password_spray_slow", "max_fails_per_user")
    # KHÔNG được chạm ngưỡng credential_stuffing (min_fails trong MỘT cửa sổ window_s ngắn hơn nhiều) — mọi cửa sổ
    # 300 giây (mặc định) chỉ có thể chứa TỐI ĐA 1 lần thử vì các lần cách nhau > 300 giây.
    min_gap = min(b.offset_s - a.offset_s for a, b in zip(attempts, attempts[1:]))
    assert min_gap > _param("credential_stuffing", "window_s")


def test_distributed_botnet_beats_its_own_rule(specs):
    s = specs["distributed_botnet"]
    attempts = s.attack_attempts
    assert len({a.username for a in attempts}) == 1  # MỘT tài khoản bị nhắm
    ips = {a.ip for a in attempts}
    assert len(ips) >= _param("distributed_bruteforce", "min_ips")
    assert sum(1 for a in attempts if not a.success) >= _param("distributed_bruteforce", "min_fails")
    span = max(a.offset_s for a in attempts) - min(a.offset_s for a in attempts)
    assert span <= _param("distributed_bruteforce", "window_s")


def test_same_country_proxy_uses_a_different_ip_and_asn_but_the_same_country_as_home(specs):
    from app.detection.geoip import lookup_asn, lookup_ip

    s = specs["same_country_proxy"]
    baseline_ip = next(a.ip for a in s.attempts if not a.is_attack_step)
    attack_ip = s.attack_attempts[0].ip
    assert baseline_ip != attack_ip

    home_geo, proxy_geo = lookup_ip(baseline_ip), lookup_ip(attack_ip)
    home_asn, proxy_asn = lookup_asn(baseline_ip), lookup_asn(attack_ip)
    assert home_geo.country == proxy_geo.country  # CÙNG nước
    assert home_asn.asn != proxy_asn.asn  # KHÁC nhà mạng — mới/hiếm so với lịch sử


def test_ua_rotation_beats_its_own_rule(specs):
    s = specs["ua_rotation"]
    attempts = s.attack_attempts
    assert len({a.username for a in attempts}) == 1
    assert len({a.ip for a in attempts}) == 1
    assert len({a.user_agent for a in attempts}) >= _param("ua_rotation", "min_distinct_ua")
    assert sum(1 for a in attempts if not a.success) >= _param("ua_rotation", "min_fails")
    span = max(a.offset_s for a in attempts) - min(a.offset_s for a in attempts)
    assert span <= _param("ua_rotation", "window_s")


def test_dormant_account_reactivation_is_dormant_long_enough_and_changes_country(specs):
    from app.detection.geoip import lookup_ip

    s = specs["dormant_account_reactivation"]
    baseline = [a for a in s.attempts if not a.is_attack_step]
    attack = s.attack_attempts
    assert len(attack) == 1 and attack[0].success is True
    gap_days = (attack[0].offset_s - baseline[-1].offset_s) / 86400
    assert gap_days >= _param("dormant_account_login", "dormant_days")
    assert lookup_ip(baseline[-1].ip).country != lookup_ip(attack[0].ip).country


def test_targeted_mimic_is_explicitly_marked_as_not_necessarily_detectable(specs):
    s = specs["targeted_mimic"]
    assert s.expect_detectable is False
    assert s.rule_hint == "hybrid_ml"  # không phải một luật enforce cụ thể


def test_account_enumeration_beats_its_own_rule_with_nonexistent_usernames_only(specs):
    s = specs["account_enumeration"]
    attempts = s.attack_attempts
    distinct = {a.username for a in attempts}
    assert len(distinct) >= _param("username_enumeration", "min_usernames")
    assert distinct.isdisjoint(s.victim_usernames)  # đều KHÔNG tồn tại — không trùng tài khoản có thật nào
    assert all(not a.success for a in attempts)
    span = max(a.offset_s for a in attempts) - min(a.offset_s for a in attempts)
    assert span <= _param("username_enumeration", "window_s")


def test_large_scale_credential_stuffing_beats_its_own_rule(specs):
    s = specs["large_scale_credential_stuffing"]
    attempts = s.attack_attempts
    assert len({a.username for a in attempts}) >= _param("credential_stuffing", "min_users")
    assert sum(1 for a in attempts if not a.success) >= _param("credential_stuffing", "min_fails")
    span = max(a.offset_s for a in attempts) - min(a.offset_s for a in attempts)
    assert span <= _param("credential_stuffing", "window_s")
    assert all(a.username in s.victim_usernames for a in attempts)  # nhắm tài khoản CÓ THẬT (khác account_enumeration)


def test_impossible_travel_two_real_distant_ips_within_a_short_window(specs):
    from app.detection.rules import haversine_distance
    from app.detection.geoip import lookup_ip

    s = specs["impossible_travel"]
    attempts = s.attack_attempts
    assert len(attempts) == 2 and all(a.success for a in attempts)
    geo_a, geo_b = lookup_ip(attempts[0].ip), lookup_ip(attempts[1].ip)
    distance_km = haversine_distance(geo_a.latitude, geo_a.longitude, geo_b.latitude, geo_b.longitude)
    elapsed_h = (attempts[1].offset_s - attempts[0].offset_s) / 3600
    speed_kmh = distance_km / elapsed_h
    assert speed_kmh > _param("impossible_travel", "max_speed_kmh") * 5  # vượt xa, không sát ngưỡng
