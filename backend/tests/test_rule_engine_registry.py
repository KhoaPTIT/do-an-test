"""MR9 — sổ đăng ký luật: siêu dữ liệu đầy đủ, kiểm tra khai báo, ép kiểu tham số, cấu hình bật/tắt/shadow."""

import json

import pytest

from app.detection.engine import REGISTRY, ConfigError, Finding, Param, RuleConfig
from app.detection.engine.registry import CATEGORIES, NEEDS, TECHNIQUES, rule


def declare(registry, **overrides):
    """Đăng ký một luật thử vào sổ riêng (không đụng REGISTRY thật)."""
    fields = dict(id="r", title="t", category=CATEGORIES[0], severity="low", description="d", registry=registry)
    fields.update(overrides)
    return rule(**fields)(lambda ctx: None)


# ------------------------------------------------------------------------------------------------ sổ thật


def test_registry_has_at_least_twelve_rules_with_complete_metadata():
    assert len(REGISTRY) >= 12
    for spec in REGISTRY.values():
        assert spec.title and spec.description and spec.category in CATEGORIES and spec.severity in ("low", "medium", "high"), spec.id
        assert spec.default_mode in ("enforce", "shadow", "off") and callable(spec.evaluate), spec.id
        assert set(spec.techniques) <= set(TECHNIQUES) and set(spec.needs) <= set(NEEDS), spec.id
        for param in spec.params:
            assert param.description and param.coerce(param.default) == param.default, (spec.id, param.name)
    assert {s.category for s in REGISTRY.values()} == set(CATEGORIES)  # mọi nhóm đều có luật


def test_registry_covers_the_rules_required_by_the_plan():
    required = {
        "brute_force", "credential_stuffing", "impossible_travel",  # ba luật tầng 1 gốc, giữ nguyên mã
        "password_spray_slow", "distributed_bruteforce", "username_enumeration",  # đoán mật khẩu
        "bot_user_agent", "scripted_client", "ua_rotation", "regular_rhythm",  # tự động hoá
        "tor_exit", "datacenter_ip", "vpn_ip", "blocklist_hit",  # hạ tầng
        "dormant_account_login", "multi_context_simultaneous", "country_hop", "rare_network_login",  # ngữ cảnh (rare_network_login: quyết định D3)
    }
    assert required <= set(REGISTRY)


def test_mitre_mapping_uses_the_techniques_named_in_the_plan():
    used = {t for spec in REGISTRY.values() for t in spec.techniques}
    assert {"T1110.001", "T1110.003", "T1110.004", "T1078", "T1090"} <= used
    assert REGISTRY["password_spray_slow"].techniques == ("T1110.003",) and REGISTRY["credential_stuffing"].techniques == ("T1110.004",)
    assert REGISTRY["tor_exit"].techniques == ("T1090.003",) and "T1078" in REGISTRY["dormant_account_login"].techniques


def test_unvalidated_or_noisy_rules_start_in_shadow_mode():
    shadow = {s.id for s in REGISTRY.values() if s.default_mode == "shadow"}
    # country_hop (Milestone B) và regular_rhythm (Milestone C+) rời nhóm này (shadow -> enforce) SAU khi qua kiểm chứng hành
    # vi — xem artifacts/behavior_verification/<luật>.json và test_registry_verified_status_matches_committed_verification_evidence.
    assert {"datacenter_ip", "vpn_ip", "rare_network_login"} <= shadow
    assert {"brute_force", "credential_stuffing", "impossible_travel", "blocklist_hit"}.isdisjoint(shadow)


def test_original_tier1_thresholds_are_preserved_as_defaults():
    from app.detection import rules as legacy

    # Milestone C: thêm `max_success_ratio` (thay đổi thiết kế có chủ ý — báo nhầm trên tài khoản dùng chung kiểu kiosk);
    # hai ngưỡng gốc của tầng 1 vẫn giữ nguyên.
    assert REGISTRY["brute_force"].defaults() == {"threshold": legacy.BRUTE_FORCE_THRESHOLD, "window_s": 300, "max_success_ratio": 0.2}
    stuffing = REGISTRY["credential_stuffing"].defaults()
    assert stuffing["min_fails"] == legacy.CREDENTIAL_STUFFING_FAIL_THRESHOLD and stuffing["min_users"] == legacy.CREDENTIAL_STUFFING_MIN_DISTINCT_USERNAMES
    assert REGISTRY["impossible_travel"].defaults() == {"max_speed_kmh": legacy.IMPOSSIBLE_TRAVEL_SPEED_KMH}


# ------------------------------------------------------------------------------------------------ khai báo luật


def test_declaring_a_rule_validates_its_metadata():
    ok = {}
    declare(ok, id="ok", techniques=("T1110.001",), needs=("asn",), params=(Param("x", 3, "mô tả", "lần", 1, 10),))
    assert ok["ok"].defaults() == {"x": 3}
    with pytest.raises(ValueError, match="trùng mã"):
        declare(ok, id="ok")
    for bad in (dict(severity="critical"), dict(default_mode="maybe"), dict(category="Khác"), dict(techniques=("T9999",)), dict(needs=("magic",))):
        with pytest.raises(ValueError):
            declare({}, **bad)
    with pytest.raises(ValueError, match="tên tham số bị trùng"):
        declare({}, params=(Param("x", 1, "a"), Param("x", 2, "b")))
    with pytest.raises(ConfigError):
        declare({}, params=(Param("x", 50, "mặc định ngoài khoảng", "", 1, 10),))  # giá trị mặc định phải hợp lệ với chính khai báo


# ------------------------------------------------------------------------------------------------ ép kiểu tham số


def test_param_coerces_and_checks_bounds():
    integer, number = Param("n", 5, "d", "", 1, 10), Param("f", 0.5, "d", "", 0.0, 1.0)
    assert integer.coerce(7) == 7 and integer.coerce(7.0) == 7 and isinstance(integer.coerce(7.0), int)
    assert number.coerce(1) == 1.0 and isinstance(number.coerce(1), float)
    for bad in (7.5, "7", True, None):
        with pytest.raises(ConfigError):
            integer.coerce(bad)
    for bad in ("0.5", True, None):
        with pytest.raises(ConfigError):
            number.coerce(bad)
    with pytest.raises(ConfigError, match="nhỏ hơn"):
        integer.coerce(0)
    with pytest.raises(ConfigError, match="lớn hơn"):
        number.coerce(1.5)


def test_param_coerces_flags_strings_and_lists():
    assert Param("b", True, "d").coerce(False) is False
    for bad in (1, "true", None):
        with pytest.raises(ConfigError):
            Param("b", True, "d").coerce(bad)
    assert Param("s", "x", "d").coerce("y") == "y"
    with pytest.raises(ConfigError):
        Param("s", "x", "d").coerce(3)
    markers = Param("m", ("a", "b"), "d")
    assert markers.coerce(["curl/", "wget/"]) == ("curl/", "wget/")
    for bad in ("curl/", ["curl/", 3], 5):
        with pytest.raises(ConfigError):
            markers.coerce(bad)


# ------------------------------------------------------------------------------------------------ cấu hình


def test_config_overrides_modes_and_parameters_and_leaves_the_rest_default():
    config = RuleConfig.from_dict({"rules": {"brute_force": {"mode": "shadow", "params": {"threshold": 8.0}}, "vpn_ip": {"mode": "off"}}})
    brute, vpn, spray = REGISTRY["brute_force"], REGISTRY["vpn_ip"], REGISTRY["password_spray_slow"]
    assert config.mode_of(brute) == "shadow" and config.mode_of(vpn) == "off" and config.mode_of(spray) == spray.default_mode
    params = config.resolved_params(brute)
    assert params.threshold == 8 and isinstance(params.threshold, int) and params.window_s == 300  # tham số không nêu giữ mặc định
    assert config.resolved_params(spray).min_users == spray.defaults()["min_users"]


def test_config_rejects_unknown_rules_parameters_modes_and_values():
    bad_configs = [
        {"rules": {"khong_co": {}}},
        {"rules": {"brute_force": {"mode": "loud"}}},
        {"rules": {"brute_force": {"params": {"nguong": 3}}}},
        {"rules": {"brute_force": {"params": {"threshold": 0}}}},  # dưới mức tối thiểu
        {"rules": {"brute_force": {"threshold": 3}}},  # sai cấu trúc: thiếu lớp 'params'
        {"luat": {}},
        [],
    ]
    for data in bad_configs:
        with pytest.raises(ConfigError):
            RuleConfig.from_dict(data)


def test_config_round_trips_through_a_json_file(tmp_path):
    original = RuleConfig.from_dict({"rules": {"scripted_client": {"params": {"markers": ["curl/", "wget/"]}}, "ua_rotation": {"mode": "shadow"}}})
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(original.to_dict(), ensure_ascii=False), encoding="utf-8")
    loaded = RuleConfig.from_file(path)
    assert loaded.modes == original.modes and loaded.params == original.params
    assert loaded.resolved_params(REGISTRY["scripted_client"]).markers == ("curl/", "wget/")
    path.write_text("{không phải json", encoding="utf-8")
    with pytest.raises(ConfigError, match="JSON"):
        RuleConfig.from_file(path)


def test_finding_defaults_are_immutable_and_severity_is_optional():
    finding = Finding("m")
    assert finding.severity is None and dict(finding.evidence) == {}
    with pytest.raises(Exception):
        finding.message = "khác"  # type: ignore[misc]
