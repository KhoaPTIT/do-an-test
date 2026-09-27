"""MR10 — hồ sơ cấu hình luật đã tinh chỉnh (app/detection/engine/profiles/): nạp được, chỉ ghi đè thứ tồn tại, tôn trọng các bậc thang bị loại."""

import json
from pathlib import Path

import pytest

from app.detection.engine import REGISTRY, LoginAttempt, RuleConfig, RuleEngine

PROFILES = Path(__file__).resolve().parents[1] / "app" / "detection" / "engine" / "profiles"
TUNED = PROFILES / "rba_train_tuned.json"

pytestmark = pytest.mark.skipif(not TUNED.is_file(), reason="chưa có hồ sơ đã tinh chỉnh (python -m ml.rba.rule_tuning tune)")


def test_the_tuned_profile_loads_and_only_overrides_known_rules_and_parameters():
    raw = json.loads(TUNED.read_text(encoding="utf-8"))
    config = RuleConfig.from_file(TUNED)  # tham số sai/ngoài khoảng/không tồn tại sẽ bị từ chối ở đây
    assert set(raw) == {"rules"} and set(raw["rules"]) <= set(REGISTRY)
    for rule_id, entry in raw["rules"].items():
        spec = REGISTRY[rule_id]
        assert set(entry) <= {"mode", "params"} and set(entry.get("params", {})) <= {p.name for p in spec.params}
        assert config.mode_of(spec) == entry.get("mode", spec.default_mode)
        resolved = vars(config.resolved_params(spec))
        assert all(resolved[name] == value for name, value in entry.get("params", {}).items())  # giá trị nạp đúng bằng giá trị trong tệp


def test_the_ladders_excluded_by_design_stay_out_of_the_profile():
    rules = json.loads(TUNED.read_text(encoding="utf-8"))["rules"]
    stuffing = rules["credential_stuffing"]["params"]
    assert stuffing["asn_min_fails"] == 1_000_000 and stuffing["asn_min_users"] == 1_000_000  # phạm vi ASN tuyệt đối bị tắt
    assert rules["dormant_account_login"] == {"mode": "shadow"}  # ngưỡng tuỳ theo tuổi log: không đưa vào


def test_an_engine_can_run_with_the_tuned_profile_and_never_enforces_a_shadowed_rule():
    engine = RuleEngine(RuleConfig.from_file(TUNED))
    shadowed = {rid for rid, entry in json.loads(TUNED.read_text(encoding="utf-8"))["rules"].items() if entry.get("mode") == "shadow"}
    hits = []
    for i in range(60):  # một IP dò 12 tài khoản liên tục: chắc chắn chạm ít nhất một luật đã tinh chỉnh
        hits += engine.evaluate(LoginAttempt(ts=1_700_000_000 + i, username=f"victim{i % 12}", success=False, ip="6.6.6.6", user_key=f"k{i % 12}", asn=64500, user_agent="curl/8.4.0")).hits
    assert hits and all(h.is_shadow for h in hits if h.rule_id in shadowed)
    assert any(h.rule_id == "scripted_client" and not h.is_shadow for h in hits)  # luật không tham số vẫn enforce
