"""MR11 — bộ gộp hybrid risk engine: noisy-OR, gộp luật/danh tiếng/ML thành điểm 0-100 và hành động, ghi đè, giải thích."""

import math

import pytest

from app.detection.engine.registry import CATEGORIES, REGISTRY
from app.detection.engine.types import RuleHit
from app.detection.hybrid.calibration import ActionBands, RuleWeightEntry, RuleWeights
from app.detection.hybrid.combine import REPUTATION_CATEGORY, combine_risk, noisy_or

BANDS = ActionBands(alert_at=20, step_up_at=50, lock_at=85)


def hit(rule_id: str, weight_hint: str = "", mode: str = "enforce") -> RuleHit:
    return RuleHit(rule_id=rule_id, severity="high", message=f"đã khớp {rule_id}{weight_hint}", evidence={}, mode=mode, techniques=())


def weights(entries: dict[str, float], override=frozenset(), default=0.05) -> RuleWeights:
    return RuleWeights({rule_id: RuleWeightEntry(w, True, 100) for rule_id, w in entries.items()}, frozenset(override), default)


# ------------------------------------------------------------------------------------------------ noisy_or


def test_noisy_or_matches_the_hand_computed_formula():
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)  # 1 - 0.5*0.5
    assert noisy_or([0.1, 0.2, 0.3]) == pytest.approx(1 - 0.9 * 0.8 * 0.7)
    assert noisy_or([]) == 0.0 and noisy_or([None, None]) == 0.0
    assert noisy_or([None, 0.4]) == pytest.approx(0.4)  # None bị bỏ qua, không phải "chắc chắn không" (0.0 sẽ giữ nguyên 0.4 khác đi)
    assert noisy_or([1.0, 0.9]) == pytest.approx(1.0)  # một bằng chứng chắc chắn -> kết quả chắc chắn


def test_noisy_or_decomposes_additively_in_log_space_regardless_of_order():
    """log(1 - P) = Σ log(1 - p_i): kiểm tra tính chất mà docstring của noisy_or khẳng định, không phụ thuộc thứ tự."""
    probs = [0.1, 0.37, 0.02, 0.6]
    total = noisy_or(probs)
    assert math.log(1 - total) == pytest.approx(sum(math.log(1 - p) for p in probs))
    assert noisy_or(probs) == pytest.approx(noisy_or(list(reversed(probs))))


def test_noisy_or_clamps_out_of_range_probabilities():
    assert noisy_or([-1.0]) == 0.0 and noisy_or([2.0]) == pytest.approx(1.0)


# ------------------------------------------------------------------------------------------------ combine_risk: cơ bản


def test_ml_alone_maps_straight_through_to_the_score():
    result = combine_risk(ml_probability=0.5, hits=[], weights=weights({}), bands=BANDS)
    assert result.score == 50 and result.action == "step_up" and result.rule_probability == 0.0 and result.reputation_probability == 0.0
    assert [c.source for c in result.contributions] == ["ml"] and result.overridden_by is None


def test_no_ml_and_no_hits_gives_an_all_clear():
    result = combine_risk(ml_probability=None, hits=[], weights=weights({}), bands=BANDS)
    assert (result.score, result.action, result.probability, result.contributions) == (0, "allow", 0.0, ())


def test_rules_and_ml_combine_via_noisy_or_and_action_follows_the_score():
    result = combine_risk(ml_probability=0.2, hits=[hit("brute_force")], weights=weights({"brute_force": 0.5}), bands=BANDS)
    assert result.probability == pytest.approx(1 - 0.8 * 0.5) and result.score == 60 and result.action == "step_up"
    assert result.rule_probability == pytest.approx(0.5) and result.ml_probability == 0.2


def test_an_unknown_rule_id_falls_back_to_the_default_weight():
    result = combine_risk(ml_probability=None, hits=[hit("brute_force")], weights=weights({}, default=0.3), bands=BANDS)
    assert result.rule_probability == pytest.approx(0.3) and result.score == 30


# ------------------------------------------------------------------------------------------------ nhóm luật vs danh tiếng


def test_reputation_and_other_rules_are_combined_separately_then_merged():
    reputation_rule = next(rid for rid, spec in REGISTRY.items() if spec.category == REPUTATION_CATEGORY)
    other_rule = next(rid for rid, spec in REGISTRY.items() if spec.category != REPUTATION_CATEGORY)
    result = combine_risk(ml_probability=None, hits=[hit(reputation_rule), hit(other_rule)], weights=weights({reputation_rule: 0.4, other_rule: 0.6}), bands=BANDS)
    assert result.reputation_probability == pytest.approx(0.4) and result.rule_probability == pytest.approx(0.6)
    assert result.probability == pytest.approx(1 - 0.6 * 0.4)
    groups = {c.source: c.group for c in result.contributions}
    assert groups[reputation_rule] == "reputation" and groups[other_rule] == "rule"


def test_reputation_category_constant_is_a_real_registry_category():
    assert REPUTATION_CATEGORY in CATEGORIES
    assert {rid for rid, spec in REGISTRY.items() if spec.category == REPUTATION_CATEGORY} == {"tor_exit", "datacenter_ip", "vpn_ip", "blocklist_hit"}


def test_two_rules_in_the_same_group_combine_via_noisy_or_not_just_the_max():
    result = combine_risk(ml_probability=None, hits=[hit("brute_force"), hit("credential_stuffing")], weights=weights({"brute_force": 0.3, "credential_stuffing": 0.3}), bands=BANDS)
    assert result.rule_probability == pytest.approx(1 - 0.7 * 0.7) and result.rule_probability > 0.3  # nhiều hơn từng luật riêng lẻ


# ------------------------------------------------------------------------------------------------ ghi đè


def test_an_override_rule_forces_a_lock_regardless_of_everything_else():
    result = combine_risk(ml_probability=0.01, hits=[hit("blocklist_hit")], weights=weights({"blocklist_hit": 0.01}, override={"blocklist_hit"}), bands=BANDS)
    assert result.overridden_by == "blocklist_hit" and result.action == "lock" and result.score == 100 and result.probability == 1.0


def test_override_wins_even_when_it_fires_alongside_other_low_confidence_hits():
    result = combine_risk(ml_probability=0.02, hits=[hit("brute_force"), hit("blocklist_hit")], weights=weights({"brute_force": 0.05, "blocklist_hit": 0.9}, override={"blocklist_hit"}), bands=BANDS)
    assert result.overridden_by == "blocklist_hit" and result.action == "lock"
    assert result.rule_probability == pytest.approx(0.05)  # thành phần luật vẫn tính đúng, chỉ hành động cuối bị ghi đè


def test_first_override_hit_in_iteration_order_is_the_one_reported():
    result = combine_risk(ml_probability=None, hits=[hit("blocklist_hit"), hit("tor_exit")], weights=weights({}, override={"blocklist_hit", "tor_exit"}), bands=BANDS)
    assert result.overridden_by == "blocklist_hit"


# ------------------------------------------------------------------------------------------------ giải thích, trùng lặp, dữ liệu tuỳ ý


def test_contributions_are_sorted_by_weight_descending_including_ml():
    result = combine_risk(ml_probability=0.9, hits=[hit("brute_force"), hit("credential_stuffing")], weights=weights({"brute_force": 0.95, "credential_stuffing": 0.1}), bands=BANDS)
    assert [c.source for c in result.contributions] == ["brute_force", "ml", "credential_stuffing"]


def test_a_duplicated_hit_for_the_same_rule_is_only_counted_once():
    result = combine_risk(ml_probability=None, hits=[hit("brute_force"), hit("brute_force")], weights=weights({"brute_force": 0.4}), bands=BANDS)
    assert result.rule_probability == pytest.approx(0.4) and len(result.contributions) == 1


def test_shadow_mode_hits_still_count_as_evidence():
    """Shadow chỉ quyết định RuleEngine có tự tạo cảnh báo hay không (app/detection/engine); ở bộ gộp, mọi lần khớp là bằng chứng."""
    enforce = combine_risk(ml_probability=None, hits=[hit("country_hop", mode="enforce")], weights=weights({"country_hop": 0.3}), bands=BANDS)
    shadow = combine_risk(ml_probability=None, hits=[hit("country_hop", mode="shadow")], weights=weights({"country_hop": 0.3}), bands=BANDS)
    assert enforce.score == shadow.score == 30


def test_score_is_rounded_and_clamped_to_0_100():
    result = combine_risk(ml_probability=0.999, hits=[hit("brute_force")], weights=weights({"brute_force": 0.999}), bands=BANDS)
    assert 0 <= result.score <= 100


def test_a_custom_registry_can_be_passed_in_for_rules_outside_the_default_one():
    from app.detection.engine.registry import RuleSpec

    custom = {"trap": RuleSpec(id="trap", title="bẫy", category=REPUTATION_CATEGORY, severity="high", techniques=(), description="", params=(), needs=(), default_mode="enforce", evaluate=lambda ctx: None)}
    result = combine_risk(ml_probability=None, hits=[hit("trap")], weights=weights({"trap": 0.7}), bands=BANDS, registry=custom)
    assert result.reputation_probability == pytest.approx(0.7) and result.rule_probability == 0.0
