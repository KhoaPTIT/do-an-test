"""Phase 3 — `app/detection/attribution.py` (hàm thuần): khi nào tạo cảnh báo, detector chính là gì, và việc tạo cảnh
báo KHÔNG đổi hành động của hybrid risk engine."""

from app.detection.attribution import (
    ALERT_REASON_OVERRIDE,
    ALERT_REASON_RULE,
    ALERT_REASON_SCORE,
    ML_ONLY_DETECTOR,
    PRIORITY,
    build_verdict,
    choose_primary,
    max_severity,
)
from app.detection.engine.registry import REGISTRY
from app.detection.engine.types import RuleHit
from app.detection.hybrid import ActionBands, RuleWeights, combine_risk

BANDS = ActionBands(alert_at=40, step_up_at=65, lock_at=85)


def _hit(rule_id, mode="enforce", evidence=None):
    spec = REGISTRY[rule_id]
    return RuleHit(rule_id, spec.severity, f"{rule_id} khớp", evidence or {"k": 1}, mode, spec.techniques)


def _verdict(hits, ml_probability=None, weights=None):
    risk = combine_risk(ml_probability=ml_probability, hits=hits, weights=weights or RuleWeights(), bands=BANDS)
    return build_verdict(hits, risk), risk


def test_priority_covers_every_registered_rule_exactly_once():
    assert sorted(PRIORITY) == sorted(REGISTRY)
    assert len(PRIORITY) == len(set(PRIORITY))


def test_enforced_rule_alone_creates_an_alert_without_changing_the_hybrid_action():
    verdict, risk = _verdict([_hit("username_enumeration", evidence={"distinct_unknown_usernames": 9})])

    assert risk.score < BANDS.alert_at and risk.action == "allow"  # điểm vẫn thấp, hành động vẫn "allow"
    assert verdict.alert is True
    assert verdict.alert_reason == ALERT_REASON_RULE
    assert verdict.primary_detector == "username_enumeration"
    assert verdict.behavior == "username_enumeration"
    assert verdict.evidence == {"distinct_unknown_usernames": 9}


def test_shadow_rule_alone_is_recorded_but_does_not_alert():
    verdict, _ = _verdict([_hit("datacenter_ip", mode="shadow")])

    assert verdict.alert is False
    assert verdict.primary_detector is None
    assert verdict.matched_rules == ("datacenter_ip",)
    assert verdict.shadow_rules == ("datacenter_ip",)


def test_behavior_rule_wins_over_marker_rule_regardless_of_weight():
    # scripted_client có trọng số CAO HƠN hẳn nhưng chỉ là dấu hiệu công cụ — hành vi vẫn là rải mật khẩu.
    weights = RuleWeights.from_dict({"weights": {"scripted_client": {"weight": 0.9, "calibrated": True, "n": 10}, "password_spray_slow": {"weight": 0.1, "calibrated": True, "n": 10}}})
    verdict, _ = _verdict([_hit("scripted_client"), _hit("password_spray_slow")], weights=weights)

    assert verdict.primary_detector == "password_spray_slow"
    assert verdict.matched_rules == ("scripted_client", "password_spray_slow")
    assert {"rule": "scripted_client", "weight": 0.9, "group": "rule"} in verdict.contributing_rules


def test_more_specific_rule_wins_within_the_same_role():
    assert choose_primary([_hit("brute_force"), _hit("distributed_bruteforce")]).rule_id == "distributed_bruteforce"
    assert choose_primary([_hit("username_enumeration"), _hit("credential_stuffing")]).rule_id == "credential_stuffing"


def test_zero_weight_rules_are_listed_as_matched_but_not_as_contributing():
    weights = RuleWeights.from_dict({"weights": {"distributed_bruteforce": {"weight": 0.0, "calibrated": True, "n": 2}}})
    verdict, _ = _verdict([_hit("distributed_bruteforce")], weights=weights)

    assert verdict.primary_detector == "distributed_bruteforce"
    assert verdict.contributing_rules == ()


def test_override_rule_is_primary_and_reason_is_override():
    verdict, risk = _verdict([_hit("scripted_client"), _hit("blocklist_hit")])

    assert risk.action == "lock"
    assert verdict.alert_reason == ALERT_REASON_OVERRIDE
    assert verdict.primary_detector == "blocklist_hit"


def test_score_threshold_without_rules_is_attributed_to_ml_only():
    verdict, risk = _verdict([], ml_probability=0.7)

    assert risk.action != "allow"
    assert verdict.alert_reason == ALERT_REASON_SCORE
    assert verdict.primary_detector == ML_ONLY_DETECTOR


def test_score_threshold_with_only_shadow_rules_still_names_a_rule():
    verdict, _ = _verdict([_hit("country_hop", mode="shadow")], ml_probability=0.7)

    assert verdict.alert_reason == ALERT_REASON_SCORE
    assert verdict.primary_detector == "country_hop"


def test_no_hits_and_low_score_means_no_alert():
    verdict, _ = _verdict([], ml_probability=0.01)
    assert verdict.alert is False


def test_explanation_carries_every_required_field():
    verdict, risk = _verdict([_hit("password_spray_slow"), _hit("scripted_client")])
    explanation = verdict.to_explanation(risk)

    for key in ("behavior", "primary_detector", "matched_rules", "contributing_rules", "risk_score", "alert_reason", "evidence"):
        assert key in explanation
    assert explanation["behavior"] == "password_spraying"
    assert explanation["risk_score"] == risk.score


def test_max_severity():
    assert max_severity("low", None, "high", "medium") == "high"
    assert max_severity(None) == "low"


def test_experimental_enforce_rule_alone_does_not_alert_but_is_recorded():
    assert not REGISTRY["scripted_client"].is_verified
    verdict, _ = _verdict([_hit("scripted_client")])
    assert verdict.alert is False
    assert verdict.matched_rules == ("scripted_client",) and verdict.experimental_rules == ("scripted_client",)


def test_verified_rule_leads_and_experimental_rule_becomes_a_secondary_signal():
    verdict, _ = _verdict([_hit("bot_user_agent"), _hit("brute_force")])
    assert verdict.alert_reason == ALERT_REASON_RULE and verdict.primary_detector == "brute_force"
    assert verdict.standalone_rules == ("brute_force",) and verdict.secondary_signals == ("bot_user_agent",)


def test_score_threshold_prefers_a_verified_rule_then_an_experimental_one_as_primary():
    verdict, _ = _verdict([_hit("scripted_client")], ml_probability=0.7)
    assert verdict.alert_reason == ALERT_REASON_SCORE and verdict.primary_detector == "scripted_client"


def test_every_rule_declares_a_valid_verification_state():
    from app.detection.engine.registry import VERIFICATION_STATES

    assert all(spec.verification in VERIFICATION_STATES for spec in REGISTRY.values())
