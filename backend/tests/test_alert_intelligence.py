"""MR13 — novelty, gán họ tấn công gợi ý, ưu tiên, chống trùng lặp: kiểm tra THUẦN (không DB), xem
app/detection/alert_intelligence.py. Tích hợp qua pipeline thật (dedup giảm số alert, message có novelty) ở
tests/test_pipeline_mr13.py."""

from app.detection.alert_intelligence import (
    DEDUP_WINDOW,
    ML_COMPONENT_FAMILY,
    NoveltyFact,
    action_escalated,
    build_alert_message,
    compute_novelty,
    priority_score,
    suggest_attack_family,
)
from app.detection.engine.registry import CATEGORIES, REGISTRY
from app.detection.hybrid import Contribution, RiskResult
from ml.rba.explain import COMPONENT_LABELS
from ml.rba.features import EventRecord, GlobalCounts, HistorySummary

US = 1_000_000


def _event(ts_us=0, user_id=1, ip="1.1.1.1", asn=100, country="VN", device_type="desktop", success=True) -> EventRecord:
    return EventRecord(
        ts_us=ts_us, user_id=user_id, ip=ip, asn=asn, country=country, ua="ua", browser="Chrome", os="Windows",
        device_type=device_type, success=success,
    )


def _summary(user_events) -> HistorySummary:
    return HistorySummary(user_events=user_events, ip_events=[], ip_prior_attempts_all=0, asn_events=[], global_counts=GlobalCounts())


def _risk_result(contributions) -> RiskResult:
    return RiskResult(
        score=90, action="lock", probability=0.9, ml_probability=None, rule_probability=0.9, reputation_probability=0.0,
        overridden_by=None, contributions=tuple(contributions),
    )


# --------------------------------------------------------------------------------------------------------- novelty


def test_no_novelty_when_current_event_matches_established_history():
    history = [_event(ts_us=i * US, country="VN", asn=100, device_type="desktop") for i in range(5)]
    current = _event(ts_us=10 * US, country="VN", asn=100, device_type="desktop")
    assert compute_novelty(current, _summary(history)) == []


def test_no_novelty_when_account_has_no_prior_success():
    current = _event(ts_us=0, country="RU")
    assert compute_novelty(current, _summary([_event(ts_us=-US, success=False)])) == []
    assert compute_novelty(current, _summary(None)) == []


def test_new_country_reports_the_usual_value_and_how_many_times_it_was_used():
    history = [_event(ts_us=i * US, country="VN", asn=100, device_type="desktop") for i in range(41)]
    current = _event(ts_us=100 * US, country="RU", asn=100, device_type="desktop")

    facts = compute_novelty(current, _summary(history))

    assert len(facts) == 1
    fact = facts[0]
    assert fact.attribute == "country" and fact.new_value == "RU" and fact.usual_value == "VN" and fact.usual_count == 41
    assert fact.text == "lần đầu quốc gia này (RU), trước đó dùng VN 41 lần"


def test_multiple_novel_attributes_are_reported_in_priority_order():
    history = [_event(ts_us=i * US, country="VN", asn=100, device_type="desktop") for i in range(3)]
    current = _event(ts_us=100 * US, country="RU", asn=999, device_type="mobile")

    facts = compute_novelty(current, _summary(history))

    assert [f.attribute for f in facts] == ["country", "asn", "device"]
    assert facts[1].new_value == "AS999" and facts[2].new_value == "di động"


def test_unknown_device_type_is_never_reported_as_a_novelty_fact():
    history = [_event(ts_us=0, country="VN", asn=100, device_type="desktop")]
    current = _event(ts_us=US, country="VN", asn=100, device_type="unknown")
    assert compute_novelty(current, _summary(history)) == []


# --------------------------------------------------------------------------------------------- gán họ tấn công


def test_family_is_none_when_there_is_no_contribution_at_all():
    assert suggest_attack_family(_risk_result([]), ml_component=None) == (None, None)


def test_every_registered_rule_maps_to_its_own_category_with_full_confidence_when_it_leads():
    """Vét cạn TOÀN BỘ luật đã đăng ký (không chỉ vài mẫu) — hồi quy nếu ai thêm luật mới mà quên nhóm nó đúng 4
    CATEGORIES hiện có."""
    # 19 luật của MR9 + `unusual_device` (Milestone B, nhóm "Hồ sơ hành vi") — đổi số này thì phải xem lại kịch bản của
    # alert_intelligence_sim.py (không phụ thuộc số luật: kiểm tra lại ở Milestone B).
    assert len(REGISTRY) == 23  # + unusual_location, unusual_hour, login_velocity_spike (Milestone C)
    for rule_id, spec in REGISTRY.items():
        group = "reputation" if spec.category == "Danh tiếng hạ tầng" else "rule"
        contribution = Contribution(rule_id, spec.title, 0.77, group)
        family, confidence = suggest_attack_family(_risk_result([contribution]), ml_component=None)
        assert family == spec.category and spec.category in CATEGORIES
        assert confidence == 0.77


def test_ml_component_leading_maps_to_its_own_vietnamese_label():
    assert set(ML_COMPONENT_FAMILY) == set(COMPONENT_LABELS)  # cùng 3 thành phần của HybridMinTail, không tự bịa thêm
    for component, label in COMPONENT_LABELS.items():
        contribution = Contribution("ml", "mô hình học máy", 0.5, "ml")
        family, confidence = suggest_attack_family(_risk_result([contribution]), ml_component=component)
        assert family == label and confidence == 0.5


def test_ml_component_unknown_still_returns_a_family_marked_as_ml_not_crash():
    contribution = Contribution("ml", "mô hình học máy", 0.5, "ml")
    family, confidence = suggest_attack_family(_risk_result([contribution]), ml_component=None)
    assert family is not None and "mô hình học máy" in family and confidence == 0.5


def test_family_comes_from_the_leading_contribution_not_a_later_one():
    contributions = [Contribution("blocklist_hit", "trong blocklist", 0.9, "reputation"), Contribution("brute_force", "dò mật khẩu", 0.3, "rule")]
    family, confidence = suggest_attack_family(_risk_result(contributions), ml_component=None)
    assert family == REGISTRY["blocklist_hit"].category and confidence == 0.9


def test_rule_evidence_wins_over_ml_even_when_ml_has_a_higher_weight():
    """Phát hiện THẬT qua backend/scripts/alert_intelligence_sim.py: trên hệ thống demo (IP Việt Nam thật), ML một
    mình có thể có trọng số CAO HƠN một luật cụ thể đã khớp (ASN/quốc gia hiếm so với RBA — đúng phát hiện PSI drift
    của MR12) — nếu không ưu tiên luật, alert do blocklist_hit sinh ra sẽ bị gán nhầm thành "đăng nhập bất thường"."""
    contributions = [Contribution("ml", "mô hình học máy", 0.95, "ml"), Contribution("blocklist_hit", "trong blocklist", 0.5, "reputation")]
    family, confidence = suggest_attack_family(_risk_result(contributions), ml_component="bat_thuong")
    assert family == REGISTRY["blocklist_hit"].category and confidence == 0.5  # luật thắng dù ML có trọng số cao hơn


def test_ml_is_used_only_when_there_is_no_rule_or_reputation_evidence_at_all():
    contributions = [Contribution("ml", "mô hình học máy", 0.4, "ml")]
    family, confidence = suggest_attack_family(_risk_result(contributions), ml_component="chiem_tai_khoan")
    assert family == COMPONENT_LABELS["chiem_tai_khoan"] and confidence == 0.4


# -------------------------------------------------------------------------------------------------------- ưu tiên


def test_priority_score_scales_with_novelty_count_confidence_and_importance():
    one_fact = [NoveltyFact("country", "RU", "VN", 10)]
    three_facts = [NoveltyFact("country", "RU", "VN", 10), NoveltyFact("asn", "AS1", None, 0), NoveltyFact("device", "di động", "máy tính", 5)]

    assert priority_score([], None, 1.0) == 0.0  # không bằng chứng, không novelty -> ưu tiên thấp nhất
    assert priority_score([], 0.8, 1.0) == 1 * 0.8 * 1.0
    assert priority_score(one_fact, 0.8, 1.0) == 2 * 0.8 * 1.0
    assert priority_score(three_facts, 0.8, 1.0) == 4 * 0.8 * 1.0
    assert priority_score(one_fact, 0.8, 2.0) == 2 * 0.8 * 2.0  # importance nhân thêm, đúng công thức


# -------------------------------------------------------------------------------------------------- chống trùng lặp


def test_action_escalated_only_when_the_new_action_ranks_strictly_higher():
    assert action_escalated("alert", "step_up") is True
    assert action_escalated("alert", "lock") is True
    assert action_escalated("lock", "alert") is False  # KHÔNG được coi tụt hạng là "leo thang"
    assert action_escalated("alert", "alert") is False
    assert DEDUP_WINDOW.total_seconds() == 15 * 60


# -------------------------------------------------------------------------------------------------------- message


def test_message_keeps_top_3_reasons_adds_one_novelty_fact_and_the_suggested_family():
    contributions = [
        Contribution("blocklist_hit", "trong blocklist", 0.9, "reputation"),
        Contribution("brute_force", "dò mật khẩu", 0.3, "rule"),
        Contribution("ml", "mô hình học máy", 0.2, "ml"),
        Contribution("bot_user_agent", "UA bot", 0.05, "rule"),  # lý do thứ 4 — KHÔNG được xuất hiện trong message (D4: top-3)
    ]
    message = build_alert_message(
        _risk_result(contributions), novelty_facts=[NoveltyFact("country", "RU", "VN", 41)], family="Danh tiếng hạ tầng", confidence=0.9,
    )
    assert "trong blocklist (90%)" in message and "dò mật khẩu (30%)" in message and "mô hình học máy (20%)" in message
    assert "UA bot" not in message
    assert "Lần đầu quốc gia này (RU), trước đó dùng VN 41 lần." in message
    assert "Họ tấn công gợi ý: Danh tiếng hạ tầng (90%)." in message


def test_message_mentions_repeat_count_only_when_deduped():
    message_first = build_alert_message(_risk_result([Contribution("blocklist_hit", "x", 0.9, "reputation")]), novelty_facts=[], family="Danh tiếng hạ tầng", confidence=0.9)
    message_repeat = build_alert_message(
        _risk_result([Contribution("blocklist_hit", "x", 0.9, "reputation")]), novelty_facts=[], family="Danh tiếng hạ tầng", confidence=0.9, occurrence_count=4,
    )
    assert "lặp lại" not in message_first
    assert "Đã lặp lại 4 lần trong 15 phút gần đây." in message_repeat
