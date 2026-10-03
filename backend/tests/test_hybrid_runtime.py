"""Risk engine lúc chạy thật (Phase 4.1): 20 detector luật + model bất thường, KHÔNG BAO GIỜ để ML tự khoá tài khoản.

Thay bộ test MR12 cũ (nạp `hybrid_cp2` qua model_registry, `scorer`, `ml_component`) — thành phần đó bị gỡ khỏi runtime ở
Phase 4.1 (cần bộ RBA 9GB, không tái lập được; quyết định ML0, docs/ml-anomaly-model.md)."""

import pytest

from app.detection import hybrid_runtime
from app.detection.engine.types import RuleHit
from app.detection.hybrid import ActionBands, HybridProfile, RuleWeights
from app.detection.hybrid.calibration import RuleWeightEntry
from app.detection.ml_runtime import ML_ANOMALY_WEIGHT, MLPrediction


def hit(rule_id, mode="enforce"):
    return RuleHit(rule_id, "medium", f"{rule_id} khớp", {}, mode, ())


def ml(is_anomaly=True, available=True, in_scope=True):
    return MLPrediction(available=available, in_scope=in_scope, model_name="isolation_forest", model_version="t", anomaly_score=0.7 if in_scope else None,
                        threshold=0.6, is_anomaly=is_anomaly)


@pytest.fixture()
def engine():
    return hybrid_runtime.HybridEngine()


def test_profile_is_the_fallback_profile_used_by_the_verified_behaviors(engine):
    assert engine.profile is hybrid_runtime._FALLBACK_PROFILE
    assert (engine.profile.bands.alert_at, engine.profile.bands.step_up_at, engine.profile.bands.lock_at) == (40, 65, 85)


def test_no_evidence_means_allow(engine):
    result = engine.evaluate(None, [])
    assert (result.score, result.action, result.ml_probability) == (0, "allow", None)


def test_ml_anomaly_alone_raises_an_alert_but_never_step_up_or_lock(engine):
    result = engine.evaluate(ml(True), [])
    assert result.ml_probability == ML_ANOMALY_WEIGHT and result.score == round(ML_ANOMALY_WEIGHT * 100)
    assert result.action == "alert"
    assert any(c.group == "ml" for c in result.contributions)


@pytest.mark.parametrize("prediction", [ml(False), ml(True, available=False), ml(True, in_scope=False), None])
def test_normal_unavailable_or_out_of_scope_ml_gives_no_evidence(engine, prediction):
    result = engine.evaluate(prediction, [hit("scripted_client")])
    assert result.ml_probability is None and not any(c.group == "ml" for c in result.contributions)


def test_ml_cannot_push_a_rule_score_into_lock(engine):
    """Luật một mình 80 điểm (step_up); thêm ML noisy-OR lên 89 ≥ ngưỡng khoá 85 ⇒ bị chốt chặn hạ về step_up."""
    engine.profile = HybridProfile(RuleWeights(entries={"credential_stuffing": RuleWeightEntry(0.8, True)}), ActionBands(40, 65, 85), None)
    rules_only = engine.evaluate(None, [hit("credential_stuffing")])
    assert (rules_only.score, rules_only.action) == (80, "step_up")
    outcome = engine.evaluate_with_guard(ml(True), [hit("credential_stuffing")])
    assert outcome.result.score >= 85 and outcome.result.action == "step_up" and outcome.ml_lock_suppressed
    assert hybrid_runtime.ml_lock_suppressed(outcome.result, engine.profile.bands)


def test_rules_alone_can_still_lock_and_blocklist_still_overrides(engine):
    engine.profile = HybridProfile(RuleWeights(entries={"credential_stuffing": RuleWeightEntry(0.9, True)}), ActionBands(40, 65, 85), None)
    assert engine.evaluate(ml(True), [hit("credential_stuffing")]).action == "lock"  # luật một mình đã 90 ≥ 85
    override = engine.evaluate(ml(False), [hit("blocklist_hit")])
    assert override.action == "lock" and override.overridden_by == "blocklist_hit"


def test_evaluate_never_raises(engine, monkeypatch):
    real = hybrid_runtime.combine_risk
    calls = {"n": 0}

    def flaky(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real(**kwargs)

    monkeypatch.setattr("app.detection.hybrid_runtime.combine_risk", flaky)
    assert engine.evaluate(ml(True), [hit("brute_force")]).action == "allow"


def test_get_engine_is_a_singleton():
    assert hybrid_runtime.get_engine() is hybrid_runtime.get_engine()
