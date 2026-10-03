"""Thí nghiệm luật vs ML (Phase 4.1F): phân nhóm A/B/C/D, kết cục kịch bản, và góc nhìn ML theo từng lần thử của runner Phase 3."""

import random
from functools import partial

import pytest

import scripts.behavior_verification as bv
from verification.harness import VerificationEnv
from verification.rule_ml_experiment import _quadrant


def test_quadrants():
    assert [_quadrant(r, m) for r, m in ((True, True), (True, False), (False, True), (False, False))] == ["A", "B", "C", "D"]


def test_final_decision_prefers_a_new_block_and_marks_alerts():
    view = [{"action": "allow"}, {"action": "alert"}]
    assert bv._final_decision(view, detection=[], blocks_created=0) == "alert"
    assert bv._final_decision([{"action": "allow"}], detection=["x"], blocks_created=0) == "allow + alert"
    assert bv._final_decision(view, detection=["x"], blocks_created=1) == "lock (blocklist) + alert"
    assert bv._final_decision([], detection=[], blocks_created=0) == "—"


def _scenario(behavior, kind="positive", i=0):
    positive_gen, negative_gen = bv.GENERATORS[behavior]
    return (positive_gen if kind == "positive" else negative_gen)(random.Random(f"test:{behavior}"), i)


def test_scenario_without_model_reports_rules_only(monkeypatch):
    result = bv.run_scenario(_scenario("brute_force"), partial(VerificationEnv, monkeypatch.setattr))
    ml = result["ml"]
    assert ml["model_loaded"] is False and ml["ml_scored_events"] == 0 and ml["ml_detected"] is False
    assert ml["rule_detected"] is True and "brute_force" in ml["primary_detectors"]


def test_scenario_with_real_model_scores_mature_successes(monkeypatch, trained_ml_model_dir):
    factory = partial(VerificationEnv, monkeypatch.setattr, ml_model_dir=trained_ml_model_dir)
    result = bv.run_scenario(_scenario("unusual_location"), factory)
    ml = result["ml"]
    assert ml["model_loaded"] is True and ml["ml_scored_events"] >= 1 and ml["ml_max_score"] is not None
    assert result["detected"] is True and ml["rule_detected"] is True  # bật ML không làm mất phát hiện của luật


def test_brute_force_failures_are_outside_the_model_scope(monkeypatch, trained_ml_model_dir):
    factory = partial(VerificationEnv, monkeypatch.setattr, ml_model_dir=trained_ml_model_dir)
    ml = bv.run_scenario(_scenario("brute_force"), factory)["ml"]
    assert ml["ml_scored_events"] == 0 and ml["ml_detected"] is False


def test_event_view_refuses_a_verdict_count_mismatch(monkeypatch):
    env, sc = VerificationEnv(monkeypatch.setattr), _scenario("brute_force")
    bv._setup(env, sc.accounts, sc.history, sc.blocks)
    step = sc.steps[0]
    env.login(step.username, success=step.success, ip=step.ip, ts=bv.T0, user_agent=step.user_agent)
    env.verdicts.clear()
    with pytest.raises(RuntimeError):
        bv.ml_event_view(env)
