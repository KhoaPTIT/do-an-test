"""MR6 — hiệu chỉnh xác suất, hybrid "bất kỳ bộ phát hiện nào báo động" và chọn/chuyển ngưỡng."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import ensemble as En


def test_ecdf_tail_is_the_weighted_share_of_legit_logins_scoring_at_least_as_high():
    rng = np.random.default_rng(0)
    scores = np.round(rng.normal(0, 1, 3000), 1)
    weights = rng.uniform(1, 5, 3000)
    calibrator = En.EcdfCalibrator.fit(scores, weights)
    probe = np.array([-3.0, -0.5, 0.0, 0.7, 2.0, 9.0])
    expected = [max(weights[scores >= s].sum() / weights.sum(), En.TAIL_FLOOR) for s in probe]
    assert np.allclose(calibrator.tail(probe), expected)
    assert calibrator.tail(np.array([1e9]))[0] == En.TAIL_FLOOR  # cao hơn mọi đăng nhập hợp lệ -> chạm sàn


def _component(name, scorer, reference, gate=None):
    return En.Component(name, scorer, En.EcdfCalibrator.fit(reference), gate)


def test_hybrid_flags_when_any_detector_is_alarmed_and_names_the_trigger():
    rng = np.random.default_rng(1)
    reference = rng.normal(0, 1, 5000)
    a = _component("chi_a", lambda f: f["a"].to_numpy(), reference)
    b = _component("chi_b", lambda f: f["b"].to_numpy(), reference)
    hybrid = En.HybridMinTail([a, b])
    frame = pd.DataFrame({"a": [0.0, 4.5, 0.0], "b": [0.0, 0.0, 4.5]})
    scores = hybrid(frame)
    assert scores[0] < 1 and scores[1] > 3 and scores[2] > 3  # chỉ dòng có bộ phát hiện báo động mới có điểm cao
    assert list(hybrid.triggered_by(frame))[1:] == ["chi_a", "chi_b"]


def test_a_gated_detector_is_silent_for_rows_outside_its_gate():
    reference = np.random.default_rng(2).normal(0, 1, 5000)
    gated = _component("chi_thanh_cong", lambda f: f["s"].to_numpy(), reference, gate=lambda f: f["ok"].to_numpy(dtype=bool))
    hybrid = En.HybridMinTail([gated])
    frame = pd.DataFrame({"s": [6.0, 6.0], "ok": [True, False]})
    scores = hybrid(frame)
    assert scores[0] > 5 and scores[1] == pytest.approx(0.0)  # -log10(1) = 0


def test_hybrid_score_grows_with_rarity_so_thresholds_transfer_across_scales():
    rng = np.random.default_rng(3)
    small_scale = _component("s", lambda f: f["x"].to_numpy(), rng.normal(0, 1, 20000))
    big_scale = _component("b", lambda f: 1000 * f["x"].to_numpy() + 50, rng.normal(0, 1, 20000) * 1000 + 50)
    frame = pd.DataFrame({"x": np.linspace(-2.5, 2.5, 50)})
    # hai tập tham chiếu độc lập nên đuôi hiếm dao động do lấy mẫu; cùng hình dạng thì điểm hybrid phải gần nhau
    assert np.allclose(En.HybridMinTail([small_scale])(frame), En.HybridMinTail([big_scale])(frame), atol=0.3)


def test_isotonic_calibration_is_monotone_and_matches_observed_rates():
    rng = np.random.default_rng(4)
    raw = rng.normal(0, 2, 40_000)
    truth = 1 / (1 + np.exp(-(raw - 1)))
    y = rng.random(len(raw)) < truth
    weights = np.ones(len(raw))
    cal = En.IsotonicCalibrator.fit(raw, y, weights)
    grid = np.linspace(-4, 6, 40)
    prob = cal.probability(grid)
    assert (np.diff(prob) >= -1e-12).all() and prob.min() >= 0 and prob.max() <= 1
    table = En.reliability_table(cal.probability(raw), y, weights, bins=10)
    assert max(abs(r["predicted"] - r["observed"]) for r in table) < 0.03
    assert sum(r["weight_share"] for r in table) == pytest.approx(1.0)
    assert En.brier_score(cal.probability(raw), y, weights) < En.brier_score(np.full(len(y), y.mean()), y, weights)


def test_threshold_chosen_on_validation_realizes_the_target_false_alert_rate_on_new_data():
    rng = np.random.default_rng(5)
    val_neg, test_neg = rng.normal(0, 1, 200_000), rng.normal(0, 1, 200_000)
    threshold = En.threshold_for_fpr(val_neg, np.ones(len(val_neg)), 0.01)
    scores = np.r_[test_neg, rng.normal(3, 1, 500)]
    y = np.r_[np.zeros(len(test_neg)), np.ones(500)].astype(bool)
    rates = En.realized_rates(scores, y, np.ones(len(y)), threshold)
    assert rates["fpr"] == pytest.approx(0.01, abs=0.002)
    assert 0.5 < rates["recall"] < 1.0


def test_realized_false_alert_rate_reveals_distribution_shift():
    rng = np.random.default_rng(6)
    val_neg = rng.normal(0, 1, 100_000)
    threshold = En.threshold_for_fpr(val_neg, np.ones(len(val_neg)), 0.01)
    drifted = rng.normal(0.5, 1, 100_000)  # phân phối trôi: người hợp lệ điểm cao hơn
    rates = En.realized_rates(drifted, np.zeros(len(drifted), dtype=bool), np.ones(len(drifted)), threshold)
    assert rates["fpr"] > 0.03 and rates["recall"] is None
