"""MR4 — chỉ số có trọng số: khớp scikit-learn, khớp tính vét cạn trên đường cong ROC, bootstrap đúng."""

import numpy as np
import pytest
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

from ml.rba import metrics as M


def make_data(n=4000, prevalence=0.05, seed=0, decimals=1):
    rng = np.random.default_rng(seed)
    y = rng.random(n) < prevalence
    score = np.round(rng.normal(0, 1, n) + 1.6 * y, decimals)  # làm tròn để có nhiều điểm bằng nhau
    weight = np.where(y, rng.uniform(1, 8, n), 1.0)
    return y, score, weight


def reference(y, score, weight):
    ref = M.NegativeReference.build(score[~y], weight[~y])
    return ref, score[y], weight[y]


@pytest.mark.parametrize("seed", [0, 1, 2])
def test_roc_auc_and_average_precision_match_scikit_learn_with_weights_and_ties(seed):
    y, score, weight = make_data(seed=seed)
    ref, ps, pw = reference(y, score, weight)
    assert M.roc_auc(ref, ps, pw) == pytest.approx(roc_auc_score(y, score, sample_weight=weight), abs=1e-12)
    assert M.average_precision(ref, ps, pw) == pytest.approx(average_precision_score(y, score, sample_weight=weight), abs=1e-12)


@pytest.mark.parametrize("target", [0.001, 0.01, 0.05, 0.2])
def test_recall_at_fpr_matches_brute_force_on_the_roc_curve(target):
    y, score, weight = make_data(seed=3)
    ref, ps, pw = reference(y, score, weight)
    fpr, tpr, _ = roc_curve(y, score, sample_weight=weight, drop_intermediate=False)
    expected = tpr[np.flatnonzero(fpr <= target)[-1]]
    assert M.recall_at_fpr(ref, ps, pw, target) == pytest.approx(expected, abs=1e-12)


@pytest.mark.parametrize("target", [0.5, 0.9, 0.99, 1.0])
def test_fpr_at_recall_matches_brute_force_on_the_roc_curve(target):
    y, score, weight = make_data(seed=4)
    ref, ps, pw = reference(y, score, weight)
    fpr, tpr, _ = roc_curve(y, score, sample_weight=weight, drop_intermediate=False)
    expected = fpr[np.flatnonzero(tpr >= target - 1e-12)[0]]
    assert M.fpr_at_recall(ref, ps, pw, target) == pytest.approx(expected, abs=1e-12)


def test_perfect_scorer():
    y = np.array([True] * 20 + [False] * 500)
    score = np.where(y, 10.0, 0.0) + np.linspace(0, 1, len(y))
    result = M.evaluate(y, score, n_boot=50)
    assert result.values["roc_auc"] == pytest.approx(1.0) and result.values["pr_auc"] == pytest.approx(1.0)
    assert result.values["recall@fpr=0.001"] == pytest.approx(1.0) and result.values["reauth@tpr=0.99"] == 0.0


def test_random_scorer_is_near_chance_and_pr_auc_near_prevalence():
    rng = np.random.default_rng(5)
    y = rng.random(60_000) < 0.05
    result = M.evaluate(y, rng.random(len(y)), n_boot=30)
    assert result.values["roc_auc"] == pytest.approx(0.5, abs=0.03)
    assert result.values["pr_auc"] == pytest.approx(y.mean(), abs=0.02)


def test_weight_is_equivalent_to_duplicating_rows():
    y, score, _ = make_data(n=600, seed=6)
    weight = np.where(y, 3.0, 1.0)
    dup_y = np.concatenate([y, y[y], y[y]])
    dup_score = np.concatenate([score, score[y], score[y]])
    ref, ps, pw = reference(y, score, weight)
    ref2, ps2, pw2 = reference(dup_y, dup_score, np.ones(len(dup_y)))
    assert M.roc_auc(ref, ps, pw) == pytest.approx(M.roc_auc(ref2, ps2, pw2), abs=1e-12)
    assert M.average_precision(ref, ps, pw) == pytest.approx(M.average_precision(ref2, ps2, pw2), abs=1e-12)


def test_bootstrap_is_deterministic_and_interval_brackets_the_estimate():
    y, score, weight = make_data(n=5000, prevalence=0.02, seed=7)
    a = M.evaluate(y, score, weight, n_boot=200, seed=11)
    b = M.evaluate(y, score, weight, n_boot=200, seed=11)
    assert a.ci == b.ci
    for name, value in a.values.items():
        lo, hi = a.ci[name]
        assert lo <= hi
        assert lo - 0.05 <= value <= hi + 0.05  # điểm ước lượng nằm trong (hoặc sát) khoảng


def test_more_positives_give_a_tighter_interval():
    small = make_data(n=4000, prevalence=0.01, seed=8)
    large = make_data(n=40_000, prevalence=0.01, seed=8)
    w_small = M.evaluate(*small[:2], n_boot=300, seed=1).ci["roc_auc"]
    w_large = M.evaluate(*large[:2], n_boot=300, seed=1).ci["roc_auc"]
    assert (w_large[1] - w_large[0]) < (w_small[1] - w_small[0])


def test_rows_of_the_same_cluster_are_resampled_together():
    y = np.array([True, True, True, True, False, False, False, False])
    score = np.array([9.0, 9.0, 1.0, 1.0, 5.0, 4.0, 3.0, 2.0])
    same_cluster = np.array([0, 0, 0, 0, 1, 2, 3, 4])  # mọi ca dương tính cùng một cụm
    tight = M.evaluate(y, score, cluster=same_cluster, n_boot=100, seed=0)
    assert tight.ci["roc_auc"][0] == tight.ci["roc_auc"][1] == tight.values["roc_auc"]  # chỉ có 1 cụm -> không dao động

    independent = M.evaluate(y, score, n_boot=200, seed=0)
    assert independent.ci["roc_auc"][0] < independent.ci["roc_auc"][1]


def test_evaluate_rejects_nan_scores_and_single_class():
    with pytest.raises(ValueError):
        M.evaluate(np.array([True, False]), np.array([1.0, np.nan]))
    with pytest.raises(ValueError):
        M.evaluate(np.array([False, False]), np.array([1.0, 2.0]))
