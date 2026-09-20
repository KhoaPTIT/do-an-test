"""MR4 — dựng bài kiểm tra và bảng báo cáo (dùng bảng đặc trưng tổng hợp nhỏ, không cần dữ liệu RBA thật)."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import eval_tasks as E
from ml.rba import splits


def make_table(n=6000, seed=0):
    rng = np.random.default_rng(seed)
    ts = pd.Timestamp("2020-03-01") + pd.to_timedelta(rng.integers(0, 260 * 24 * 3600, n), unit="s")
    df = pd.DataFrame(
        {
            "row_id": np.arange(n), "ts": ts, "user_id": rng.integers(0, 800, n),
            "ip": [f"1.2.{i % 200}.{i % 250}" for i in range(n)], "cur_success": (rng.random(n) < 0.8).astype(float),
            "is_attack_ip": rng.random(n) < 0.06, "is_ato": False, "in_warmup": False,
            "u_n_success": rng.integers(0, 12, n).astype(float), "llr_sum": rng.normal(0, 1, n),
        }
    )
    df["weight"] = np.where(df["is_attack_ip"], 6.0, 1.0)
    df["partition"] = splits.assign_time_split(df["ts"])
    df.loc[df["is_ato"], "partition"] = "ato"
    ato_rows = df[(df["ts"] > "2020-09-05") & (df["cur_success"] == 1) & ~df["is_attack_ip"]].sample(40, random_state=1).index
    df.loc[ato_rows, "is_ato"] = True
    df.loc[ato_rows, "partition"] = "ato"
    df.loc[ato_rows, "llr_sum"] += 3.0  # ATO có điểm cao hơn
    df.loc[df["is_attack_ip"], "llr_sum"] += 1.0
    df.loc[df["in_warmup"], "partition"] = "train"
    return df


@pytest.fixture(scope="module")
def tasks():
    return E.build_tasks(make_table())


def test_expected_tasks_exist_without_attackers(tasks):
    assert set(tasks) == {"attack_ip/val", "attack_ip/test", "attack_ip/late", "ato/future", "ato/all"}


def test_ato_negatives_are_legit_successful_logins_only(tasks):
    frame = tasks["ato/future"].frame
    negatives = frame[~frame["y"]]
    assert (negatives["cur_success"] == 1).all() and not negatives["is_attack_ip"].any() and not negatives["is_ato"].any()
    assert set(negatives["partition"]) == {"test"}
    positives = frame[frame["y"]]
    assert positives["is_ato"].all() and (positives["ts"] >= splits.VAL_END).all() and (positives["ts"] < splits.TEST_END).all()


def test_attack_ip_task_uses_weights_and_clusters_by_ip(tasks):
    frame = tasks["attack_ip/test"].frame
    assert set(frame["partition"]) == {"test"}
    assert frame.loc[frame["y"], "cluster"].isin(frame["ip"]).all()


def test_warmup_rows_are_excluded_everywhere():
    df = make_table()
    df.loc[df.index[:500], "in_warmup"] = True
    tasks = E.build_tasks(df)
    warm_ids = set(df.loc[df["in_warmup"], "row_id"])
    for task in tasks.values():
        assert not (set(task.frame["row_id"]) & warm_ids)


def test_evaluate_task_reports_all_metrics_with_intervals_and_history_buckets(tasks):
    result = E.evaluate_task(tasks["ato/future"], lambda f: f["llr_sum"].to_numpy(), n_boot=40)
    assert result["n_pos"] > 0 and result["n_neg"] > 0
    for name in ("roc_auc", "pr_auc", "recall@fpr=0.01", "recall@fpr=0.001", "reauth@tpr=0.9", "reauth@tpr=0.99"):
        assert set(result["metrics"][name]) == {"value", "ci95"}
    assert result["metrics"]["roc_auc"]["value"] > 0.8  # ATO có điểm cao hơn hẳn trong dữ liệu tổng hợp
    assert [b["bucket"] for b in result["by_history"]] == [b[0] for b in E.HISTORY_BUCKETS]


def test_history_breakdown_uses_one_global_threshold(tasks):
    frame = tasks["ato/all"].frame
    score = frame["llr_sum"].to_numpy()
    rows = E.breakdown_by_history(frame, score, None, fpr_target=0.05)
    total_neg = (~frame["y"]).sum()
    flagged = sum(r["false_alert_rate"] * r["n_neg"] for r in rows if r["n_neg"])
    assert flagged / total_neg <= 0.05 + 1e-9  # tổng FPR tại ngưỡng chung không vượt mục tiêu


def test_random_scorer_gets_chance_level_on_every_task(tasks):
    from ml.rba.scorers import random_scorer

    for name in ("attack_ip/test", "ato/all"):
        result = E.evaluate_task(tasks[name], random_scorer(3), n_boot=20)
        assert result["metrics"]["roc_auc"]["value"] == pytest.approx(0.5, abs=0.12)


def test_markdown_report_has_one_row_per_task(tasks):
    report = E.run_report("demo", lambda f: f["llr_sum"].to_numpy(), {k: tasks[k] for k in ("attack_ip/test", "ato/future")}, n_boot=20)
    text = E.to_markdown(report)
    assert "`attack_ip/test`" in text and "`ato/future`" in text and "Recall@FPR 1%" in text


def test_alert_volume_scales_sample_back_to_population_and_grows_with_recall(tasks):
    frame = tasks["attack_ip/test"].frame.copy()
    frame["stratum"] = np.where(frame["u_n_success"] > 5, "heavy", "light")
    frame["forced"] = False
    score = frame["llr_sum"].to_numpy()
    v90, v99 = E.alert_volume(frame, score, 0.90), E.alert_volume(frame, score, 0.99)
    assert v99["alerts_per_1000_logins"] > v90["alerts_per_1000_logins"] > 0
    assert v99["alerts_per_day"] > v90["alerts_per_day"] > 0
    # dòng "heavy" mang trọng số 1/0,25 và dòng "light" 1/0,10 (cùng weight thô)
    rates = E.population_weights(frame.iloc[:2].assign(weight=1.0, stratum=["heavy", "light"], forced=False))
    assert list(rates) == [4.0, 10.0]
    forced = E.population_weights(frame.iloc[:1].assign(weight=1.0, stratum="heavy", forced=True))
    assert list(forced) == [1.0]


def test_comparison_markdown_puts_every_scorer_side_by_side_per_task(tasks):
    from ml.rba.report import comparison_markdown

    subset = {k: tasks[k] for k in ("attack_ip/test", "ato/future")}
    reports = [
        E.run_report("mo_hinh_a", lambda f: f["llr_sum"].to_numpy(), subset, n_boot=15),
        E.run_report("mo_hinh_b", lambda f: -f["llr_sum"].to_numpy(), subset, n_boot=15),
    ]
    text = comparison_markdown(reports)
    assert text.count("#### `attack_ip/test`") == 1 and text.count("#### `ato/future`") == 1
    assert text.count("`mo_hinh_a`") == 2 and text.count("`mo_hinh_b`") == 2  # mỗi mô hình một dòng ở mỗi bảng
    assert "Xác thực lại @TPR 99%" in text
