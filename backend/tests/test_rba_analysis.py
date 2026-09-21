"""MR6 — phân tích chuyển ngưỡng và hiệu chỉnh xác suất (dữ liệu tổng hợp nhỏ)."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import analysis as An
from ml.rba import eval_tasks as E
from ml.rba import splits


def make_df(n=20000, seed=0, shift_late=0.0):
    rng = np.random.default_rng(seed)
    ts = pd.Timestamp("2020-03-01") + pd.to_timedelta(rng.integers(0, 350 * 24 * 3600, n), unit="s")  # tới 02/2021: có đủ train/val/test/late
    df = pd.DataFrame(
        {
            "row_id": np.arange(n), "ts": ts, "user_id": rng.integers(0, 3000, n), "ip": [f"1.2.{i % 250}.{i % 200}" for i in range(n)],
            "cur_success": (rng.random(n) < 0.8).astype(float), "is_attack_ip": rng.random(n) < 0.06, "is_ato": False,
            "in_warmup": False, "u_n_success": rng.integers(0, 12, n).astype(float),
        }
    )
    df["weight"] = np.where(df["is_attack_ip"], 5.0, 1.0)
    df["partition"] = splits.assign_time_split(df["ts"])
    df["score_true"] = rng.normal(0, 1, n) + 2.0 * df["is_attack_ip"]
    df.loc[df["partition"] == "late", "score_true"] += shift_late  # trôi phân phối: điểm của người hợp lệ tăng lên
    ato_rows = df[(df["ts"] > "2020-09-05") & (df["cur_success"] == 1) & ~df["is_attack_ip"]].sample(40, random_state=1).index
    df.loc[ato_rows, "is_ato"] = True
    df.loc[ato_rows, "partition"] = "ato"
    df.loc[ato_rows, "score_true"] += 3.0
    return E.add_population_weights(df)


def score(frame):
    return frame["score_true"].to_numpy()


def test_transfer_realizes_the_target_when_the_distribution_is_stable():
    df = make_df(n=60000)
    tasks = E.build_tasks(df)
    rows = An.transfer_table(score, tasks, df)
    ip_rows = [r for r in rows if r["family"] == "IP tấn công" and r["target"] == "attack_ip/test" and r["target_fpr"] == 0.01]
    assert len(ip_rows) == 1
    assert ip_rows[0]["fpr"] == pytest.approx(0.01, abs=0.005) and 0.3 < ip_rows[0]["recall"] < 1.0


def test_transfer_exposes_distribution_shift_in_the_late_period():
    df = make_df(n=60000, shift_late=1.0)
    tasks = E.build_tasks(df)
    rows = An.transfer_table(score, tasks, df)
    late = next(r for r in rows if r["target"] == "attack_ip/late" and r["target_fpr"] == 0.01)
    test = next(r for r in rows if r["target"] == "attack_ip/test" and r["target_fpr"] == 0.01)
    assert late["fpr"] > 2 * test["fpr"]  # cùng ngưỡng nhưng người hợp lệ giai đoạn late bị báo nhầm nhiều hơn hẳn


def test_transfer_covers_every_family_and_target_fpr():
    df = make_df(n=40000)
    tasks = E.build_tasks(df)
    rows = An.transfer_table(score, tasks, df)
    assert {r["family"] for r in rows} == {"IP tấn công", "ATO thật"}  # không có bài attacker/* vì không truyền kẻ tấn công
    assert {r["target_fpr"] for r in rows} == set(An.FPR_TARGETS)
    assert {r["target"] for r in rows if r["family"] == "ATO thật"} == {"ato/future", "ato/all"}


def test_calibration_report_improves_on_a_constant_guess_and_has_ordered_deciles():
    df = make_df(n=80000)
    tasks = E.build_tasks(df)
    report = An.calibration_report("gbm_demo", score, tasks, bins=10)
    for info in report["periods"].values():
        assert info["brier_calibrated"] < info["brier_constant"]
        observed = [r["observed"] for r in info["reliability"]]
        assert observed[-1] > observed[0]  # nhóm xác suất cao có tỉ lệ tấn công thực cao hơn nhóm thấp
        assert sum(r["weight_share"] for r in info["reliability"]) == pytest.approx(1.0)


def test_markdown_renderers_contain_the_key_numbers():
    df = make_df(n=40000)
    tasks = E.build_tasks(df)
    text = An.transfer_markdown("demo", An.transfer_table(score, tasks, df))
    assert "`demo`" in text and "FPR thực tế" in text and "attack_ip/late" in text
    cal = An.calibration_markdown(An.calibration_report("gbm_demo", score, tasks))
    assert "Brier" in cal and "attack_ip/test" in cal


def test_hybrid_attribution_splits_alerts_and_false_alarms_by_component():
    from ml.rba import ensemble as En

    df = make_df(n=60000, seed=5)
    tasks = E.build_tasks(df)
    val = df[(df["partition"] == "val") & ~df["in_warmup"] & ~df["is_attack_ip"] & ~df["is_ato"]]

    def noise(frame):  # thành phần không mang thông tin: nhiễu tất định theo row_id
        return np.sin(frame["row_id"].to_numpy() * 12.9898) * 43758.5453 % 1.0

    components = []
    for name, scorer in (("co_tin_hieu", score), ("nhieu", noise)):
        calibrator = En.EcdfCalibrator.fit(scorer(val), val["pop_weight"].to_numpy())
        components.append(En.Component(name, scorer, calibrator))
    hybrid = En.HybridMinTail(components)

    rows = An.hybrid_attribution(hybrid, tasks, df, target_fpr=0.01)
    negative, positives = rows[0], {r["task"]: r for r in rows[1:]}
    assert negative["task"] == "val/legit_success" and negative["recall"] is None
    assert negative["fpr"] == pytest.approx(0.01, abs=0.004)
    assert sum(negative["by_component"].values()) == pytest.approx(negative["fpr"])  # mỗi báo nhầm thuộc đúng một thành phần
    ip = positives["attack_ip/test"]
    assert ip["recall"] > 0.2
    assert sum(ip["by_component"].values()) == pytest.approx(ip["recall"])
    assert ip["by_component"]["co_tin_hieu"] > 5 * ip["by_component"]["nhieu"]  # thành phần có tín hiệu gánh gần hết ca bắt được
    text = An.attribution_markdown(rows, 0.01)
    assert "`co_tin_hieu`" in text and "val/legit_success" in text and "FPR 1.0%" in text
