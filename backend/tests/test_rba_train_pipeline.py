"""MR6 — chạy thử toàn bộ quy trình huấn luyện trên dữ liệu tổng hợp nhỏ (bắt lỗi ghép nối trước khi chạy dữ liệu thật)."""

import json

import numpy as np
import pandas as pd
import pytest

from ml.rba import ensemble as En
from ml.rba import eval_tasks, models, splits, train
from ml.rba.features import FEATURE_NAMES
from ml.rba.scorers import SCORER_FACTORIES


def make_world(n=9000, seed=0):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({name: rng.gamma(2.0, 1.0, n) for name in FEATURE_NAMES})
    for name in [f"new_{a}" for a in ("country", "asn", "ip", "ua", "browser", "os", "device", "browser_family", "os_family")] + ["cur_success"]:
        df[name] = (rng.random(n) < 0.6).astype(float)
    df["cur_device_code"] = rng.integers(0, 6, n).astype(float)
    df["u_n_success"] = rng.integers(0, 12, n).astype(float)
    df["row_id"] = np.arange(n)
    df["user_id"] = rng.integers(0, 1500, n)
    df["ip"] = [f"9.9.{i % 200}.{i % 250}" for i in range(n)]
    df["ts"] = pd.Timestamp("2020-03-01") + pd.to_timedelta(rng.integers(0, 260 * 24 * 3600, n), unit="s")
    df["partition"] = splits.assign_time_split(df["ts"])
    df["is_attack_ip"] = rng.random(n) < 0.08
    df["is_ato"] = False
    df["in_warmup"] = False
    df["weight"] = np.where(df["is_attack_ip"], 4.0, 1.0)
    df.loc[df["is_attack_ip"], "rare_asn"] += 5.0
    df.loc[df["is_attack_ip"], "ip_distinct_users_24h"] += 8.0

    donors = df[(df["partition"].isin(["train", "val"])) & ~df["is_attack_ip"] & (df["cur_success"] == 1)].sample(900, random_state=1).copy()
    donors["row_id"] = 10**9 + np.arange(len(donors))
    donors["llr_country"] += 4.0
    donors["rare_country"] += 3.0
    donors["period"] = np.where(donors["partition"] == "train", "train", "val")
    donors["attacker_type"] = rng.choice(["naive", "vpn", "targeted"], len(donors))
    donors["partition"] = "attacker"
    donors["pop_weight"] = 1.0
    return eval_tasks.add_population_weights(df), donors


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    out = tmp_path_factory.mktemp("artifacts")
    original = (models.ARTIFACT_DIR, dict(models.DEFAULT_GBM_PARAMS))
    models.ARTIFACT_DIR = out
    models.DEFAULT_GBM_PARAMS.update({"min_data_in_leaf": 20, "num_leaves": 15, "num_threads": 2})
    try:
        df, attackers = make_world()
        report = train.train_all(df, attackers, quick=True)
    finally:
        models.ARTIFACT_DIR, models.DEFAULT_GBM_PARAMS = original[0], original[1]
    return out, df, attackers, report


def test_every_model_is_trained_saved_and_reported(trained):
    out, _, _, report = trained
    expected = {"gbm_attack_ip", "gbm_attacker_sim", "gbm_combined", "gbm_combined_global", "knn_distance", "autoencoder", "isolation_forest", "hybrid"}
    assert set(report["models"]) == expected
    for name in ("gbm_attack_ip", "gbm_attacker_sim", "gbm_combined", "gbm_combined_global"):
        assert (out / f"{name}.txt").exists() and (out / f"{name}.json").exists()
    for name in ("knn_distance", "autoencoder", "isolation_forest", "hybrid"):
        assert (out / f"{name}.joblib").exists()
    saved = json.loads((out / "train_report.json").read_text(encoding="utf-8"))
    assert saved["rho_grid"] == list(train.RHO_GRID)


def test_rho_is_chosen_from_the_grid_using_validation_only(trained):
    _, _, _, report = trained
    combined = report["models"]["gbm_combined"]
    assert combined["chosen_rho"] in train.RHO_GRID
    grid = combined["rho_grid_results"]
    best = max(grid, key=lambda k: grid[k]["selection"])
    assert float(best) == combined["chosen_rho"]


def test_global_only_model_uses_only_global_features(trained):
    out, *_ = trained
    loaded = models.GbmScorer.load("gbm_combined_global", out)
    assert set(loaded.features) == set(models.GLOBAL_ONLY_FEATURES)
    assert not any(f.startswith(("new_", "llr_", "u_")) for f in loaded.features)


def test_planted_signals_are_learned_by_the_matching_models(trained):
    _, df, attackers, report = trained
    assert report["models"]["gbm_attack_ip"]["selection"]["attack_ip_ap"] > 0.5  # IP tấn công có tín hiệu rõ
    recalls = report["models"]["gbm_attacker_sim"]["selection"]["attacker_recall_fpr1"]
    assert max(recalls) > 0.3  # kẻ tấn công mô phỏng có llr/rare_country cao


def test_hybrid_scores_every_task_row_and_names_its_trigger(trained):
    out, df, attackers, _ = trained
    import joblib

    hybrid = joblib.load(out / "hybrid.joblib")
    frame = df[df["partition"] == "val"].head(400)
    scores = hybrid(frame)
    assert len(scores) == 400 and not np.isnan(scores).any() and (scores >= 0).all()
    assert set(hybrid.triggered_by(frame)) <= {"ip_tan_cong", "chiem_tai_khoan", "bat_thuong"}
    failed = frame[frame["cur_success"] == 0]
    # cổng "thành công": với đăng nhập thất bại chỉ bộ phát hiện IP tấn công được phép báo động
    assert set(hybrid.triggered_by(failed)) <= {"ip_tan_cong", "chiem_tai_khoan", "bat_thuong"}
    assert (hybrid._tails(failed)[:, 1:] == 1.0).all()


def test_registry_loads_the_saved_artifacts_and_reports_missing_ones(trained, monkeypatch):
    out, df, attackers, _ = trained
    monkeypatch.setattr(models, "ARTIFACT_DIR", out)
    frame = df[df["partition"] == "val"].head(50)
    for name in ("gbm_attack_ip", "gbm_combined", "knn_distance", "hybrid"):
        scorer = SCORER_FACTORIES[name](df)
        assert len(scorer(frame)) == 50
    monkeypatch.setattr(models, "ARTIFACT_DIR", out / "khong_ton_tai")
    with pytest.raises(FileNotFoundError):
        SCORER_FACTORIES["gbm_attack_ip"](df)
