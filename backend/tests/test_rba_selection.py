"""MR8b — chốt mô hình ở CP2: loại trừ lùi có kiểm định ghép cặp, tập chọn ATO quá khứ, đặc trưng quan hệ với lịch sử, huấn luyện mô hình cuối."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import eval_tasks
from ml.rba import explain as Ex
from ml.rba import models as Mo
from ml.rba import scorers
from ml.rba import selection as Se
from ml.rba import splits
from ml.rba.features import FEATURE_GROUPS, FEATURE_NAMES
from tests.test_rba_explain_eval import make_attackers, make_frame

TINY_FOREST = dict(n_estimators=20, max_samples=256, sample_rows=3000)


def synthetic_task(n=3000, positives=150, seed=0):
    rng = np.random.default_rng(seed)
    y = np.zeros(n, dtype=bool)
    y[rng.choice(n, positives, replace=False)] = True
    frame = pd.DataFrame({"y": y, "pop_weight": 1.0, "cluster": np.where(y, rng.integers(0, positives // 2, n), np.arange(n) + 10_000)})
    return eval_tasks.Task("t", "tổng hợp", frame), rng


# ------------------------------------------------------------------------------------------------ nhóm đặc trưng


def test_groups_keep_feature_order_and_the_user_relative_set_leaves_out_infrastructure():
    assert Se.groups_features(("infra_ip", "cur")) == [f for f in FEATURE_NAMES if f in FEATURE_GROUPS["cur"] + FEATURE_GROUPS["infra_ip"]]
    assert Se.groups_features(tuple(FEATURE_GROUPS)) == FEATURE_NAMES
    relative = Se.USER_RELATIVE_FEATURES
    assert len(relative) == 28 and relative == [f for f in FEATURE_NAMES if f in relative]  # đúng thứ tự
    assert {"new_ip", "llr_sum", "u_secs_since_last_success", "u_age_days"} <= set(relative)
    assert not any(f.startswith(("rare_", "ip_", "asn_", "cur_")) for f in relative)  # hạ tầng, độ hiếm, sự kiện hiện tại đều đã bỏ


# ------------------------------------------------------------------------------------------------ bootstrap ghép cặp


def test_paired_bootstrap_sees_a_real_improvement_and_nothing_between_identical_scorers():
    task, rng = synthetic_task()
    y, w, c = (task.frame[k].to_numpy() for k in ("y", "pop_weight", "cluster"))
    weak = rng.normal(size=len(y)) + 0.5 * y
    strong = weak + 1.5 * y
    better = Se.paired_bootstrap(y, weak, strong, w, c, "roc_auc", n_boot=200)
    assert better.mean() > 0.05 and np.quantile(better, 0.05) > 0  # tốt hơn thật: cận dưới một phía 95% dương
    worse = Se.paired_bootstrap(y, strong, weak, w, c, "roc_auc", n_boot=200)
    assert np.quantile(worse, 0.95) < 0
    assert np.array_equal(Se.paired_bootstrap(y, weak, weak, w, c, "pr_auc", n_boot=50), np.zeros(50))  # cùng điểm: hiệu số đúng bằng 0
    again = Se.paired_bootstrap(y, weak, strong, w, c, "recall@fpr=0.01", n_boot=50, seed=3)
    assert np.array_equal(again, Se.paired_bootstrap(y, weak, strong, w, c, "recall@fpr=0.01", n_boot=50, seed=3))  # hạt giống cố định


# ------------------------------------------------------------------------------------------------ loại trừ lùi


def test_backward_selection_drops_the_group_that_hurts_and_stops_when_nothing_helps():
    task, rng = synthetic_task(n=4000, positives=200, seed=1)
    y = task.frame["y"].to_numpy()
    parts = {"good1": rng.normal(size=len(y)) + 1.5 * y, "good2": rng.normal(size=len(y)) + 1.0 * y, "junk": rng.normal(scale=6.0, size=len(y)), "neutral": np.zeros(len(y))}
    calls = []

    def score_fn(kept):
        calls.append(kept)
        return sum(parts[g] for g in kept)

    result = Se.backward_select(score_fn, task, groups=("good1", "good2", "junk", "neutral"), metric="roc_auc", max_rounds=3, n_boot=100, log=lambda m: None)
    assert result["rounds"][0]["accepted"] == "junk"  # nhóm chỉ thêm nhiễu bị bỏ ở vòng 1
    assert result["rounds"][1]["accepted"] is None and len(result["rounds"]) == 2  # vòng 2: bỏ neutral không đổi gì, bỏ nhóm tốt thì hại -> dừng
    assert result["selected_groups"] == ["good1", "good2", "neutral"]
    first = {c["dropped"]: c for c in result["rounds"][0]["candidates"]}
    assert first["junk"]["lower"] > 0 and first["good1"]["lower"] < 0 and first["good2"]["lower"] < 0 and first["neutral"]["lower"] <= 0
    assert first["junk"]["diff"] > 0.05 and first["good1"]["diff"] < 0 and abs(first["neutral"]["diff"]) < 0.01
    assert len(calls) == len(set(calls)) == 8  # mỗi cấu hình chỉ huấn luyện một lần (bộ nhớ đệm): 5 ở vòng 1 + 3 mới ở vòng 2
    assert result["n_pos"] == 200 and result["metric"] == "roc_auc"


def test_backward_selection_respects_the_round_limit_and_keeps_everything_when_differences_are_noise():
    task, rng = synthetic_task(seed=2)
    y = task.frame["y"].to_numpy()
    base = rng.normal(size=len(y)) + 1.0 * y
    parts = {g: rng.normal(scale=0.02, size=len(y)) for g in ("a", "b", "c")}  # ba nhóm chỉ thêm nhiễu cực nhỏ
    result = Se.backward_select(lambda kept: base + sum(parts[g] for g in kept), task, groups=("a", "b", "c"), metric="roc_auc", n_boot=100, log=lambda m: None)
    assert result["selected_groups"] == ["a", "b", "c"] and len(result["rounds"]) == 1 and result["rounds"][0]["accepted"] is None

    parts2 = {"good1": rng.normal(size=len(y)) + 1.5 * y, "good2": rng.normal(size=len(y)) + 1.0 * y, "junkA": rng.normal(scale=6.0, size=len(y)), "junkB": rng.normal(scale=1.0, size=len(y))}
    limited = Se.backward_select(lambda kept: sum(parts2[g] for g in kept), task, groups=tuple(parts2), metric="roc_auc", max_rounds=1, n_boot=100, log=lambda m: None)
    assert len(limited["rounds"]) == 1 and limited["rounds"][0]["accepted"] == "junkA"
    assert limited["selected_groups"] == ["good1", "good2", "junkB"]  # hết số vòng thì dừng, dù còn nhóm nhiễu nhỏ


# ------------------------------------------------------------------------------------------------ tập chọn ATO quá khứ


def test_past_ato_task_has_only_past_cases_and_val_negatives():
    df = make_frame(n=9000, seed=4)
    rng = np.random.default_rng(4)
    early = df[(df["ts"] < splits.VAL_END) & (df["cur_success"] == 1) & ~df["is_attack_ip"]].index.to_numpy()
    picks = rng.choice(early, 30, replace=False)
    df.loc[picks, ["is_ato", "partition"]] = [True, "ato"]
    df.loc[picks[:5], "in_warmup"] = True  # 5 ca warm-up: không tính
    future = int(df["is_ato"].sum()) - 30
    assert future == 40  # 40 ATO ở giai đoạn test do make_frame cài sẵn

    task = Se.past_ato_task(eval_tasks.add_population_weights(df))
    frame = task.frame
    positives, negatives = frame[frame["y"]], frame[~frame["y"]]
    assert len(positives) == 25 and (positives["ts"] < splits.VAL_END).all() and not positives["in_warmup"].any()
    assert (negatives["partition"] == "val").all() and (negatives["cur_success"] == 1).all() and not negatives["is_attack_ip"].any() and not negatives["is_ato"].any()
    assert set(positives["row_id"]).isdisjoint(set(df[df["is_ato"] & (df["ts"] >= splits.VAL_END)]["row_id"]))  # ATO tương lai không lọt vào
    assert {"y", "cluster", "pop_weight"} <= set(frame.columns) and "25 ATO quá khứ" in task.description


# ------------------------------------------------------------------------------------------------ hai cuộc chọn và mô hình cuối


@pytest.fixture(scope="module")
def world():
    df = make_frame(n=14000, seed=0)
    rng = np.random.default_rng(9)
    early = df[(df["ts"] < splits.VAL_END) & (df["cur_success"] == 1) & ~df["is_attack_ip"]].index.to_numpy()
    picks = rng.choice(early, 30, replace=False)
    df.loc[picks, ["is_ato", "partition"]] = [True, "ato"]
    df.loc[picks, "rare_asn"] += 12.0
    df.loc[picks, "rare_country"] += 12.0
    return eval_tasks.add_population_weights(df)


def test_forest_selection_returns_a_well_formed_result_on_past_ato_only(world):
    result = Se.select_forest_groups(world, log=lambda m: None, n_boot=30, max_rounds=1, **TINY_FOREST)
    assert result["n_pos"] == 30 and result["metric"] == "recall@fpr=0.01" and len(result["rounds"]) == 1
    first = result["rounds"][0]
    assert len(first["candidates"]) == len(Se.ALL_GROUPS) and {c["dropped"] for c in first["candidates"]} == set(Se.ALL_GROUPS)
    assert set(result["selected_groups"]) <= set(Se.ALL_GROUPS) and 0.0 <= first["control"]["recall@fpr=0.01"] <= 1.0
    assert first["control"]["roc_auc"] > 0.8  # ATO cài sẵn nhà mạng/quốc gia cực hiếm: rừng cô lập (chỉ 20 cây) vẫn phải thấy
    text = Se.selection_markdown(result, "Isolation Forest")
    assert "Bỏ nhóm" in text and "Kết quả: giữ" in text  # bảng dựng được


def test_attack_ip_selection_scores_on_validation_and_can_only_drop_groups(world):
    result = Se.select_attack_ip_groups(world, log=lambda m: None, n_boot=30, rounds=25, max_rounds=1)
    assert result["metric"] == "pr_auc" and result["n_pos"] > 50
    assert result["rounds"][0]["control"]["pr_auc"] > 0.3  # tín hiệu cài sẵn ở ip_distinct_users_24h và rare_asn
    accepted = result["rounds"][0]["accepted"]
    assert (accepted is None) == (result["selected_groups"] == list(Se.ALL_GROUPS))
    for c in result["rounds"][0]["candidates"]:
        assert (c["lower"] > 0) or c["dropped"] != accepted  # chỉ nhận nhóm có cận dưới dương


def _save_mr6_baseline(world, directory):
    """Bản MR6 của gbm_attack_ip (50 đặc trưng) mà `train_final` nạp làm đối chứng và làm phương án dự phòng khi bị phủ quyết."""
    ip_train, ip_val = Mo.attack_ip_sets(world)
    Mo.train_gbm("gbm_attack_ip", FEATURE_NAMES, ip_train, ip_val, params={"num_threads": 2, "num_leaves": 15, "min_data_in_leaf": 20}, rounds=40, early_stopping=10).save(directory)


ALL_MINUS_ASN = tuple(g for g in Se.ALL_GROUPS if g != "infra_asn")
FOREST_GROUPS = ("novelty", "freeman", "rarity", "infra_asn")


def test_final_models_use_the_chosen_features_and_are_saved_with_the_cp2_suffix(world, tmp_path, monkeypatch):
    monkeypatch.setattr(Mo, "ARTIFACT_DIR", tmp_path)
    _save_mr6_baseline(world, tmp_path)
    trainval = make_attackers(world, ("train", "val"), 600, seed=5)
    monkeypatch.setattr(Se, "late_guard", lambda *a, **k: {"old": 0.2, "new": 0.25, "upper": 0.08, "veto": False, "metric": "recall@fpr=0.01", "task": "attack_ip/late"})
    report = Se.train_final(world, trainval, FOREST_GROUPS, ALL_MINUS_ASN, log=lambda m: None, rounds=40, forest_kwargs=TINY_FOREST)
    assert report["features"] == {"gbm_attack_ip": len(Se.groups_features(ALL_MINUS_ASN)), "gbm_attacker_sim": 28, "isolation_forest": len(Se.groups_features(FOREST_GROUPS))}
    assert report["attack_ip_model"] == "gbm_attack_ip_cp2" and report["attack_ip_vetoed"] is False
    for name in ("gbm_attack_ip_cp2.txt", "gbm_attack_ip_cp2.json", "gbm_attacker_sim_cp2.txt", "isolation_forest_cp2.joblib", "hybrid_cp2.joblib"):
        assert (tmp_path / name).is_file(), name

    hybrid = scorers.SCORER_FACTORIES["hybrid_cp2"](world)
    ip, sim, forest = (c.scorer for c in hybrid.components)
    assert [c.name for c in hybrid.components] == ["ip_tan_cong", "chiem_tai_khoan", "bat_thuong"]
    assert ip.features == Se.groups_features(ALL_MINUS_ASN) and sim.features == Se.USER_RELATIVE_FEATURES and forest.feature_names() == Se.groups_features(FOREST_GROUPS)
    scores = hybrid(world.head(300))
    assert np.isfinite(scores).all() and scores.max() > scores.min()
    assert all(f in FEATURE_NAMES for f in sim.features) and "infra" not in "".join(sim.features)

    # giải thích vẫn chạy với thành phần bị bỏ nhóm đặc trưng: yếu tố không có đặc trưng thì không xuất hiện
    explainer = Ex.HybridExplainer(hybrid, Ex.ExplainReference.fit(world), threshold=0.5)
    explanations = explainer.explain(world[world["cur_success"] == 1].head(100))
    used = {f.concept for e in explanations for f in e.factors if e.component == "chiem_tai_khoan"}
    assert used and used <= {"quoc_gia", "nha_mang", "ip", "thiet_bi", "lich_su", "nhip", "that_bai"}  # không có hoat_dong_ip / hoat_dong_asn


def test_a_vetoed_candidate_is_saved_for_the_record_but_the_mr6_model_stays_in_the_hybrid(world, tmp_path, monkeypatch):
    monkeypatch.setattr(Mo, "ARTIFACT_DIR", tmp_path)
    _save_mr6_baseline(world, tmp_path)
    trainval = make_attackers(world, ("train", "val"), 400, seed=6)
    monkeypatch.setattr(Se, "late_guard", lambda *a, **k: {"old": 0.2, "new": 0.1, "upper": -0.03, "veto": True, "metric": "recall@fpr=0.01", "task": "attack_ip/late"})
    report = Se.train_final(world, trainval, FOREST_GROUPS, ALL_MINUS_ASN, log=lambda m: None, rounds=30, forest_kwargs=TINY_FOREST)
    assert report["attack_ip_vetoed"] is True and report["attack_ip_model"] == "gbm_attack_ip" and report["features"]["gbm_attack_ip"] == 50
    assert (tmp_path / "gbm_attack_ip_cp2.txt").is_file()  # ứng viên vẫn được lưu để tra cứu
    ip = scorers.SCORER_FACTORIES["hybrid_cp2"](world).components[0].scorer
    assert ip.features == FEATURE_NAMES and ip.name == "gbm_attack_ip"


def test_keeping_all_feature_groups_reuses_the_mr6_attack_ip_model_without_retraining(world, tmp_path, monkeypatch):
    monkeypatch.setattr(Mo, "ARTIFACT_DIR", tmp_path)
    _save_mr6_baseline(world, tmp_path)
    trainval = make_attackers(world, ("train", "val"), 400, seed=7)
    monkeypatch.setattr(Se, "late_guard", lambda *a, **k: pytest.fail("không đổi đặc trưng thì không cần phủ quyết"))
    report = Se.train_final(world, trainval, FOREST_GROUPS, Se.ALL_GROUPS, log=lambda m: None, rounds=30, forest_kwargs=TINY_FOREST)
    assert report["late_guard"] is None and report["attack_ip_model"] == "gbm_attack_ip" and not (tmp_path / "gbm_attack_ip_cp2.txt").exists()


def test_late_guard_vetoes_only_a_significant_loss_in_the_drift_period(world):
    good = Mo.train_gbm("g", FEATURE_NAMES, *Mo.attack_ip_sets(world), params={"num_threads": 2, "num_leaves": 15, "min_data_in_leaf": 20}, rounds=40, early_stopping=10)
    rng = np.random.default_rng(0)
    assert Se.late_guard(world, good, good, n_boot=60)["veto"] is False  # cùng mô hình: hiệu số 0
    worse = Se.late_guard(world, good, lambda frame: rng.random(len(frame)), n_boot=60)  # mô hình ngẫu nhiên tệ hơn hẳn
    assert worse["veto"] is True and worse["new"] < worse["old"] and worse["upper"] < 0 and worse["task"] == "attack_ip/late"
    better = Se.late_guard(world, lambda frame: rng.random(len(frame)), good, n_boot=60)  # đổi chiều: mới tốt hơn thì không phủ quyết
    assert better["veto"] is False and better["upper"] > 0


def test_cp2_models_are_registered_next_to_the_mr6_ones():
    for name in ("hybrid", "hybrid_cp2", "gbm_attack_ip_cp2", "gbm_attacker_sim_cp2", "isolation_forest_cp2"):
        assert name in scorers.SCORER_FACTORIES
