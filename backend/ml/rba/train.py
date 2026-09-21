"""Huấn luyện và lưu mọi mô hình của MR6:  python -m ml.rba.train

Thứ tự: (1) LightGBM nhãn IP tấn công, (2) LightGBM kẻ tấn công mô phỏng, (3) LightGBM gộp hai nguồn dương tính
(chọn tỉ trọng rho trên val), (4) biến thể chỉ dùng đặc trưng toàn cục (để đo giá trị của cá nhân hoá), (5) kNN-distance,
Autoencoder, Isolation Forest, (6) hybrid "bất kỳ bộ phát hiện nào báo động" với hiệu chỉnh trên val.

Quy tắc chống rò rỉ: mô hình học từ `train`; dừng sớm, chọn rho và hiệu chỉnh chỉ dùng `val`; 141 ATO thật không bao
giờ được đưa vào (kể cả để chọn). Kết quả và thời gian ghi ở backend/ml/artifacts/rba/train_report.json.
"""

from __future__ import annotations

import json
import sys
import time

import joblib
import numpy as np
import pandas as pd

from ml.rba import baselines, eval_tasks, models
from ml.rba import ensemble as En
from ml.rba.eval_tasks import ATTACKERS_TRAINVAL_PARQUET
from ml.rba.features import FEATURE_NAMES

RHO_GRID = (0.25, 1.0)
SELECTION_TASKS = ("attack_ip/val", "attacker_val/naive", "attacker_val/vpn", "attacker_val/targeted")


def load_inputs() -> tuple[pd.DataFrame, pd.DataFrame]:
    df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
    trainval = pd.read_parquet(ATTACKERS_TRAINVAL_PARQUET).assign(pop_weight=1.0)
    return df, trainval


def selection_tasks(df: pd.DataFrame, trainval: pd.DataFrame) -> dict[str, eval_tasks.Task]:
    tasks = eval_tasks.build_tasks(df, None, trainval[trainval["period"] == "val"])
    return {name: tasks[name] for name in SELECTION_TASKS}


def selection_score(scorer, tasks: dict[str, eval_tasks.Task]) -> dict:
    """Chỉ số dùng để CHỌN mô hình (chỉ trên val): trung bình của AP bài IP tấn công và recall@FPR 1% của 3 kiểu kẻ tấn công."""
    scores = eval_tasks.score_all_tasks(scorer, tasks)
    per_task = {name: eval_tasks.point_metrics(task, scores[name]) for name, task in tasks.items()}
    ap = per_task["attack_ip/val"]["pr_auc"]
    recalls = [per_task[f"attacker_val/{k}"]["recall@fpr=0.01"] for k in ("naive", "vpn", "targeted")]
    return {"selection": 0.5 * ap + 0.5 * float(np.mean(recalls)), "attack_ip_ap": ap, "attacker_recall_fpr1": recalls, "per_task": per_task}


def _val_reference(df: pd.DataFrame, success_only: bool) -> pd.DataFrame:
    val = df[(df["partition"] == "val") & ~df["in_warmup"] & ~df["is_attack_ip"] & ~df["is_ato"]]
    return val[val["cur_success"] == 1] if success_only else val


def build_hybrid(df: pd.DataFrame, components: list[tuple[str, object, object]]) -> En.HybridMinTail:
    """components: (tên, mô hình, cổng hoặc None). Hiệu chỉnh trên đăng nhập hợp lệ của val QUA CỔNG của chính nó."""
    built = []
    for name, scorer, gate in components:
        reference = _val_reference(df, success_only=False)
        if gate is not None:
            reference = reference[gate(reference)]
        calibrator = En.EcdfCalibrator.fit(scorer(reference), reference["pop_weight"].to_numpy())
        built.append(En.Component(name, scorer, calibrator, gate))
    return En.HybridMinTail(built)


def train_all(df: pd.DataFrame, trainval: pd.DataFrame, quick: bool = False) -> dict:
    out = models.ARTIFACT_DIR
    out.mkdir(parents=True, exist_ok=True)
    sel_tasks = selection_tasks(df, trainval)
    report: dict = {"rho_grid": list(RHO_GRID), "models": {}}
    started = time.time()

    def say(message: str) -> None:
        print(f"  [{time.time() - started:6.0f}s] {message}", flush=True)

    rounds = 60 if quick else 1500
    gbm_kwargs = {"rounds": rounds}

    say("LightGBM nhãn IP tấn công")
    ip_train, ip_val = models.attack_ip_sets(df)
    gbm_ip = models.train_gbm("gbm_attack_ip", FEATURE_NAMES, ip_train, ip_val, **gbm_kwargs)
    gbm_ip.save(out)
    report["models"]["gbm_attack_ip"] = {**gbm_ip.meta, "selection": selection_score(gbm_ip, sel_tasks)}

    say("LightGBM kẻ tấn công mô phỏng")
    sim_train, sim_val = models.simulated_attacker_sets(df, trainval)
    gbm_sim = models.train_gbm("gbm_attacker_sim", FEATURE_NAMES, sim_train, sim_val, **gbm_kwargs)
    gbm_sim.save(out)
    report["models"]["gbm_attacker_sim"] = {**gbm_sim.meta, "selection": selection_score(gbm_sim, sel_tasks)}

    say("LightGBM gộp hai nguồn dương tính (chọn rho trên val)")
    best = None
    grid = {}
    for rho in RHO_GRID:
        train_set, val_set = models.combined_sets(df, trainval, rho=rho)
        candidate = models.train_gbm(f"gbm_combined_rho{rho:g}", FEATURE_NAMES, train_set, val_set, **gbm_kwargs)
        score = selection_score(candidate, sel_tasks)
        grid[f"{rho:g}"] = {"selection": score["selection"], "attack_ip_ap": score["attack_ip_ap"], "attacker_recall_fpr1": score["attacker_recall_fpr1"]}
        say(f"  rho={rho:g}: điểm chọn {score['selection']:.4f}")
        if best is None or score["selection"] > best[0]:
            best = (score["selection"], rho, candidate, score)
    _, rho, combined, combined_score = best
    combined.name = "gbm_combined"
    combined.meta["name"], combined.meta["chosen_rho"] = "gbm_combined", rho
    combined.save(out)
    report["models"]["gbm_combined"] = {**combined.meta, "selection": combined_score, "rho_grid_results": grid}

    say("LightGBM gộp — chỉ đặc trưng toàn cục (đo giá trị của cá nhân hoá)")
    train_set, val_set = models.combined_sets(df, trainval, rho=rho)
    global_only = models.train_gbm("gbm_combined_global", models.GLOBAL_ONLY_FEATURES, train_set, val_set, **gbm_kwargs)
    global_only.save(out)
    report["models"]["gbm_combined_global"] = {**global_only.meta, "selection": selection_score(global_only, sel_tasks)}

    say("kNN-distance, Autoencoder, Isolation Forest")
    knn = models.KnnDistanceScorer().fit(df)
    ae = models.AutoencoderScorer(max_iter=8 if quick else 40).fit(df)
    forest = baselines.IsolationForestScorer().fit(df)
    for name, scorer in (("knn_distance", knn), ("autoencoder", ae), ("isolation_forest", forest)):
        joblib.dump(scorer, out / f"{name}.joblib")
        report["models"][name] = {"selection": selection_score(scorer, sel_tasks)}
        say(f"  {name}: điểm chọn {report['models'][name]['selection']['selection']:.4f}")

    say("hybrid: bất kỳ bộ phát hiện nào báo động")
    hybrid = build_hybrid(df, [("ip_tan_cong", gbm_ip, None), ("chiem_tai_khoan", gbm_sim, En.gate_success_with_history), ("bat_thuong", forest, En.gate_success)])
    joblib.dump(hybrid, out / "hybrid.joblib")
    report["models"]["hybrid"] = {"selection": selection_score(hybrid, sel_tasks)}

    (out / "train_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    say("xong")
    return report


def main() -> int:
    quick = "--quick" in sys.argv
    for path in (eval_tasks.MODEL_TABLE_PARQUET, ATTACKERS_TRAINVAL_PARQUET):
        if not path.is_file():
            print(f"Thiếu {path} — chạy `python -m ml.rba.build_features` và `python -m ml.rba.attackers --period trainval` trước.")
            return 1
    df, trainval = load_inputs()
    report = train_all(df, trainval, quick=quick)
    print("\nĐiểm chọn mô hình trên VAL (0,5·AP IP tấn công + 0,5·recall@FPR1% trung bình 3 kẻ tấn công mô phỏng):")
    for name, info in report["models"].items():
        s = info["selection"]
        print(f"  {name:22s} chọn {s['selection']:.4f} | AP IP {s['attack_ip_ap']:.3f} | recall@1% naive/vpn/targeted "
              + "/".join(f"{r:.1%}" for r in s["attacker_recall_fpr1"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
