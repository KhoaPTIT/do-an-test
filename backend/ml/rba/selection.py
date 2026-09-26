"""Chốt mô hình ở CP2 (MR8b):  python -m ml.rba.selection [search|train|all]

Chủ dự án đã duyệt ba việc ở CP2 (docs/checklist.md, D1 và D2):

  D1. `gbm_attacker_sim` chỉ dùng nhóm đặc trưng QUAN HỆ VỚI LỊCH SỬ TÀI KHOẢN (`novelty`, `freeman`, `rhythm`, `history`; 28 đặc trưng).
      Không có tìm kiếm và không dựa vào kết quả huấn luyện: kiểm định dấu vân tay CÓ ĐIỀU KIỆN (ml/rba/audit.py `conditional`) cho thấy hạ
      tầng IP và độ hiếm còn tách được đăng nhập giả khỏi đăng nhập hợp lệ dùng IP mới; hai nhóm đó vốn do `ip_tan_cong` và `bat_thuong` đảm nhiệm.
  D2a. Isolation Forest (không nhãn): loại trừ lùi từng nhóm đặc trưng, đo trên 92 ca ATO QUÁ KHỨ (trước 09/2020) so với đăng nhập hợp lệ thành
      công của val. 38 ca ATO tương lai KHÔNG tham gia chọn (chỉ để báo cáo cuối) — nhưng đã bị nhìn ở MR7, phải ghi rõ khi báo cáo.
  D2b. `gbm_attack_ip`: cùng loại trừ lùi, đo bằng PR-AUC của nhãn IP tấn công trên val (không dùng ATO).

Loại trừ lùi (`backward_select`): mỗi vòng thử bỏ MỘT nhóm còn lại; nhận nhóm cho điểm tốt nhất chỉ khi hiệu số so với cấu hình hiện tại
DƯƠNG một cách có ý nghĩa (cận dưới một phía của bootstrap GHÉP CẶP trên cùng các cụm dương tính lấy lại mẫu > 0); dừng khi không còn nhóm nào
đạt hoặc hết số vòng tối đa (mặc định 2, mức 5%) để hạn chế chọn theo nhiễu của 92 ca.

PHỦ QUYẾT THEO `late` (`late_guard`, thêm SAU KHI đã thấy kết quả MR8b — nói rõ để chủ dự án có thể đảo lại): thay đổi đặc trưng chọn trên val bị loại nếu
recall@FPR 1% ở `attack_ip/late` (12/2020–02/2021, giai đoạn phân phối trôi, không dùng để chọn) giảm có ý nghĩa (cận trên một phía của hiệu số ghép cặp < 0).
Lý do: mục đích của `gbm_attack_ip` là chạy được nhiều tháng sau khi huấn luyện; cải thiện +0,007 PR-AUC trên một tháng val không đáng đổi lấy suy giảm khi trôi. Chỉ áp dụng
được cho `gbm_attack_ip` (Isolation Forest không có ATO ở `late`; `gbm_attacker_sim` không qua tìm kiếm).

⚠️ ATO của bộ RBA tổng hợp đến từ nhà mạng/quốc gia cực hiếm (dấu hiệu nhân tạo, docs/ml-holdout-ablation.md mục 5.1): chọn nhóm đặc trưng để bắt
ATO của bộ dữ liệu này thiên về nhóm phát hiện độ hiếm — kết quả chọn là đúng cho dữ liệu này, chưa chắc đúng ngoài đời.

Mô hình cuối lưu cùng thư mục với mô hình MR6 nhưng có hậu tố `_cp2` (`hybrid_cp2`, `gbm_attack_ip_cp2`, `gbm_attacker_sim_cp2`, `isolation_forest_cp2`)
để so trước/sau trong cùng một bảng (`python -m ml.rba.report ...`).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Callable, Sequence

import joblib
import numpy as np
import pandas as pd

from ml.rba import baselines, eval_tasks, models, splits, train
from ml.rba import ensemble as En
from ml.rba import metrics as M
from ml.rba.eval_tasks import ATTACKERS_TRAINVAL_PARQUET, Task
from ml.rba.features import FEATURE_GROUPS, FEATURE_NAMES

OUT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "rba_cp2"
SELECTION_JSON = OUT_DIR / "selection.json"
SUFFIX = "_cp2"
USER_RELATIVE_GROUPS = ("novelty", "freeman", "rhythm", "history")
ALL_GROUPS = tuple(FEATURE_GROUPS)
ALPHA = 0.05
MAX_ROUNDS = 2
N_BOOT = 300
FOREST_KWARGS = dict(n_estimators=100, max_samples=1024, sample_rows=200_000)  # như ablation MR7: nhẹ để thử nhiều cấu hình

METRICS: dict[str, Callable] = {
    "roc_auc": M.roc_auc,
    "pr_auc": M.average_precision,
    "recall@fpr=0.01": lambda ref, scores, weights: M.recall_at_fpr(ref, scores, weights, 0.01),
}


def groups_features(groups: Sequence[str]) -> list[str]:
    """Đặc trưng của các nhóm, giữ thứ tự FEATURE_NAMES."""
    wanted = {f for g in groups for f in FEATURE_GROUPS[g]}
    return [f for f in FEATURE_NAMES if f in wanted]


USER_RELATIVE_FEATURES = groups_features(USER_RELATIVE_GROUPS)


def _n_features(groups: Sequence[str]) -> int:
    return sum(len(FEATURE_GROUPS.get(g, ())) for g in groups)  # dung sai tên nhóm lạ để thử bằng dữ liệu tổng hợp


# ------------------------------------------------------------------------------------------ bootstrap ghép cặp


def _metric_value(metric: str, scores: np.ndarray, y: np.ndarray, weight: np.ndarray) -> float:
    ref = M.NegativeReference.build(scores[~y], weight[~y])
    return float(METRICS[metric](ref, scores[y], weight[y]))


def paired_bootstrap(
    y: np.ndarray, score_a: np.ndarray, score_b: np.ndarray, weight: np.ndarray, cluster: np.ndarray, metric: str, n_boot: int = N_BOOT, seed: int = 0
) -> np.ndarray:
    """Các giá trị `metric(b) − metric(a)` qua `n_boot` lần lấy lại mẫu CÙNG các cụm dương tính cho cả hai mô hình (ghép cặp: mô hình
    tốt hơn ở ca khó nào thì được ghi nhận ở đúng ca đó, nên hiệu số ổn định hơn hai khoảng tin cậy riêng lẻ). Như `metrics.evaluate`, chỉ lấy
    mẫu lại phía dương tính; tham chiếu âm tính cố định."""
    y = np.asarray(y, dtype=bool)
    weight = np.asarray(weight, dtype=float)
    ref_a = M.NegativeReference.build(score_a[~y], weight[~y])
    ref_b = M.NegativeReference.build(score_b[~y], weight[~y])
    pos_a, pos_b, pos_w = score_a[y], score_b[y], weight[y]
    _, pos_cluster = np.unique(np.asarray(cluster)[y], return_inverse=True)
    n_clusters = int(pos_cluster.max()) + 1
    order = np.argsort(pos_cluster, kind="stable")
    boundaries = np.searchsorted(pos_cluster[order], np.arange(n_clusters + 1))

    rng = np.random.default_rng(seed)
    fn = METRICS[metric]
    diffs = np.empty(n_boot)
    for i in range(n_boot):
        chosen = rng.integers(0, n_clusters, n_clusters)
        idx = np.concatenate([order[boundaries[c]:boundaries[c + 1]] for c in chosen])
        diffs[i] = fn(ref_b, pos_b[idx], pos_w[idx]) - fn(ref_a, pos_a[idx], pos_w[idx])
    return diffs


def backward_select(
    score_fn: Callable[[tuple[str, ...]], np.ndarray],
    task: Task,
    groups: Sequence[str] = ALL_GROUPS,
    metric: str = "recall@fpr=0.01",
    alpha: float = ALPHA,
    max_rounds: int = MAX_ROUNDS,
    n_boot: int = N_BOOT,
    log=print,
) -> dict:
    """Loại trừ lùi theo nhóm. `score_fn(nhóm_giữ_lại) -> điểm cho từng dòng của task.frame` (huấn luyện + chấm). Trả về mọi ứng viên đã thử ở
    mỗi vòng (giá trị, hiệu số so với cấu hình hiện tại, cận dưới một phía của hiệu số) và các nhóm được chọn giữ lại."""
    frame = task.frame
    y, weight, cluster = frame["y"].to_numpy(), frame["pop_weight"].to_numpy(dtype=float), frame["cluster"].to_numpy()
    cache: dict[tuple[str, ...], np.ndarray] = {}

    def scores(kept: tuple[str, ...]) -> np.ndarray:
        if kept not in cache:
            cache[kept] = np.asarray(score_fn(kept), dtype=float)
        return cache[kept]

    def all_values(s: np.ndarray) -> dict[str, float]:
        return {name: _metric_value(name, s, y, weight) for name in METRICS}

    current = tuple(groups)
    rounds = []
    for round_no in range(1, max_rounds + 1):
        control = scores(current)
        control_values = all_values(control)
        candidates = []
        for group in current:
            kept = tuple(g for g in current if g != group)
            if not kept:
                continue
            s = scores(kept)
            diffs = paired_bootstrap(y, control, s, weight, cluster, metric, n_boot, seed=round_no)
            values = all_values(s)
            candidates.append(
                {"dropped": group, "n_features": _n_features(kept), "values": values, "diff": values[metric] - control_values[metric], "lower": float(np.quantile(diffs, alpha))}
            )
            log(f"    vòng {round_no}: bỏ {group:12s} {metric} {values[metric]:.4f} (Δ {candidates[-1]['diff']:+.4f}, cận dưới {candidates[-1]['lower']:+.4f})")
        significant = [c for c in candidates if c["lower"] > 0]
        best = max(significant, key=lambda c: c["values"][metric]) if significant else None
        rounds.append(
            {"groups": list(current), "n_features": _n_features(current), "control": control_values, "candidates": candidates, "accepted": None if best is None else best["dropped"]}
        )
        if best is None:
            break
        current = tuple(g for g in current if g != best["dropped"])
    return {
        "metric": metric, "alpha": alpha, "max_rounds": max_rounds, "n_pos": int(y.sum()), "n_neg": int((~y).sum()),
        "rounds": rounds, "selected_groups": list(current),
    }


# ---------------------------------------------------------------------------------------- hai cuộc chọn


def past_ato_task(df: pd.DataFrame) -> Task:
    """Tập chọn ngoài cho Isolation Forest: ATO QUÁ KHỨ (trước `VAL_END`, không warm-up) so với đăng nhập hợp lệ thành công của val. ATO tương lai
    (09–11/2020) không có ở đây. Âm tính lấy ở val (Isolation Forest học từ train nên âm tính val là ngoài mẫu)."""
    frame = df[~df["in_warmup"]]
    ato = frame[frame["is_ato"] & (frame["ts"] < splits.VAL_END)]
    legit = frame[(frame["partition"] == "val") & eval_tasks._legit_success(frame)]
    both = pd.concat([legit, ato])
    return Task(
        "ato/past", f"{len(ato)} ATO quá khứ (trước 09/2020) so với đăng nhập hợp lệ thành công của val",
        eval_tasks._with_labels(both, both["is_ato"], both["user_id"]),
    )


def select_forest_groups(df: pd.DataFrame, log=print, n_boot: int = N_BOOT, max_rounds: int = MAX_ROUNDS, **kwargs) -> dict:
    task = past_ato_task(df)
    log(f"Isolation Forest — chọn nhóm đặc trưng trên {int(task.frame['y'].sum())} ca ATO quá khứ ({len(task.frame):,} dòng)")

    def score_fn(kept: tuple[str, ...]) -> np.ndarray:
        forest = baselines.IsolationForestScorer(features=groups_features(kept), **{**FOREST_KWARGS, **kwargs}).fit(df)
        return forest(task.frame)

    return backward_select(score_fn, task, metric="recall@fpr=0.01", n_boot=n_boot, max_rounds=max_rounds, log=log)


def select_attack_ip_groups(df: pd.DataFrame, log=print, n_boot: int = N_BOOT, rounds: int = 1500, max_rounds: int = MAX_ROUNDS) -> dict:
    task = eval_tasks.build_tasks(df)["attack_ip/val"]
    train_set, val_set = models.attack_ip_sets(df)
    log(f"gbm_attack_ip — chọn nhóm đặc trưng bằng PR-AUC trên val ({int(task.frame['y'].sum()):,} dòng IP tấn công, {len(task.frame):,} dòng)")

    def score_fn(kept: tuple[str, ...]) -> np.ndarray:
        model = models.train_gbm("sel_attack_ip", groups_features(kept), train_set, val_set, rounds=rounds)
        return model(task.frame)

    return backward_select(score_fn, task, metric="pr_auc", n_boot=n_boot, max_rounds=max_rounds, log=log)


def late_guard(df: pd.DataFrame, old_scorer, new_scorer, n_boot: int = N_BOOT, alpha: float = ALPHA) -> dict:
    """Phủ quyết theo `late`: recall@FPR 1% ở `attack_ip/late` của mô hình mới so với mô hình cũ, bootstrap ghép cặp theo IP. `veto` = mô hình mới tệ hơn có ý nghĩa
    (cận trên một phía 1 − alpha của hiệu số mới − cũ < 0)."""
    frame = eval_tasks.build_tasks(df)["attack_ip/late"].frame
    y, weight, cluster = frame["y"].to_numpy(), frame["pop_weight"].to_numpy(dtype=float), frame["cluster"].to_numpy()
    old, new = np.asarray(old_scorer(frame), dtype=float), np.asarray(new_scorer(frame), dtype=float)
    diffs = paired_bootstrap(y, old, new, weight, cluster, "recall@fpr=0.01", n_boot, seed=11)
    upper = float(np.quantile(diffs, 1 - alpha))
    return {
        "metric": "recall@fpr=0.01", "task": "attack_ip/late", "old": _metric_value("recall@fpr=0.01", old, y, weight), "new": _metric_value("recall@fpr=0.01", new, y, weight),
        "upper": upper, "veto": upper < 0,
    }


# ------------------------------------------------------------------------------------------ mô hình cuối


def train_final(df: pd.DataFrame, trainval: pd.DataFrame, forest_groups: Sequence[str], attack_ip_groups: Sequence[str], log=print, rounds: int = 1500, forest_kwargs: dict | None = None) -> dict:
    """Huấn luyện ba thành phần với đặc trưng đã chốt, dựng hybrid (hiệu chỉnh lại trên val), lưu với hậu tố `_cp2` cạnh mô hình MR6."""
    out = models.ARTIFACT_DIR
    out.mkdir(parents=True, exist_ok=True)
    started = time.time()

    ip_features = groups_features(attack_ip_groups)
    baseline_ip = models.GbmScorer.load("gbm_attack_ip")  # bản MR6, 50 đặc trưng (python -m ml.rba.train)
    guard = None
    if ip_features == list(FEATURE_NAMES):
        gbm_ip = baseline_ip  # cuộc chọn không bỏ nhóm nào: giữ nguyên bản MR6
        log(f"  [{time.time() - started:4.0f}s] gbm_attack_ip: giữ bản MR6 (không bỏ nhóm nào)")
    else:
        ip_train, ip_val = models.attack_ip_sets(df)
        candidate = models.train_gbm(f"gbm_attack_ip{SUFFIX}", ip_features, ip_train, ip_val, rounds=rounds)
        candidate.save(out)
        guard = late_guard(df, baseline_ip, candidate)
        gbm_ip = baseline_ip if guard["veto"] else candidate
        log(
            f"  [{time.time() - started:4.0f}s] ứng viên gbm_attack_ip{SUFFIX}: {len(ip_features)} đặc trưng, AP val {candidate.meta['val_average_precision']:.4f}; recall@1% ở late "
            f"{guard['old']:.1%} → {guard['new']:.1%} (cận trên hiệu số {guard['upper']:+.3f}) => " + ("PHỦ QUYẾT, giữ bản MR6" if guard["veto"] else "chấp nhận")
        )

    sim_train, sim_val = models.simulated_attacker_sets(df, trainval)
    gbm_sim = models.train_gbm(f"gbm_attacker_sim{SUFFIX}", USER_RELATIVE_FEATURES, sim_train, sim_val, rounds=rounds)
    gbm_sim.save(out)
    log(f"  [{time.time() - started:4.0f}s] gbm_attacker_sim{SUFFIX}: {len(USER_RELATIVE_FEATURES)} đặc trưng (quan hệ với lịch sử), AP val {gbm_sim.meta['val_average_precision']:.4f}")

    forest_features = groups_features(forest_groups)
    forest = baselines.IsolationForestScorer(features=forest_features, **(forest_kwargs or {})).fit(df)
    joblib.dump(forest, out / f"isolation_forest{SUFFIX}.joblib")
    log(f"  [{time.time() - started:4.0f}s] isolation_forest{SUFFIX}: {len(forest_features)} đặc trưng")

    hybrid = train.build_hybrid(
        df, [("ip_tan_cong", gbm_ip, None), ("chiem_tai_khoan", gbm_sim, En.gate_success_with_history), ("bat_thuong", forest, En.gate_success)]
    )
    joblib.dump(hybrid, out / f"hybrid{SUFFIX}.joblib")
    log(f"  [{time.time() - started:4.0f}s] hybrid{SUFFIX} đã dựng và hiệu chỉnh trên val")
    return {
        "attack_ip_groups_selected": list(attack_ip_groups), "forest_groups": list(forest_groups), "late_guard": guard,
        "attack_ip_model": gbm_ip.name, "attack_ip_vetoed": bool(guard and guard["veto"]),
        "features": {"gbm_attack_ip": len(gbm_ip.features), "gbm_attacker_sim": len(USER_RELATIVE_FEATURES), "isolation_forest": len(forest_features)},
        "val_average_precision": {"gbm_attack_ip": gbm_ip.meta["val_average_precision"], "gbm_attacker_sim": gbm_sim.meta["val_average_precision"]},
    }


# ------------------------------------------------------------------------------------------ bảng tài liệu


def selection_markdown(result: dict, title: str) -> str:
    """Bảng vòng đầu (mọi nhóm bỏ riêng lẻ) và các vòng tiếp theo nếu có."""
    metric = result["metric"]
    lines = [f"**{title}** — {result['n_pos']:,} ca dương, {result['n_neg']:,} âm; chỉ số chọn: `{metric}`; nhận nhóm khi cận dưới một phía {1 - result['alpha']:.0%} của hiệu số ghép cặp > 0", ""]
    for i, r in enumerate(result["rounds"], 1):
        control = r["control"]
        lines += [
            f"Vòng {i}: cấu hình hiện tại {len(r['groups'])} nhóm ({r['n_features']} đặc trưng) — `{metric}` {control[metric]:.4f}, ROC-AUC {control['roc_auc']:.4f}, PR-AUC {control['pr_auc']:.4f}, recall@1% {control['recall@fpr=0.01']:.1%}",
            "",
            "| Bỏ nhóm | Số đặc trưng còn | " + f"`{metric}`" + " | Hiệu số | Cận dưới | ROC-AUC | PR-AUC | Recall@1% | Nhận |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for c in sorted(r["candidates"], key=lambda c: -c["values"][metric]):
            mark = "**có**" if c["dropped"] == r["accepted"] else ""
            v = c["values"]
            lines.append(
                f"| `{c['dropped']}` | {c['n_features']} | {v[metric]:.4f} | {c['diff']:+.4f} | {c['lower']:+.4f} | {v['roc_auc']:.4f} | {v['pr_auc']:.4f} | {v['recall@fpr=0.01']:.1%} | {mark} |"
            )
        lines.append("")
    dropped = [g for g in ALL_GROUPS if g not in result["selected_groups"]]
    lines.append("Kết quả: giữ " + ", ".join(f"`{g}`" for g in result["selected_groups"]) + (f"; bỏ " + ", ".join(f"`{g}`" for g in dropped) if dropped else " (không bỏ nhóm nào)"))
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------ dòng lệnh


def _load_inputs():
    df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
    trainval = pd.read_parquet(ATTACKERS_TRAINVAL_PARQUET).assign(pop_weight=1.0)
    return df, trainval


def main() -> int:
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    df, trainval = _load_inputs()
    started = time.time()

    def say(message: str) -> None:
        print(f"  [{time.time() - started:6.0f}s] {message}", flush=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if what in ("search", "all"):
        result = {"forest": select_forest_groups(df, log=say), "attack_ip": select_attack_ip_groups(df, log=say)}
        SELECTION_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print("\n" + selection_markdown(result["forest"], "Isolation Forest, ATO quá khứ") + "\n\n" + selection_markdown(result["attack_ip"], "gbm_attack_ip, val"), flush=True)
    if what in ("train", "all"):
        chosen = json.loads(SELECTION_JSON.read_text(encoding="utf-8"))
        report = train_final(df, trainval, chosen["forest"]["selected_groups"], chosen["attack_ip"]["selected_groups"], log=say)
        (OUT_DIR / "train_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    say("xong")
    return 0


if __name__ == "__main__":
    sys.exit(main())
