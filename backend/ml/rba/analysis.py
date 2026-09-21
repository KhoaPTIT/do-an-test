"""Phân tích sau huấn luyện (MR6):  python -m ml.rba.analysis <mô hình> [<mô hình> ...]

1. CHUYỂN NGƯỠNG: chọn ngưỡng cho FPR mục tiêu chỉ trên đăng nhập hợp lệ của `val`, rồi đo tỉ lệ báo nhầm THỰC TẾ và
   recall khi áp cùng ngưỡng ấy lên `test` (tương lai gần) và `late` (12/2020–02/2021, sau khi phân phối trôi). Đây là câu
   hỏi vận hành thật: ngưỡng đặt hôm nay có còn cho đúng mức báo nhầm sau vài tháng không?
2. HIỆU CHỈNH XÁC SUẤT: hồi quy isotonic học trên `val` biến điểm thành xác suất tấn công; đo độ tin cậy (bảng theo phân vị)
   và Brier score trên `test`/`late` so với xác suất thô của mô hình và so với đoán theo tỉ lệ tấn công trung bình.

3. GÁN CÔNG (chỉ hybrid): ở ngưỡng hybrid cho FPR mục tiêu chọn trên `val`, mỗi ca tấn công bắt được do thành phần nào báo
   (thành phần có xác suất đuôi nhỏ nhất) và thành phần nào gây báo nhầm — cho biết mỗi bộ phát hiện đóng góp gì.

Tất cả dùng trọng số dân số (`pop_weight`), giống khung đánh giá MR4.
"""

from __future__ import annotations

import sys

import numpy as np
import pandas as pd

from ml.rba import eval_tasks
from ml.rba import ensemble as En
from ml.rba import splits
from ml.rba.eval_tasks import Task
from ml.rba.scorers import SCORER_FACTORIES

FPR_TARGETS = (0.01, 0.001)


def _val_legit_success_task(df: pd.DataFrame, with_history: bool = False) -> Task:
    """Nguồn chọn ngưỡng cho họ ATO (mọi đăng nhập hợp lệ thành công của val) và họ kẻ tấn công mô phỏng (chỉ tài khoản đã có lịch
    sử, đúng như âm tính của bài `attacker/*`: lẫn tài khoản chưa có lịch sử vào thì mô hình học từ kẻ tấn công mô phỏng — chưa
    bao giờ thấy chúng — cho điểm rất cao ở đó và ngưỡng chọn ra bị đẩy lên quá cao)."""
    rows = df[(df["partition"] == "val") & ~df["in_warmup"] & eval_tasks._legit_success(df)]
    if with_history:
        rows = rows[rows["u_n_success"] >= 1]
    name = "val/legit_success_history" if with_history else "val/legit_success"
    return Task(name, "đăng nhập hợp lệ thành công của val" + (" của tài khoản đã có lịch sử" if with_history else ""), eval_tasks._with_labels(rows, np.zeros(len(rows), dtype=bool), rows["user_id"]))


def transfer_table(scorer, tasks: dict[str, Task], df: pd.DataFrame) -> list[dict]:
    """Mỗi dòng: (họ bài, ngưỡng chọn trên nguồn, đích, FPR mục tiêu) -> FPR và recall thực tế trên đích."""
    val_legit = _val_legit_success_task(df)
    plan = [
        ("IP tấn công", "attack_ip/val", ["attack_ip/test", "attack_ip/late"]),
        ("ATO thật", "val/legit_success", ["ato/future", "ato/all"]),
        ("Kẻ tấn công mô phỏng", "val/legit_success_history", [n for n in tasks if n.startswith("attacker/")]),
    ]
    needed = {name: tasks[name] for _, _, targets in plan for name in targets if name in tasks}
    needed["attack_ip/val"] = tasks["attack_ip/val"]
    needed["val/legit_success"] = val_legit
    needed["val/legit_success_history"] = _val_legit_success_task(df, with_history=True)
    scores = eval_tasks.score_all_tasks(scorer, needed)

    rows = []
    for family, source, targets in plan:
        frame = needed[source].frame
        y_src = frame["y"].to_numpy()
        neg_scores = scores[source][~y_src]
        neg_weights = frame["pop_weight"].to_numpy()[~y_src]
        for target_fpr in FPR_TARGETS:
            threshold = En.threshold_for_fpr(neg_scores, neg_weights, target_fpr)
            for target in targets:
                if target not in needed:
                    continue
                t = needed[target].frame
                rates = En.realized_rates(scores[target], t["y"].to_numpy(), t["pop_weight"].to_numpy(), threshold)
                rows.append({"family": family, "source": source, "target": target, "target_fpr": target_fpr, **rates})
    return rows


def calibration_report(scorer_name: str, scorer, tasks: dict[str, Task], bins: int = 10) -> dict:
    """Hiệu chỉnh isotonic trên `attack_ip/val`; báo độ tin cậy và Brier trên `attack_ip/test` và `attack_ip/late`."""
    needed = {k: tasks[k] for k in ("attack_ip/val", "attack_ip/test", "attack_ip/late")}
    scores = eval_tasks.score_all_tasks(scorer, needed)

    def parts(name):
        f = needed[name].frame
        return scores[name], f["y"].to_numpy(dtype=float), f["pop_weight"].to_numpy()

    s_val, y_val, w_val = parts("attack_ip/val")
    isotonic = En.IsotonicCalibrator.fit(s_val, y_val, w_val)
    base_rate = float((y_val * w_val).sum() / w_val.sum())
    out = {"scorer": scorer_name, "val_attack_rate": base_rate, "periods": {}}
    for name in ("attack_ip/test", "attack_ip/late"):
        s, y, w = parts(name)
        raw = 1.0 / (1.0 + np.exp(-s))  # log-odds -> xác suất thô (chỉ có nghĩa với mô hình LightGBM)
        calibrated = isotonic.probability(s)
        out["periods"][name] = {
            "brier_calibrated": En.brier_score(calibrated, y, w),
            "brier_raw": En.brier_score(raw, y, w) if scorer_name.startswith("gbm") else None,
            "brier_constant": En.brier_score(np.full(len(y), base_rate), y, w),
            "observed_attack_rate": float((y * w).sum() / w.sum()),
            "reliability": En.reliability_table(calibrated, y, w, bins),
        }
    return out


def hybrid_attribution(hybrid: En.HybridMinTail, tasks: dict[str, Task], df: pd.DataFrame, target_fpr: float = 0.01) -> list[dict]:
    """Ngưỡng hybrid chọn trên đăng nhập hợp lệ thành công của val; mỗi bài dương tính: recall và phần ca (tính trên TỔNG ca
    dương) bắt được do từng thành phần báo. Dòng đầu là bài âm tính val: tỉ lệ báo nhầm và phần báo nhầm do từng thành phần."""
    names = np.array([c.name for c in hybrid.components])

    def score(frame: pd.DataFrame):
        tails = hybrid._tails(frame)
        return -np.log10(tails.min(axis=1)), names[tails.argmin(axis=1)]

    val = _val_legit_success_task(df).frame
    val_score, val_who = score(val)
    val_w = val["pop_weight"].to_numpy()
    threshold = En.threshold_for_fpr(val_score, val_w, target_fpr)
    flagged = val_score > threshold
    rows = [
        {
            "task": "val/legit_success", "n_pos": 0, "recall": None, "fpr": float(val_w[flagged].sum() / val_w.sum()),
            "by_component": {n: float(val_w[flagged & (val_who == n)].sum() / val_w.sum()) for n in names},
        }
    ]
    for name, task in tasks.items():
        frame = task.frame
        s, who = score(frame)
        y, w = frame["y"].to_numpy(), frame["pop_weight"].to_numpy()
        hit = (s > threshold) & y
        rows.append(
            {
                "task": name, "n_pos": int(y.sum()), "recall": float(w[hit].sum() / w[y].sum()), "fpr": None,
                "by_component": {n: float(w[hit & (who == n)].sum() / w[y].sum()) for n in names},
            }
        )
    return rows


def attribution_markdown(rows: list[dict], target_fpr: float) -> str:
    names = list(rows[0]["by_component"])
    lines = [
        f"Ngưỡng hybrid chọn trên đăng nhập hợp lệ thành công của val cho FPR {target_fpr:.1%}. Mỗi ô: phần ca dương tính được thành phần đó báo (thành phần có xác suất đuôi nhỏ nhất); dòng `val/legit_success`: phần đăng nhập hợp lệ bị báo nhầm do thành phần đó.",
        "",
        "| Bài | Ca dương | Recall | " + " | ".join(f"`{n}`" for n in names) + " |",
        "|---|---|---|" + "---|" * len(names),
    ]
    for r in rows:
        recall = f"FPR {r['fpr']:.2%}" if r["recall"] is None else f"{r['recall']:.1%}"
        n_pos = "—" if r["n_pos"] == 0 else f"{r['n_pos']:,}"
        lines.append(f"| `{r['task']}` | {n_pos} | {recall} | " + " | ".join(f"{r['by_component'][n]:.1%}" for n in names) + " |")
    return "\n".join(lines)


def transfer_markdown(name: str, rows: list[dict]) -> str:
    lines = [f"#### `{name}`", "", "| Họ bài | Ngưỡng chọn trên | Áp lên | FPR mục tiêu | FPR thực tế | Recall |", "|---|---|---|---|---|---|"]
    for r in rows:
        recall = "—" if r["recall"] is None else f"{r['recall']:.1%}"
        fpr = "—" if r["fpr"] is None else f"{r['fpr']:.2%}"
        lines.append(f"| {r['family']} | `{r['source']}` | `{r['target']}` | {r['target_fpr']:.1%} | {fpr} | {recall} |")
    return "\n".join(lines)


def calibration_markdown(report: dict) -> str:
    lines = [f"#### `{report['scorer']}` (tỉ lệ tấn công của val: {report['val_attack_rate']:.2%})", ""]
    for period, info in report["periods"].items():
        raw = "" if info["brier_raw"] is None else f", thô {info['brier_raw']:.4f}"
        lines += [
            f"**{period}** — tỉ lệ tấn công thực {info['observed_attack_rate']:.2%}; Brier: isotonic {info['brier_calibrated']:.4f}{raw}, đoán theo tỉ lệ trung bình {info['brier_constant']:.4f}",
            "",
            "| Nhóm phân vị | Xác suất dự đoán | Tỉ lệ tấn công thực |",
            "|---|---|---|",
        ]
        for i, row in enumerate(info["reliability"], 1):
            lines.append(f"| {i} | {row['predicted']:.2%} | {row['observed']:.2%} |")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    names = sys.argv[1:] or ["gbm_attack_ip", "gbm_attacker_sim", "hybrid"]
    df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
    import pandas as _pd

    attackers = _pd.read_parquet(eval_tasks.ATTACKERS_PARQUET) if eval_tasks.ATTACKERS_PARQUET.is_file() else None
    tasks = eval_tasks.build_tasks(df, attackers)
    for name in names:
        scorer = SCORER_FACTORIES[name](df)
        print(transfer_markdown(name, transfer_table(scorer, tasks, df)), "\n", flush=True)
        if name.startswith("gbm_attack_ip") or name == "gbm_combined":
            print(calibration_markdown(calibration_report(name, scorer, tasks)), flush=True)
        if name == "hybrid":
            wanted = {k: v for k, v in tasks.items() if k.startswith(("ato/", "attacker/", "attack_ip/test"))}
            print(attribution_markdown(hybrid_attribution(scorer, wanted, df), 0.01), "\n", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
