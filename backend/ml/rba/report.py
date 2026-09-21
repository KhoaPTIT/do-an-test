"""Sinh bảng kết quả chuẩn cho một hoặc nhiều mô hình/luật (MR4) — một lệnh cho mọi mô hình.

    cd backend
    venv\\Scripts\\python.exe -m ml.rba.report freeman_all
    venv\\Scripts\\python.exe -m ml.rba.report random freeman_all tier2_current rules_tuned isolation_forest
    venv\\Scripts\\python.exe -m ml.rba.report all --n-boot 200

Đầu ra: bảng markdown in ra màn hình; lưu ở ml/artifacts/rba_reports/<tên>.md/.json và, khi chạy nhiều mô hình,
bảng so sánh `comparison.md`. Bài `attacker/*` chỉ có khi đã chạy `python -m ml.rba.attackers`.
"""

from __future__ import annotations

import argparse
import sys
import time

import pandas as pd

from ml.rba import eval_tasks
from ml.rba.scorers import SCORER_FACTORIES

_COMPARISON_COLUMNS = (
    ("roc_auc", "ROC-AUC", False),
    ("pr_auc", "PR-AUC", False),
    ("recall@fpr=0.01", "Recall@FPR 1%", True),
    ("reauth@tpr=0.9", "Xác thực lại @TPR 90%", True),
    ("reauth@tpr=0.99", "Xác thực lại @TPR 99%", True),
)


def comparison_markdown(reports: list[dict]) -> str:
    """Mỗi bài một bảng, mỗi dòng một mô hình — để so sánh cạnh nhau (kèm khoảng tin cậy 95%)."""
    task_names = [t["task"] for t in reports[0]["tasks"]]
    lines = []
    for name in task_names:
        first = next(t for t in reports[0]["tasks"] if t["task"] == name)
        lines += [f"#### `{name}` ({first['n_pos']:,} dương tính / {first['n_neg']:,} âm tính)", ""]
        lines += ["| Mô hình | " + " | ".join(label for _, label, _ in _COMPARISON_COLUMNS) + " |", "|---|" + "---|" * len(_COMPARISON_COLUMNS)]
        for report in reports:
            task = next(t for t in report["tasks"] if t["task"] == name)
            cells = []
            for key, _, pct in _COMPARISON_COLUMNS:
                m = task["metrics"][key]
                v, (lo, hi) = m["value"], m["ci95"]
                cells.append(f"{v:.1%} [{lo:.1%}–{hi:.1%}]" if pct else f"{v:.3f} [{lo:.3f}–{hi:.3f}]")
            lines.append(f"| `{report['scorer']}` | " + " | ".join(cells) + " |")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bảng kết quả chuẩn cho mô hình/luật trên bộ RBA")
    parser.add_argument("scorers", nargs="+", help=f"một hoặc nhiều trong {sorted(SCORER_FACTORIES)} hoặc 'all'")
    parser.add_argument("--n-boot", type=int, default=500)
    args = parser.parse_args()

    names = sorted(SCORER_FACTORIES) if args.scorers == ["all"] else args.scorers
    unknown = [n for n in names if n not in SCORER_FACTORIES]
    if unknown:
        print(f"Không có mô hình {unknown}; có: {sorted(SCORER_FACTORIES)}")
        return 1
    if not eval_tasks.MODEL_TABLE_PARQUET.is_file():
        print("Chưa có rba_model_table.parquet — chạy `python -m ml.rba.build_features` trước.")
        return 1

    df = eval_tasks.load_model_table()
    attackers = pd.read_parquet(eval_tasks.ATTACKERS_PARQUET) if eval_tasks.ATTACKERS_PARQUET.is_file() else None
    trainval = pd.read_parquet(eval_tasks.ATTACKERS_TRAINVAL_PARQUET) if eval_tasks.ATTACKERS_TRAINVAL_PARQUET.is_file() else None
    attackers_val = None if trainval is None else trainval[trainval["period"] == "val"]
    tasks = eval_tasks.build_tasks(df, attackers, attackers_val)
    print(f"Các bài: {', '.join(tasks)}", flush=True)

    reports = []
    for name in names:
        started = time.time()
        scorer = SCORER_FACTORIES[name](df)
        report = eval_tasks.run_report(name, scorer, tasks, args.n_boot)
        path = eval_tasks.save_report(report, name)
        reports.append(report)
        print(f"  {name}: xong sau {time.time() - started:.0f}s -> {path}", flush=True)
        if hasattr(scorer, "describe"):
            print("    luật (trọng số):", ", ".join(f"{r['rule']} ({r['weight']:+.2f})" for r in scorer.describe()[:6]), flush=True)

    if len(reports) > 1:
        text = comparison_markdown(reports)
        (eval_tasks.REPORT_DIR / "comparison.md").write_text(text, encoding="utf-8")
        print("\n" + text)
    else:
        print("\n" + eval_tasks.to_markdown(reports[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
