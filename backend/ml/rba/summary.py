"""Bảng tóm tắt từ các báo cáo đã lưu (MR6):  python -m ml.rba.summary

Đọc ml/artifacts/rba_reports/*.json (sinh bởi `python -m ml.rba.report`) và in ma trận mô hình × bài cho từng chỉ số, để
đưa thẳng vào tài liệu — số trong tài liệu luôn sinh từ báo cáo, không gõ tay.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ml.rba.eval_tasks import REPORT_DIR

MATRICES = (
    ("roc_auc", "ROC-AUC", False),
    ("pr_auc", "PR-AUC (có trọng số dân số)", False),
    ("recall@fpr=0.01", "Recall khi báo nhầm 1% đăng nhập hợp lệ", True),
    ("recall@fpr=0.001", "Recall khi báo nhầm 0,1% đăng nhập hợp lệ", True),
    ("reauth@tpr=0.9", "Tỉ lệ xác thực lại để bắt 90% tấn công", True),
    ("reauth@tpr=0.99", "Tỉ lệ xác thực lại để bắt 99% tấn công", True),
)
_SKIP = {"comparison"}


def load_reports(directory: Path = REPORT_DIR, names: list[str] | None = None) -> list[dict]:
    reports = []
    for path in sorted(directory.glob("*.json")):
        if path.stem in _SKIP or (names and path.stem not in names):
            continue
        reports.append(json.loads(path.read_text(encoding="utf-8")))
    return reports


def matrix_markdown(reports: list[dict], metric: str, title: str, pct: bool, with_ci: bool = False, tasks: list[str] | None = None) -> str:
    task_names = tasks or [t["task"] for t in reports[0]["tasks"]]
    lines = [f"**{title}**", "", "| Mô hình | " + " | ".join(f"`{n}`" for n in task_names) + " |", "|---|" + "---|" * len(task_names)]
    for report in reports:
        by_task = {t["task"]: t for t in report["tasks"]}
        cells = []
        for name in task_names:
            task = by_task.get(name)
            if task is None:
                cells.append("—")
                continue
            m = task["metrics"][metric]
            v, (lo, hi) = m["value"], m["ci95"]
            if pct:
                cells.append(f"{v:.1%} [{lo:.0%}–{hi:.0%}]" if with_ci else f"{v:.1%}")
            else:
                cells.append(f"{v:.3f} [{lo:.2f}–{hi:.2f}]" if with_ci else f"{v:.3f}")
        lines.append(f"| `{report['scorer']}` | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def history_markdown(reports: list[dict], task: str) -> str:
    """Recall và báo nhầm theo mức lịch sử tại ngưỡng chung cho FPR 1%, cho một bài."""
    lines = [f"**Theo mức lịch sử của tài khoản — bài `{task}`, ngưỡng chung cho FPR 1%** (recall / báo nhầm)", "", "| Mô hình | Chưa có lịch sử | Mỏng (1–4) | Dày (≥5) |", "|---|---|---|---|"]
    for report in reports:
        t = next((x for x in report["tasks"] if x["task"] == task), None)
        if t is None:
            continue
        cells = []
        for bucket in t["by_history"]:
            if bucket["recall"] is None or bucket["n_pos"] == 0:
                cells.append(f"— / {bucket['false_alert_rate']:.2%}" if bucket["false_alert_rate"] is not None else "—")
            else:
                cells.append(f"{bucket['recall']:.0%} / {bucket['false_alert_rate']:.2%}")
        lines.append(f"| `{report['scorer']}` | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main() -> int:
    names = sys.argv[1:] or None
    reports = load_reports(names=names)
    if not reports:
        print("Chưa có báo cáo — chạy `python -m ml.rba.report all` trước.")
        return 1
    for metric, title, pct in MATRICES:
        print(matrix_markdown(reports, metric, title, pct), "\n")
    for task in ("ato/future", "ato/all", "attacker/naive", "attacker/vpn"):
        print(history_markdown(reports, task), "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
