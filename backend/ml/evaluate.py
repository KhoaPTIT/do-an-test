"""Đánh giá CUỐI model bất thường trên tập TEST (Phase 4.1 — ML3/ML4E). Test không được dùng ở bước nào trước đó.

    python -m ml.evaluate    # -> artifacts/ml/evaluation.json, per_anomaly_metrics.json, confusion_matrix.{json,png}

Metric chính: precision, recall, F1, FPR ở NGƯỠNG ĐÃ CHỌN TRÊN VALIDATION (không chọn lại trên test), cùng ROC-AUC và PR-AUC
(average precision) trên điểm liên tục. Không dùng accuracy làm metric chính (lớp bất thường chỉ ~4%: đoán "bình thường" cho
mọi dòng đã đạt ~96% accuracy). ⚠️ Dataset TỔNG HỢP: đây không phải hiệu năng trên người dùng/tấn công thật."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from sklearn.metrics import average_precision_score, roc_auc_score

from ml.anomaly_model import ARTIFACT_DIR, AnomalyModel
from ml.build_features import read_split
from ml.dataset import DATA_DIR, read_labels

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = REPO_ROOT / "artifacts" / "ml"


def _rates(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }


def evaluate(data_dir: Path = DATA_DIR, model_dir: Path = ARTIFACT_DIR, evidence_dir: Path = EVIDENCE_DIR) -> dict:
    model = AnomalyModel.load(model_dir)
    ids, matrix = read_split(data_dir / "splits" / "test.csv")
    labels = read_labels(data_dir / "labels.csv")
    scores = model.scores(matrix)
    y = [int(labels[i] is not None) for i in ids]
    pred = [int(s >= model.threshold) for s in scores]

    tp = sum(1 for a, b in zip(y, pred) if a and b)
    fp = sum(1 for a, b in zip(y, pred) if not a and b)
    tn = sum(1 for a, b in zip(y, pred) if not a and not b)
    fn = sum(1 for a, b in zip(y, pred) if a and not b)
    per_type: dict[str, dict] = defaultdict(lambda: {"samples": 0, "detected": 0})
    for i, p in zip(ids, pred):
        if labels[i] is not None:
            per_type[labels[i]]["samples"] += 1
            per_type[labels[i]]["detected"] += p
    per_anomaly = {
        kind: {**v, "missed": v["samples"] - v["detected"], "recall": round(v["detected"] / v["samples"], 4)} for kind, v in sorted(per_type.items())
    }
    prevalence = sum(y) / len(y)
    result = {
        "model_name": model.model_name, "model_version": model.model_version, "threshold": model.threshold,
        "threshold_selected_on": "validation (FPR mục tiêu 1% trên dòng bình thường) — KHÔNG chọn trên test",
        "test_rows": len(y), "test_anomalies": sum(y), "test_prevalence": round(prevalence, 4),
        "at_threshold": _rates(tp, fp, tn, fn),
        "roc_auc": round(roc_auc_score(y, scores), 4),
        "pr_auc_average_precision": round(average_precision_score(y, scores), 4),
        "pr_auc_random_baseline": round(prevalence, 4),
        "accuracy_note": "không dùng accuracy làm metric chính: đoán 'bình thường' cho mọi dòng đã đạt accuracy = 1 − prevalence",
        "dataset_note": "dataset TỔNG HỢP (ml/dataset.py) — không phải hiệu năng trên người dùng/tấn công thật",
    }
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "evaluation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (evidence_dir / "per_anomaly_metrics.json").write_text(json.dumps({
        "model_version": model.model_version, "split": "test", "threshold": model.threshold, "per_anomaly": per_anomaly,
        "normal": {"samples": fp + tn, "flagged": fp, "fpr": result["at_threshold"]["fpr"]},
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    confusion = {"labels": ["normal", "anomaly"], "matrix": [[tn, fp], [fn, tp]], "rows": "thực tế", "columns": "dự đoán"}
    (evidence_dir / "confusion_matrix.json").write_text(json.dumps(confusion, ensure_ascii=False, indent=2), encoding="utf-8")
    _plot_confusion(confusion, evidence_dir / "confusion_matrix.png", model.model_version)
    return {**result, "per_anomaly": per_anomaly}


def _plot_confusion(confusion: dict, path: Path, version: str) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(4, 3.4), dpi=120)
    m = confusion["matrix"]
    ax.imshow(m, cmap="Blues")
    for r in range(2):
        for c in range(2):
            ax.text(c, r, str(m[r][c]), ha="center", va="center", fontsize=12, color="black")
    ax.set_xticks([0, 1], ["bình thường", "bất thường"])
    ax.set_yticks([0, 1], ["bình thường", "bất thường"])
    ax.set_xlabel("dự đoán")
    ax.set_ylabel("thực tế")
    ax.set_title(f"Isolation Forest — test\n{version}", fontsize=8)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--model-dir", default=str(ARTIFACT_DIR))
    parser.add_argument("--evidence-dir", default=str(EVIDENCE_DIR))
    args = parser.parse_args(argv)
    r = evaluate(Path(args.data_dir), Path(args.model_dir), Path(args.evidence_dir))
    a = r["at_threshold"]
    print(f"TEST ({r['test_rows']} dòng, {r['test_anomalies']} bất thường): TP {a['tp']} FP {a['fp']} TN {a['tn']} FN {a['fn']}")
    print(f"precision {a['precision']} recall {a['recall']} F1 {a['f1']} FPR {a['fpr']} ROC-AUC {r['roc_auc']} PR-AUC {r['pr_auc_average_precision']}")
    for kind, v in r["per_anomaly"].items():
        print(f"  {kind:26} {v['detected']}/{v['samples']}  recall {v['recall']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
