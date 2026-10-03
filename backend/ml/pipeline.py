"""Chạy TOÀN BỘ chuỗi ML từ đầu (Phase 4.1): sinh dataset → trích đặc trưng + chia tập → train → đánh giá test → bằng chứng.

    cd backend && python -m ml.pipeline

Sau lệnh này `ml/artifacts/anomaly_iforest/` có model mới; khởi động lại backend để nạp (log: "đã nạp model bất thường").
Bằng chứng (commit được) ghi vào `artifacts/ml/` ở gốc repo."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from ml import build_features, dataset, evaluate, train
from ml.anomaly_model import ARTIFACT_DIR
from ml.features import FEATURE_NAMES, feature_signature


def dataset_summary(data_dir: Path, counts: dict[str, int]) -> dict:
    events = dataset.read_events(data_dir / "events.csv")
    labels = dataset.read_labels(data_dir / "labels.csv")
    split_types = {}
    for name in build_features.SPLITS:
        ids, _ = build_features.read_split(data_dir / "splits" / f"{name}.csv")
        c = Counter(labels[i] or "normal" for i in ids)
        split_types[name] = {"rows": len(ids), "anomalies": sum(v for k, v in c.items() if k != "normal"), "by_type": dict(sorted(c.items()))}
    files = ["events.csv", "labels.csv", "features.csv", "splits/train.csv", "splits/validation.csv", "splits/test.csv"]
    return {
        "nature": "TỔNG HỢP — hành vi bình thường từ bộ sinh lưu lượng bình thường v3 (verification/normal_traffic.py), bất thường được chèn",
        "seed": dataset.DATASET_SEED, "harness_seed_excluded": 20260302,
        "users": dataset.N_USERS + 13, "distinct_usernames": len({e.username for e in events}),
        "events": len(events), "successful_events": sum(e.success for e in events),
        "first_event": min(e.ts for e in events).isoformat(), "last_event": max(e.ts for e in events).isoformat(),
        "injected_anomaly_events": dict(sorted(Counter(v for v in labels.values() if v).items())),
        "feature_rows": sum(counts.values()), "feature_scope": "lần THÀNH CÔNG của hồ sơ trưởng thành (≥10 lần, ≥7 ngày)",
        "features": FEATURE_NAMES, "feature_signature": feature_signature(),
        "split_rule": f"theo thời gian: train < ngày {build_features.TRAIN_END_DAY} ≤ validation < ngày {build_features.VALIDATION_END_DAY} ≤ test",
        "splits": split_types,
        "sha256": {f: hashlib.sha256((data_dir / f).read_bytes()).hexdigest() for f in files},
    }


def run(data_dir: Path = dataset.DATA_DIR, model_dir: Path = ARTIFACT_DIR, evidence_dir: Path = evaluate.EVIDENCE_DIR) -> dict:
    raws, labels = dataset.build()
    dataset.write(raws, labels, data_dir)
    counts = build_features.build(data_dir)
    summary = dataset_summary(data_dir, counts)
    meta = train.train(data_dir, model_dir)
    result = evaluate.evaluate(data_dir, model_dir, evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "dataset_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    training = {k: v for k, v in meta.items() if k not in ("train_feature_mean", "train_feature_std")}
    (evidence_dir / "training_summary.json").write_text(json.dumps(training, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"dataset": summary, "training": training, "evaluation": result}


def main() -> int:
    out = run()
    d, t, e = out["dataset"], out["training"], out["evaluation"]
    print(f"dataset: {d['events']} sự kiện, {d['feature_rows']} dòng đặc trưng — " + ", ".join(f"{k} {v['rows']}" for k, v in d["splits"].items()))
    print(f"model: {t['model_name']} {t['model_version']} ngưỡng {t['threshold']:.4f} -> {ARTIFACT_DIR}")
    a = e["at_threshold"]
    print(f"test: P {a['precision']} R {a['recall']} F1 {a['f1']} FPR {a['fpr']} ROC-AUC {e['roc_auc']} PR-AUC {e['pr_auc_average_precision']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
