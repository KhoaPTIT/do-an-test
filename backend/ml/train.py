"""Huấn luyện model bất thường runtime (Phase 4.1 — ML3): Isolation Forest.

    python -m ml.train      # ml/data/v3/splits -> ml/artifacts/anomaly_iforest/{model.joblib,metadata.json}

  - TRAIN: fit Isolation Forest trên MỌI dòng của tập train, KHÔNG dùng nhãn (`contamination="auto"` — không ước lượng từ
    tỉ lệ nhãn như bản Tuần 7).
  - VALIDATION: chọn ngưỡng = phân vị (1 − `TARGET_FPR`) điểm bất thường của các dòng BÌNH THƯỜNG trong validation (mục
    tiêu tỉ lệ báo nhầm 1%). Đây là chỗ DUY NHẤT nhãn tham gia trước khi đánh giá.
  - TEST: không đọc ở đây — chỉ `ml/evaluate.py` đọc, một lần.

Cấu hình chốt TRƯỚC khi train lần đầu; không chỉnh sau khi xem kết quả test."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

from ml.anomaly_model import ARTIFACT_DIR, METADATA_FILE, MODEL_FILE
from ml.build_features import read_split
from ml.dataset import DATA_DIR, read_labels
from ml.features import FEATURE_NAMES, FEATURE_VERSION, feature_signature

MODEL_NAME = "isolation_forest"
TRAINING_SEED = 42
TARGET_FPR = 0.01
PARAMS = {"n_estimators": 300, "max_samples": 256, "contamination": "auto", "max_features": 1.0, "bootstrap": False}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def train(data_dir: Path = DATA_DIR, out_dir: Path = ARTIFACT_DIR) -> dict:
    import joblib

    _, x_train = read_split(data_dir / "splits" / "train.csv")
    val_ids, x_val = read_split(data_dir / "splits" / "validation.csv")
    labels = read_labels(data_dir / "labels.csv")

    model = IsolationForest(random_state=TRAINING_SEED, **PARAMS)
    model.fit(np.asarray(x_train, dtype=float))  # không nhãn

    val_scores = -model.score_samples(np.asarray(x_val, dtype=float))
    val_normal = np.array([s for s, i in zip(val_scores, val_ids) if labels[i] is None])
    threshold = float(np.quantile(val_normal, 1 - TARGET_FPR, method="higher"))
    val_anomaly = np.array([s for s, i in zip(val_scores, val_ids) if labels[i] is not None])

    train_matrix = np.asarray(x_train, dtype=float)
    train_hash = _sha(data_dir / "splits" / "train.csv")
    metadata = {
        "model_name": MODEL_NAME,
        "model_version": f"{FEATURE_VERSION}-{feature_signature()}-{train_hash[:8]}-s{TRAINING_SEED}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sklearn.ensemble.IsolationForest",
        "algorithm_parameters": {**PARAMS, "random_state": TRAINING_SEED},
        "feature_names": FEATURE_NAMES,
        "feature_version": FEATURE_VERSION,
        "feature_signature": feature_signature(),
        "training_seed": TRAINING_SEED,
        "train_size": len(x_train),
        "validation_size": len(x_val),
        "test_size": len(read_split(data_dir / "splits" / "test.csv")[0]),
        "threshold": threshold,
        "threshold_rule": f"phân vị {1 - TARGET_FPR:.2f} điểm bất thường của dòng BÌNH THƯỜNG trong validation (FPR mục tiêu {TARGET_FPR:.0%})",
        "validation": {
            "normal_rows": int(len(val_normal)), "anomaly_rows": int(len(val_anomaly)),
            "fpr_at_threshold": float(np.mean(val_normal >= threshold)),
            "recall_at_threshold": float(np.mean(val_anomaly >= threshold)) if len(val_anomaly) else None,
        },
        "train_feature_mean": train_matrix.mean(axis=0).tolist(),
        "train_feature_std": train_matrix.std(axis=0).tolist(),
        "score_semantics": "anomaly_score = -score_samples (càng cao càng lạ); is_anomaly <=> anomaly_score >= threshold",
        "data_files_sha256": {name: _sha(data_dir / name) for name in ("events.csv", "labels.csv", "features.csv")},
        "dataset": "TỔNG HỢP (ml/dataset.py) — không phải dữ liệu người dùng/tấn công thật",
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out_dir / MODEL_FILE)
    (out_dir / METADATA_FILE).write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--out-dir", default=str(ARTIFACT_DIR))
    args = parser.parse_args(argv)
    meta = train(Path(args.data_dir), Path(args.out_dir))
    print(f"{meta['model_name']} {meta['model_version']}: train {meta['train_size']}, validation {meta['validation_size']}, ngưỡng {meta['threshold']:.4f}")
    print(f"validation @ngưỡng: FPR {meta['validation']['fpr_at_threshold']:.3%}, recall {meta['validation']['recall_at_threshold']:.3%}")
    print(f"-> {Path(args.out_dir).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
