"""Đánh giá & so sánh tầng 3 (ML) với tầng 2 thật trên CÙNG tập test
(nhiệm vụ 7.1 + 7.2 — số liệu đưa vào báo cáo).

Tầng 2 KHÔNG viết lại song song — gọi THẲNG `compute_risk_score()` thật từ
app/detection/scoring.py, dựng `UserBaseline` giả từ ngữ cảnh đã lưu lúc
trích xuất đặc trưng (ml/extract_features.py), nên số liệu so sánh phản
ánh đúng code đang chạy thật trong hệ thống, không phải bản mô phỏng riêng
có thể lệch.

Xuất ra:
  - Bảng precision/recall/F1/ROC-AUC cho 4 phương pháp (tầng 2, Isolation
    Forest, LOF, Autoencoder) → in ra console + lưu CSV.
  - Ma trận nhầm lẫn từng phương pháp → docs/figures/ml-confusion-matrices.png
  - Đường ROC chồng 4 phương pháp → docs/figures/ml-roc-curves.png
  - Feature importance (permutation, dựa trên ROC-AUC) của Isolation Forest
    → docs/figures/ml-feature-importance.png

Chạy (sau khi đã chạy ml/train.py):
    cd backend
    venv\\Scripts\\python.exe -m ml.evaluate
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from types import SimpleNamespace

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from app.detection.scoring import LOW_RISK_MAX, compute_risk_score
from ml.features import FEATURE_NAMES

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
FIGURES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "figures")


def _load_artifacts():
    scaler = joblib.load(os.path.join(ARTIFACTS_DIR, "scaler.joblib"))
    models = {
        "isolation_forest": joblib.load(os.path.join(ARTIFACTS_DIR, "isolation_forest.joblib")),
        "local_outlier_factor": joblib.load(os.path.join(ARTIFACTS_DIR, "local_outlier_factor.joblib")),
        "autoencoder": joblib.load(os.path.join(ARTIFACTS_DIR, "autoencoder.joblib")),
    }
    with open(os.path.join(ARTIFACTS_DIR, "meta.json"), encoding="utf-8") as f:
        meta = json.load(f)
    test_df = pd.read_csv(os.path.join(ARTIFACTS_DIR, "test_set.csv"))
    return scaler, models, meta, test_df


def _tier2_scores(test_df: pd.DataFrame) -> np.ndarray:
    """Gọi THẲNG compute_risk_score() thật cho từng dòng test — xem docstring đầu file."""
    scores = []
    for row in test_df.itertuples():
        count = int(row.successful_login_count_so_far)
        if count == 0 or pd.isna(row.avg_login_hour_so_far):
            baseline = None
        else:
            first_login_at = (
                datetime.fromisoformat(row.first_login_at_so_far) if row.first_login_at_so_far else None
            )
            baseline = SimpleNamespace(
                avg_login_hour=row.avg_login_hour_so_far,
                stddev_login_hour=row.stddev_login_hour_so_far,
                successful_login_count=count,
                first_login_at=first_login_at,
            )
        score, _factors = compute_risk_score(
            baseline=baseline,
            login_hour=row.login_hour,
            is_new_location=bool(row.is_new_location),
            consecutive_fail=False,  # tập ML chỉ gồm đăng nhập THÀNH CÔNG, không có ngữ cảnh fail
            success_after_fail_streak=False,
        )
        scores.append(score)
    return np.array(scores, dtype=float)


def _ml_scores(models: dict, X_scaled: np.ndarray, meta: dict) -> dict[str, np.ndarray]:
    # score_samples/decision_function: SỐ CÀNG THẤP CÀNG BẤT THƯỜNG với
    # Isolation Forest & LOF của scikit-learn -> đảo dấu để "càng cao càng bất thường".
    iso_scores = -models["isolation_forest"].score_samples(X_scaled)
    lof_scores = -models["local_outlier_factor"].decision_function(X_scaled)

    recon = models["autoencoder"].predict(X_scaled)
    ae_scores = np.mean((X_scaled - recon) ** 2, axis=1)

    return {"isolation_forest": iso_scores, "local_outlier_factor": lof_scores, "autoencoder": ae_scores}


def _binary_from_continuous(scores: np.ndarray, contamination: float) -> np.ndarray:
    threshold = np.percentile(scores, 100 * (1 - contamination))
    return (scores >= threshold).astype(int)


def main() -> None:
    os.makedirs(FIGURES_DIR, exist_ok=True)
    scaler, models, meta, test_df = _load_artifacts()

    y_true = test_df["is_anomaly"].values.astype(int)
    X_test_scaled = scaler.transform(test_df[FEATURE_NAMES].values)

    tier2_scores = _tier2_scores(test_df)
    tier2_pred = (tier2_scores >= LOW_RISK_MAX).astype(int)

    ml_scores = _ml_scores(models, X_test_scaled, meta)
    contamination = meta["contamination"]

    all_scores = {"tier2_behavioral": tier2_scores, **ml_scores}
    all_preds = {
        "tier2_behavioral": tier2_pred,
        "isolation_forest": _binary_from_continuous(ml_scores["isolation_forest"], contamination),
        "local_outlier_factor": _binary_from_continuous(ml_scores["local_outlier_factor"], contamination),
        "autoencoder": (ml_scores["autoencoder"] >= meta["autoencoder_threshold"]).astype(int),
    }

    rows = []
    for name in all_preds:
        y_pred = all_preds[name]
        y_score = all_scores[name]
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        rows.append(
            {
                "method": name,
                "precision": precision_score(y_true, y_pred, zero_division=0),
                "recall": recall_score(y_true, y_pred, zero_division=0),
                "f1": f1_score(y_true, y_pred, zero_division=0),
                "roc_auc": roc_auc_score(y_true, y_score),
                "tp": int(tp),
                "fp": int(fp),
                "fn": int(fn),
                "tn": int(tn),
            }
        )

    result_df = pd.DataFrame(rows).set_index("method")
    print(result_df.round(3).to_string())

    result_path = os.path.join(ARTIFACTS_DIR, "evaluation_results.csv")
    result_df.to_csv(result_path)
    print(f"\nĐã lưu bảng kết quả: {os.path.abspath(result_path)}")

    # --- Biểu đồ 1: ma trận nhầm lẫn 4 phương pháp ---
    fig, axes = plt.subplots(1, 4, figsize=(18, 4.5))
    for ax, name in zip(axes, all_preds):
        cm = confusion_matrix(y_true, all_preds[name], labels=[0, 1])
        ConfusionMatrixDisplay(cm, display_labels=["normal", "anomaly"]).plot(ax=ax, colorbar=False)
        ax.set_title(name)
    fig.suptitle("Ma trận nhầm lẫn — tầng 2 (behavioral) vs 3 mô hình ML tầng 3")
    fig.tight_layout()
    fig.savefig(os.path.join(FIGURES_DIR, "ml-confusion-matrices.png"), dpi=120)

    # --- Biểu đồ 2: đường ROC chồng 4 phương pháp ---
    fig2, ax2 = plt.subplots(figsize=(6, 6))
    for name, score in all_scores.items():
        fpr, tpr, _ = roc_curve(y_true, score)
        auc = roc_auc_score(y_true, score)
        ax2.plot(fpr, tpr, label=f"{name} (AUC={auc:.3f})")
    ax2.plot([0, 1], [0, 1], linestyle="--", color="grey", label="random")
    ax2.set_xlabel("False Positive Rate")
    ax2.set_ylabel("True Positive Rate")
    ax2.set_title("ROC — tầng 2 (behavioral) vs 3 mô hình ML")
    ax2.legend(fontsize=8)
    fig2.tight_layout()
    fig2.savefig(os.path.join(FIGURES_DIR, "ml-roc-curves.png"), dpi=120)

    # --- Biểu đồ 3: feature importance (permutation, Isolation Forest) ---
    def _iso_auc_scorer(estimator, X, y):
        return roc_auc_score(y, -estimator.score_samples(X))

    perm = permutation_importance(
        models["isolation_forest"], X_test_scaled, y_true, scoring=_iso_auc_scorer, n_repeats=20, random_state=42
    )
    order = np.argsort(perm.importances_mean)
    fig3, ax3 = plt.subplots(figsize=(7, 4))
    ax3.barh(np.array(FEATURE_NAMES)[order], perm.importances_mean[order], xerr=perm.importances_std[order])
    ax3.set_xlabel("Mức giảm ROC-AUC khi xáo trộn đặc trưng (permutation importance)")
    ax3.set_title("Feature importance — Isolation Forest")
    fig3.tight_layout()
    fig3.savefig(os.path.join(FIGURES_DIR, "ml-feature-importance.png"), dpi=120)

    print(f"Đã lưu 3 biểu đồ vào {os.path.abspath(FIGURES_DIR)}")


if __name__ == "__main__":
    main()
