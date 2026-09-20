"""Huấn luyện 3 mô hình ML tầng 3 (nhiệm vụ 7.1): Isolation Forest, Local
Outlier Factor (novelty detection), Autoencoder (MLP bottleneck qua
scikit-learn — không cần cài TensorFlow/PyTorch).

Train/test split THEO THỜI GIAN, RIÊNG CHO TỪNG USER (70% đầu → train, 30%
cuối → test, theo `created_at` của chính user đó) — mô phỏng đúng bài toán
thật: dự đoán các lần đăng nhập TƯƠNG LAI từ lịch sử, KHÔNG xáo trộn ngẫu
nhiên như train_test_split() mặc định (sẽ làm lẫn tương lai vào tập train).

Isolation Forest học trên TOÀN BỘ tập train (kể cả vài ca bất thường lẫn
vào — đúng bản chất "unsupervised outlier detection", nhãn chỉ dùng để
ĐÁNH GIÁ ở ml/evaluate.py, không dùng khi train). LOF và Autoencoder theo
trường phái "novelty detection" — chỉ học trên phần được xác nhận BÌNH
THƯỜNG của tập train, sau đó đo mức độ "lạ" của dữ liệu mới so với đó.

Chạy (sau khi đã chạy ml/generate_dataset.py và ml/extract_features.py):
    cd backend
    venv\\Scripts\\python.exe -m ml.train
"""

from __future__ import annotations

import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURE_NAMES

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "features.csv")
ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
TRAIN_RATIO = 0.7
RANDOM_STATE = 42


def time_based_split_per_user(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """70% đầu / 30% cuối THEO THỜI GIAN, tính riêng cho từng user — không
    dùng sklearn.train_test_split() vì nó xáo trộn ngẫu nhiên."""
    train_parts, test_parts = [], []
    for _, group in df.groupby("username"):
        group = group.sort_values("created_at")
        split_idx = max(1, int(len(group) * TRAIN_RATIO))
        train_parts.append(group.iloc[:split_idx])
        test_parts.append(group.iloc[split_idx:])
    return pd.concat(train_parts).reset_index(drop=True), pd.concat(test_parts).reset_index(drop=True)


def main() -> None:
    df = pd.read_csv(DATA_PATH)
    train_df, test_df = time_based_split_per_user(df)

    print(f"Train: {len(train_df)} dòng ({int(train_df['is_anomaly'].sum())} bất thường)")
    print(f"Test:  {len(test_df)} dòng ({int(test_df['is_anomaly'].sum())} bất thường)")

    X_train = train_df[FEATURE_NAMES].values
    X_test = test_df[FEATURE_NAMES].values

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    _ = scaler.transform(X_test)  # chỉ để xác nhận không lỗi shape — dùng thật ở evaluate.py

    normal_mask = train_df["is_anomaly"].values == 0
    X_train_normal_scaled = X_train_scaled[normal_mask]

    contamination = max(0.01, min(0.5, float(train_df["is_anomaly"].mean())))

    models = {}

    # --- 1. Isolation Forest — học trên TOÀN BỘ train (kể cả lẫn anomaly) ---
    iso_forest = IsolationForest(n_estimators=200, contamination=contamination, random_state=RANDOM_STATE)
    iso_forest.fit(X_train_scaled)
    models["isolation_forest"] = iso_forest

    # --- 2. Local Outlier Factor (novelty=True) — chỉ học trên phần "sạch" ---
    lof = LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=contamination)
    lof.fit(X_train_normal_scaled)
    models["local_outlier_factor"] = lof

    # --- 3. Autoencoder (MLP bottleneck) — chỉ học tái tạo dữ liệu "sạch" ---
    n_features = X_train_scaled.shape[1]
    bottleneck = max(2, n_features // 3)
    autoencoder = MLPRegressor(
        hidden_layer_sizes=(6, bottleneck, 6),
        activation="relu",
        max_iter=2000,
        random_state=RANDOM_STATE,
        early_stopping=True,
    )
    autoencoder.fit(X_train_normal_scaled, X_train_normal_scaled)
    models["autoencoder"] = autoencoder

    train_normal_recon = autoencoder.predict(X_train_normal_scaled)
    train_normal_mse = np.mean((X_train_normal_scaled - train_normal_recon) ** 2, axis=1)
    autoencoder_threshold = float(np.percentile(train_normal_mse, 100 * (1 - contamination)))

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    joblib.dump(scaler, os.path.join(ARTIFACTS_DIR, "scaler.joblib"))
    for name, model in models.items():
        joblib.dump(model, os.path.join(ARTIFACTS_DIR, f"{name}.joblib"))

    meta = {
        "feature_names": FEATURE_NAMES,
        "contamination": contamination,
        "autoencoder_threshold": autoencoder_threshold,
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "train_anomaly_rows": int(train_df["is_anomaly"].sum()),
        "test_anomaly_rows": int(test_df["is_anomaly"].sum()),
    }
    with open(os.path.join(ARTIFACTS_DIR, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    test_df.to_csv(os.path.join(ARTIFACTS_DIR, "test_set.csv"), index=False)

    print(f"Đã lưu 3 mô hình + scaler + meta vào {os.path.abspath(ARTIFACTS_DIR)}")
    print(f"contamination ước tính từ train set: {contamination:.3f}")
    print(f"Ngưỡng reconstruction error (autoencoder): {autoencoder_threshold:.4f}")


if __name__ == "__main__":
    main()
