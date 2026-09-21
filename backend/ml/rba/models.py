"""Mô hình cho bộ RBA (MR6): LightGBM có giám sát; kNN-distance và Autoencoder không giám sát.

Mọi mô hình là một hàm `frame -> điểm` (càng cao càng đáng ngờ) để đi qua đúng khung đánh giá MR4.

Nguồn nhãn cho học có giám sát (KHÔNG BAO GIỜ dùng 141 ca ATO thật để học hay chọn mô hình):
  - `Is Attack IP` (train, chia theo nhóm IP): lưu lượng tấn công hàng loạt — dò mật khẩu, nhồi thông tin đăng nhập.
  - Kẻ tấn công MÔ PHỎNG (ml/rba/attackers.py, nạn nhân giai đoạn train): tấn công vào tài khoản có lịch sử với
    mật khẩu đúng — kiểu tấn công mà nhãn IP không có. ATO thật chỉ dùng để đánh giá cuối cùng.
Chọn siêu tham số / dừng sớm / hiệu chỉnh chỉ dùng phân vùng `val`; `test` và `late` chỉ để báo cáo.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from ml.rba.features import FEATURE_GROUPS, FEATURE_NAMES

RANDOM_STATE = 20260922
ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "rba"

GLOBAL_ONLY_FEATURES = [
    name for group in ("cur", "rarity", "infra_ip", "infra_asn") for name in FEATURE_GROUPS[group]
]
CATEGORICAL_FEATURES = ["cur_device_code"]

DEFAULT_GBM_PARAMS = {
    "objective": "binary",
    "learning_rate": 0.05,
    "num_leaves": 63,
    "min_data_in_leaf": 200,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 10.0,
    "max_bin": 255,
    "metric": ["average_precision", "binary_logloss"],
    "first_metric_only": True,
    "verbosity": -1,
    "seed": RANDOM_STATE,
    "num_threads": 8,
}


def feature_matrix(frame: pd.DataFrame, features: list[str]) -> np.ndarray:
    return frame[features].to_numpy(dtype=np.float32)


def legit_success(df: pd.DataFrame) -> pd.Series:
    return (df["cur_success"] == 1) & ~df["is_attack_ip"] & ~df["is_ato"]


# --------------------------------------------------------------------------------------------- LightGBM


@dataclass
class GbmScorer:
    name: str
    features: list[str]
    booster: lgb.Booster
    meta: dict = field(default_factory=dict)

    def __call__(self, frame: pd.DataFrame) -> np.ndarray:
        return self.booster.predict(feature_matrix(frame, self.features), raw_score=True)

    def predict_proba(self, frame: pd.DataFrame) -> np.ndarray:
        return self.booster.predict(feature_matrix(frame, self.features))

    def importance(self, top: int = 15) -> list[dict]:
        gains = self.booster.feature_importance(importance_type="gain")
        total = float(gains.sum()) or 1.0
        order = np.argsort(-gains)[:top]
        return [{"feature": self.features[i], "gain_share": float(gains[i] / total)} for i in order]

    def save(self, directory: Path | None = None) -> Path:
        directory = directory or ARTIFACT_DIR
        directory.mkdir(parents=True, exist_ok=True)
        self.booster.save_model(str(directory / f"{self.name}.txt"))
        (directory / f"{self.name}.json").write_text(
            json.dumps({**self.meta, "features": self.features}, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return directory / f"{self.name}.txt"

    @classmethod
    def load(cls, name: str, directory: Path | None = None) -> "GbmScorer":
        directory = directory or ARTIFACT_DIR
        meta = json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))
        booster = lgb.Booster(model_file=str(directory / f"{name}.txt"))
        return cls(name, meta["features"], booster, meta)


def train_gbm(
    name: str,
    features: list[str],
    train: tuple[pd.DataFrame, np.ndarray, np.ndarray],
    val: tuple[pd.DataFrame, np.ndarray, np.ndarray],
    params: dict | None = None,
    rounds: int = 1500,
    early_stopping: int = 60,
) -> GbmScorer:
    """`train`/`val` = (bảng đặc trưng, nhãn 0/1, trọng số). Dừng sớm theo average precision (có trọng số) trên val."""
    merged = {**DEFAULT_GBM_PARAMS, **(params or {})}
    categorical = [f for f in CATEGORICAL_FEATURES if f in features]
    (x_tr, y_tr, w_tr), (x_va, y_va, w_va) = train, val
    d_train = lgb.Dataset(feature_matrix(x_tr, features), label=y_tr, weight=w_tr, feature_name=features, categorical_feature=categorical, free_raw_data=False)
    d_val = lgb.Dataset(feature_matrix(x_va, features), label=y_va, weight=w_va, reference=d_train, feature_name=features, categorical_feature=categorical, free_raw_data=False)

    started = time.time()
    evals: dict = {}
    booster = lgb.train(
        merged, d_train, num_boost_round=rounds, valid_sets=[d_val], valid_names=["val"],
        callbacks=[lgb.early_stopping(early_stopping, verbose=False), lgb.record_evaluation(evals)],
    )
    best = booster.best_iteration
    meta = {
        "name": name,
        "params": {k: v for k, v in merged.items() if k != "num_threads"},
        "best_iteration": int(best),
        "val_average_precision": float(evals["val"]["average_precision"][best - 1]),
        "val_logloss": float(evals["val"]["binary_logloss"][best - 1]),
        "n_train": int(len(y_tr)),
        "n_train_positive": int(y_tr.sum()),
        "n_val": int(len(y_va)),
        "n_val_positive": int(y_va.sum()),
        "seconds": round(time.time() - started),
    }
    scorer = GbmScorer(name, features, booster, meta)
    scorer.meta["top_features"] = scorer.importance()
    return scorer


# ----------------------------------------------------------------------------- tập huấn luyện có giám sát


def _split_rows(df: pd.DataFrame, partition: str) -> pd.DataFrame:
    return df[(df["partition"] == partition) & ~df["in_warmup"]]


def attack_ip_sets(df: pd.DataFrame):
    """Nhãn `Is Attack IP`: mọi dòng của phân vùng, trọng số quy về dân số (`pop_weight`)."""
    out = []
    for partition in ("train", "val"):
        rows = _split_rows(df, partition)
        out.append((rows, rows["is_attack_ip"].to_numpy(dtype=np.float32), rows["pop_weight"].to_numpy(dtype=np.float32)))
    return out


def _positive_weights(n_positive: int, negative_weight: float, prior: float) -> np.ndarray:
    """Trọng số mỗi ca dương tính để tổng trọng số dương = prior/(1−prior) × tổng trọng số âm (tỉ lệ tiên nghiệm cho trước)."""
    return np.full(n_positive, prior / (1.0 - prior) * negative_weight / max(n_positive, 1), dtype=np.float32)


def simulated_attacker_sets(df: pd.DataFrame, attackers: pd.DataFrame, prior: float = 0.02, negative_cap: int = 600_000, seed: int = RANDOM_STATE):
    """Dương tính: kẻ tấn công mô phỏng của giai đoạn tương ứng. Âm tính: đăng nhập hợp lệ THÀNH CÔNG của tài khoản ĐÃ CÓ LỊCH SỬ
    cùng giai đoạn (cùng loại dòng như lúc đánh giá — `cur_success` và "tài khoản mới" không thành lối tắt). `prior`: tỉ lệ tấn công giả định."""
    out = []
    for partition in ("train", "val"):
        negatives = _split_rows(df, partition)
        negatives = negatives[legit_success(negatives) & (negatives["u_n_success"] >= 1)]
        if len(negatives) > negative_cap:
            negatives = negatives.sample(negative_cap, random_state=seed)
        positives = attackers[attackers["period"] == partition]
        neg_w = negatives["pop_weight"].to_numpy(dtype=np.float32)
        pos_w = _positive_weights(len(positives), float(neg_w.sum()), prior)
        frame = pd.concat([negatives, positives])
        y = np.r_[np.zeros(len(negatives)), np.ones(len(positives))].astype(np.float32)
        w = np.r_[neg_w, pos_w].astype(np.float32)
        out.append((frame, y, w))
    return out


def combined_sets(df: pd.DataFrame, attackers: pd.DataFrame, rho: float = 0.5, seed: int = RANDOM_STATE):
    """Một mô hình cho cả hai kiểu tấn công. Âm tính: mọi dòng không thuộc IP tấn công/ATO. Dương tính: dòng IP tấn công
    (trọng số dân số) + kẻ tấn công mô phỏng với TỔNG trọng số = rho × tổng trọng số dương của IP tấn công."""
    out = []
    for partition in ("train", "val"):
        rows = _split_rows(df, partition)
        rows = rows[~rows["is_ato"]]
        attack_w = rows.loc[rows["is_attack_ip"], "pop_weight"].sum()
        sims = attackers[attackers["period"] == partition]
        sim_w = np.full(len(sims), rho * attack_w / max(len(sims), 1), dtype=np.float32)
        frame = pd.concat([rows, sims])
        y = np.r_[rows["is_attack_ip"].to_numpy(dtype=np.float32), np.ones(len(sims), dtype=np.float32)]
        w = np.r_[rows["pop_weight"].to_numpy(dtype=np.float32), sim_w]
        out.append((frame, y, w))
    return out


# --------------------------------------------------------------------------------- không giám sát (khoảng cách)

_COUNT_LIKE = [
    name for name in FEATURE_NAMES
    if name.startswith(("u_n_", "u_attempts", "u_fails", "u_distinct", "ip_attempts", "ip_distinct", "ip_unknown", "ip_prior", "asn_attempts", "asn_distinct", "u_secs", "u_age", "u_fail_streak"))
]


class FeaturePreprocessor:
    """log1p cho đặc trưng đếm, điền giá trị thiếu bằng trung vị của tập học, chuẩn hoá — giống hệt Isolation Forest MR5."""

    def _log(self, x: np.ndarray) -> np.ndarray:
        x = x.copy()
        for i, name in enumerate(FEATURE_NAMES):
            if name in _COUNT_LIKE:
                x[:, i] = np.log1p(np.maximum(np.nan_to_num(x[:, i], nan=0.0), 0.0))
        return x

    def fit(self, frame: pd.DataFrame) -> "FeaturePreprocessor":
        raw = self._log(frame[FEATURE_NAMES].to_numpy(dtype=float))
        medians = np.nanmedian(raw, axis=0)
        self.medians_ = np.where(np.isnan(medians), 0.0, medians)
        self.scaler_ = StandardScaler().fit(np.where(np.isnan(raw), self.medians_, raw))
        return self

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        raw = self._log(frame[FEATURE_NAMES].to_numpy(dtype=float))
        return self.scaler_.transform(np.where(np.isnan(raw), self.medians_, raw)).astype(np.float32)


def _legit_train_sample(df: pd.DataFrame, rows: int, seed: int) -> pd.DataFrame:
    train = _split_rows(df, "train")
    legit = train[~train["is_attack_ip"] & ~train["is_ato"]]
    return legit.sample(min(rows, len(legit)), random_state=seed)


class KnnDistanceScorer:
    """Điểm = khoảng cách trung bình tới k láng giềng gần nhất trong một tập tham chiếu các đăng nhập BÌNH THƯỜNG (train).
    Không dùng nhãn để học (nhãn chỉ để loại các dòng đã biết là tấn công khỏi tập tham chiếu). Cùng họ với LOF nhưng
    không chuẩn hoá theo mật độ cục bộ nên chạy được trên hàng triệu dòng bằng phép nhân ma trận (BLAS)."""

    def __init__(self, k: int = 10, reference_rows: int = 30_000, chunk: int = 1500):
        self.k, self.reference_rows, self.chunk = k, reference_rows, chunk

    def fit(self, df: pd.DataFrame) -> "KnnDistanceScorer":
        sample = _legit_train_sample(df, self.reference_rows, RANDOM_STATE)
        self.pre_ = FeaturePreprocessor().fit(sample)
        self.reference_ = self.pre_.transform(sample)
        self.reference_sq_ = (self.reference_ ** 2).sum(axis=1)
        return self

    def __call__(self, frame: pd.DataFrame) -> np.ndarray:
        x = self.pre_.transform(frame)
        out = np.empty(len(x), dtype=np.float32)
        for start in range(0, len(x), self.chunk):
            block = x[start:start + self.chunk]
            d2 = (block ** 2).sum(axis=1)[:, None] + self.reference_sq_[None, :] - 2.0 * block @ self.reference_.T
            nearest = np.partition(np.maximum(d2, 0.0), self.k - 1, axis=1)[:, : self.k]
            out[start:start + self.chunk] = np.sqrt(nearest).mean(axis=1)
        return out.astype(float)


class AutoencoderScorer:
    """Mạng nén (32-12-32) học tái tạo đăng nhập bình thường; điểm = sai số tái tạo bình phương trung bình."""

    def __init__(self, sample_rows: int = 300_000, max_iter: int = 40):
        self.sample_rows, self.max_iter = sample_rows, max_iter

    def fit(self, df: pd.DataFrame) -> "AutoencoderScorer":
        sample = _legit_train_sample(df, self.sample_rows, RANDOM_STATE)
        self.pre_ = FeaturePreprocessor().fit(sample)
        x = self.pre_.transform(sample)
        self.net_ = MLPRegressor(
            hidden_layer_sizes=(32, 12, 32), activation="relu", batch_size=1024, max_iter=self.max_iter,
            early_stopping=True, n_iter_no_change=4, random_state=RANDOM_STATE,
        ).fit(x, x)
        return self

    def __call__(self, frame: pd.DataFrame) -> np.ndarray:
        x = self.pre_.transform(frame)
        return ((self.net_.predict(x) - x) ** 2).mean(axis=1).astype(float)
