"""Baseline để so sánh (MR5): Freeman, luật Tier 2 hiện tại, luật đã tinh chỉnh, Isolation Forest.

Mọi mô hình có tham số chỉ học từ phân vùng `train` (không warm-up); lựa chọn biến thể dùng `val`;
`test` chỉ để báo cáo. Điểm càng cao càng đáng ngờ.

| Tên | Là gì | Học từ |
|---|---|---|
| `freeman_all`       | Freeman et al. 2016: tổng log-tỉ-số khả năng 7 thuộc tính (IP, quốc gia, ASN, UA, trình duyệt, OS, thiết bị) | không học |
| `freeman_no_ip`     | như trên nhưng bỏ IP (IP gần như duy nhất mỗi lần nên nhiễu) | không học |
| `tier2_current`     | luật chấm điểm Tier 2 hiện tại của hệ thống (trọng số +30/+40/+50), xấp xỉ bằng đặc trưng RBA | không học |
| `rules_tuned`       | ~18 luật ngưỡng do người viết, ngưỡng chọn trên train, trọng số học bằng hồi quy logistic | train |
| `isolation_forest`  | Isolation Forest học trên đăng nhập bình thường (không dùng nhãn) | train |

Xấp xỉ `tier2_current`: RBA không có giờ đăng nhập đáng tin (timestamp có nhiễu) nên luật "lệch giờ +20" bị bỏ;
"vị trí lạ" dùng `new_country` (RBA không có thành phố); "5 lần sai trong 5 phút" xấp xỉ bằng chuỗi thất bại liên
tiếp vì không tách được cửa sổ 5 phút từ đặc trưng đã tính.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from ml.rba.eval_tasks import Scorer
from ml.rba.features import FEATURE_NAMES, FREEMAN_ATTRS

RANDOM_STATE = 20260921


def training_rows(df: pd.DataFrame) -> pd.DataFrame:
    return df[(df["partition"] == "train") & ~df["in_warmup"]]


def freeman_scorer(attrs=FREEMAN_ATTRS) -> Scorer:
    columns = [f"llr_{a}" for a in attrs]

    def score(frame: pd.DataFrame) -> np.ndarray:
        return frame[columns].to_numpy(dtype=float).sum(axis=1)

    return score


def tier2_scorer() -> Scorer:
    def score(frame: pd.DataFrame) -> np.ndarray:
        learning = (frame["u_n_attempts"] < 10) | (frame["u_age_days"].fillna(0) < 7)
        unknown_location = (frame["new_country"] == 1) & ~learning
        brute_force = (frame["cur_success"] == 0) & (frame["u_fail_streak"] >= 4)
        success_after_streak = (frame["cur_success"] == 1) & (frame["u_fail_streak"] >= 3)
        total = 30 * unknown_location + 40 * brute_force + 50 * success_after_streak
        return np.minimum(total, 100).to_numpy(dtype=float)

    return score


# (đặc trưng, kiểu): "flag" = đặc trưng 0/1, "eq0" = bằng 0, "ge" = ngưỡng chọn từ phân vị của train
RULE_CANDIDATES = [
    ("new_country", "flag"), ("new_asn", "flag"), ("new_ip", "flag"), ("new_ua", "flag"),
    ("new_browser_family", "flag"), ("new_os_family", "flag"), ("new_device", "flag"),
    ("u_n_success", "eq0"), ("u_fail_streak", "ge"),
    ("rare_country", "ge"), ("rare_asn", "ge"), ("rare_ip", "ge"),
    ("ip_distinct_users_24h", "ge"), ("ip_unknown_attempts_24h", "ge"), ("ip_prior_attempts_all", "ge"),
    ("ip_distinct_ua_24h", "ge"), ("asn_fail_ratio_24h", "ge"), ("asn_distinct_users_24h", "ge"),
]
THRESHOLD_QUANTILES = (0.5, 0.75, 0.9, 0.95, 0.99)


def _youden(y: np.ndarray, fired: np.ndarray, w: np.ndarray) -> float:
    tpr = w[y & fired].sum() / w[y].sum()
    fpr = w[~y & fired].sum() / w[~y].sum()
    return tpr - fpr


@dataclass
class TunedRules:
    rules: list[tuple[str, str, float | None]]  # (đặc trưng, kiểu, ngưỡng; None nếu không có ngưỡng)
    model: LogisticRegression

    def _indicators(self, frame: pd.DataFrame) -> np.ndarray:
        columns = []
        for feature, kind, threshold in self.rules:
            values = frame[feature].to_numpy(dtype=float)
            if kind == "flag":
                fired = values == 1
            elif kind == "eq0":
                fired = values == 0
            else:
                fired = values >= threshold
            columns.append(fired.astype(float))
        return np.column_stack(columns)

    def __call__(self, frame: pd.DataFrame) -> np.ndarray:
        return self.model.decision_function(self._indicators(frame))

    def describe(self) -> list[dict]:
        out = []
        for (feature, kind, threshold), weight in zip(self.rules, self.model.coef_[0]):
            if kind == "flag":
                condition = f"{feature} = 1"
            elif kind == "eq0":
                condition = f"{feature} = 0"
            else:
                condition = f"{feature} ≥ {threshold:.3g}"
            out.append({"rule": condition, "weight": float(weight)})
        return sorted(out, key=lambda r: -abs(r["weight"]))


def fit_tuned_rules(df: pd.DataFrame) -> TunedRules:
    """Chọn ngưỡng từng luật để tối đa hoá Youden J (recall − FPR) có trọng số trên train, rồi học trọng số."""
    train = training_rows(df)
    y = train["is_attack_ip"].to_numpy()
    w = train["weight"].to_numpy()

    rules: list[tuple[str, str, float | None]] = []
    for feature, kind in RULE_CANDIDATES:
        if kind != "ge":
            rules.append((feature, kind, None))
            continue
        values = train[feature].to_numpy(dtype=float)
        finite = values[~np.isnan(values)]
        best_threshold, best_j = None, -np.inf
        for q in THRESHOLD_QUANTILES:
            threshold = float(np.quantile(finite, q))
            fired = np.nan_to_num(values, nan=-np.inf) >= threshold
            j = _youden(y, fired, w)
            if j > best_j:
                best_threshold, best_j = threshold, j
        rules.append((feature, kind, best_threshold))

    draft = TunedRules(rules, LogisticRegression())
    x = draft._indicators(train)
    model = LogisticRegression(C=1.0, max_iter=500)
    model.fit(x, y, sample_weight=w)
    return TunedRules(rules, model)


_COUNT_LIKE = [
    name for name in FEATURE_NAMES
    if name.startswith(("u_n_", "u_attempts", "u_fails", "u_distinct", "ip_attempts", "ip_distinct", "ip_unknown", "ip_prior", "asn_attempts", "asn_distinct", "u_secs", "u_age", "u_fail_streak"))
]


class IsolationForestScorer:
    """Isolation Forest học trên đăng nhập BÌNH THƯỜNG của train (không IP tấn công, không ATO). Không dùng nhãn."""

    def __init__(self, n_estimators: int = 300, max_samples: int = 2048, sample_rows: int = 400_000, features=None):
        self.n_estimators, self.max_samples, self.sample_rows = n_estimators, max_samples, sample_rows
        self.features = list(features) if features else None  # None = cả 50 đặc trưng (dùng cho ablation theo nhóm ở MR7)

    def _names(self) -> list[str]:
        return getattr(self, "features", None) or FEATURE_NAMES  # đối tượng lưu trước MR7 không có thuộc tính `features`

    def _prepare(self, frame: pd.DataFrame) -> np.ndarray:
        names = self._names()
        x = frame[names].to_numpy(dtype=float).copy()
        for i, name in enumerate(names):
            if name in _COUNT_LIKE:
                x[:, i] = np.log1p(np.maximum(np.nan_to_num(x[:, i], nan=0.0), 0.0))
        x = np.where(np.isnan(x), self.medians_, x)
        return self.scaler_.transform(x)

    def fit(self, df: pd.DataFrame) -> "IsolationForestScorer":
        train = training_rows(df)
        legit = train[~train["is_attack_ip"] & ~train["is_ato"]]
        legit = legit.sample(min(self.sample_rows, len(legit)), random_state=RANDOM_STATE)
        names = self._names()
        raw = legit[names].to_numpy(dtype=float).copy()
        for i, name in enumerate(names):
            if name in _COUNT_LIKE:
                raw[:, i] = np.log1p(np.maximum(np.nan_to_num(raw[:, i], nan=0.0), 0.0))
        self.medians_ = np.nanmedian(raw, axis=0)
        self.medians_ = np.where(np.isnan(self.medians_), 0.0, self.medians_)
        raw = np.where(np.isnan(raw), self.medians_, raw)
        self.scaler_ = StandardScaler().fit(raw)
        self.forest_ = IsolationForest(
            n_estimators=self.n_estimators, max_samples=self.max_samples, contamination="auto",
            random_state=RANDOM_STATE, n_jobs=-1,
        ).fit(self.scaler_.transform(raw))
        return self

    def __call__(self, frame: pd.DataFrame) -> np.ndarray:
        return -self.forest_.score_samples(self._prepare(frame))
