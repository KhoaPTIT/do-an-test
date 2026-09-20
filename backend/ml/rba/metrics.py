"""Chỉ số đánh giá có trọng số + khoảng tin cậy bootstrap (MR4).

Quy ước: điểm CÀNG CAO CÀNG ĐÁNG NGỜ; nhãn dương = tấn công. Mọi chỉ số nhận trọng số dòng (`weight`
của bảng mô hình: dòng tấn công chỉ giữ theo nhóm IP nên cần trọng số 1/tỉ lệ nhóm để phục hồi tỉ lệ
tấn công tự nhiên — xem docs/rba-data-card.md mục 8).

Cách tính dựa trên một "tham chiếu âm tính" (`NegativeReference`): tập âm tính sắp xếp một lần, sau đó
mọi chỉ số chỉ cần điểm của các ca dương tính. Nhờ vậy bootstrap chỉ phải lấy mẫu lại phía dương tính
(ATO chỉ có 38–141 ca; tập âm tính hàng trăm nghìn dòng nên đóng góp bất định không đáng kể) và mỗi lần
lấy mẫu chỉ tốn O(P log P). Kết quả điểm ước lượng được kiểm chứng bằng test so với scikit-learn.

Định nghĩa ngưỡng: một dòng bị cảnh báo khi điểm >= ngưỡng. Ties (điểm bằng nhau giữa dương và âm)
được tính theo cách bảo thủ nhất quán với đường cong ROC của scikit-learn.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

DEFAULT_FPR_TARGETS = (0.01, 0.001)
DEFAULT_TPR_TARGETS = (0.90, 0.99)


@dataclass
class NegativeReference:
    """Tập âm tính đã sắp xếp: trả lời "tổng trọng số âm tính có điểm >= s" bằng tìm kiếm nhị phân."""

    scores_desc: np.ndarray
    cumulative_weight: np.ndarray  # cumulative_weight[i] = tổng trọng số của scores_desc[: i + 1]
    total_weight: float

    @classmethod
    def build(cls, scores: np.ndarray, weights: np.ndarray) -> "NegativeReference":
        order = np.argsort(-scores, kind="mergesort")
        s = scores[order]
        cw = np.cumsum(weights[order])
        return cls(s, cw, float(cw[-1]) if len(cw) else 0.0)

    def _count_ge(self, threshold: np.ndarray) -> np.ndarray:
        """Số phần tử (theo chỉ số) có điểm >= threshold trong mảng giảm dần."""
        # scores_desc giảm dần -> dùng phần bù để searchsorted trên mảng tăng dần
        return len(self.scores_desc) - np.searchsorted(self.scores_desc[::-1], threshold, side="left")

    def weight_ge(self, threshold) -> np.ndarray:
        threshold = np.atleast_1d(np.asarray(threshold, dtype=float))
        k = self._count_ge(threshold)
        out = np.zeros(len(threshold))
        nonzero = k > 0
        out[nonzero] = self.cumulative_weight[k[nonzero] - 1]
        return out

    def weight_gt(self, threshold) -> np.ndarray:
        threshold = np.atleast_1d(np.asarray(threshold, dtype=float))
        k = len(self.scores_desc) - np.searchsorted(self.scores_desc[::-1], threshold, side="right")
        out = np.zeros(len(threshold))
        nonzero = k > 0
        out[nonzero] = self.cumulative_weight[k[nonzero] - 1]
        return out

    def fpr_at(self, threshold) -> np.ndarray:
        return self.weight_ge(threshold) / self.total_weight

    def exceeding_score(self, fpr_target: float) -> float:
        """Điểm âm tính cao nhất mà tại đó FPR (điểm >= s) vượt fpr_target; -inf nếu không bao giờ vượt."""
        limit = fpr_target * self.total_weight
        # cumulative_weight tăng dần theo chỉ số; tìm chỉ số đầu tiên có tổng > limit
        idx = int(np.searchsorted(self.cumulative_weight, limit, side="right"))
        if idx >= len(self.scores_desc):
            return -np.inf
        return float(self.scores_desc[idx])


def _weighted_positive_stats(pos_scores: np.ndarray, pos_weights: np.ndarray):
    order = np.argsort(-pos_scores, kind="mergesort")
    return pos_scores[order], pos_weights[order]


def recall_at_fpr(ref: NegativeReference, pos_scores, pos_weights, fpr_target: float) -> float:
    """Tỉ lệ ca dương tính bắt được với FPR <= fpr_target (ngưỡng thấp nhất còn thoả FPR)."""
    s_star = ref.exceeding_score(fpr_target)
    total = pos_weights.sum()
    return float(pos_weights[pos_scores > s_star].sum() / total)


def fpr_at_recall(ref: NegativeReference, pos_scores, pos_weights, tpr_target: float) -> float:
    """FPR nhỏ nhất đạt được TPR >= tpr_target — chính là "tỉ lệ yêu cầu xác thực lại" của user hợp lệ."""
    s, w = _weighted_positive_stats(pos_scores, pos_weights)
    cum = np.cumsum(w) / w.sum()
    idx = int(np.searchsorted(cum, tpr_target - 1e-12, side="left"))
    idx = min(idx, len(s) - 1)
    return float(ref.fpr_at(s[idx])[0])


def threshold_for_recall(pos_scores, pos_weights, tpr_target: float) -> float:
    """Ngưỡng CAO NHẤT (cảnh báo khi điểm >= ngưỡng) để bắt được ít nhất tpr_target ca dương tính."""
    s, w = _weighted_positive_stats(pos_scores, pos_weights)
    cum = np.cumsum(w) / w.sum()
    idx = min(int(np.searchsorted(cum, tpr_target - 1e-12, side="left")), len(s) - 1)
    return float(s[idx])


def roc_auc(ref: NegativeReference, pos_scores, pos_weights) -> float:
    """P(điểm dương > điểm âm) + 0,5·P(bằng nhau), có trọng số."""
    below = ref.total_weight - ref.weight_ge(pos_scores)  # âm tính có điểm < s
    equal = ref.weight_ge(pos_scores) - ref.weight_gt(pos_scores)
    per_positive = (below + 0.5 * equal) / ref.total_weight
    return float((pos_weights * per_positive).sum() / pos_weights.sum())


def average_precision(ref: NegativeReference, pos_scores, pos_weights) -> float:
    """Average precision theo định nghĩa của scikit-learn (tổng bậc thang), có trọng số."""
    s, w = _weighted_positive_stats(pos_scores, pos_weights)
    starts = np.r_[True, s[1:] != s[:-1]]
    group_id = np.cumsum(starts) - 1
    group_score = s[starts]
    group_weight = np.bincount(group_id, weights=w)
    cum_tp = np.cumsum(group_weight)
    fp = ref.weight_ge(group_score)
    precision = cum_tp / (cum_tp + fp)
    return float(((group_weight / w.sum()) * precision).sum())


@dataclass
class TaskMetrics:
    n_pos: int
    n_neg: int
    values: dict[str, float]
    ci: dict[str, tuple[float, float]]


def compute_metrics(
    ref: NegativeReference,
    pos_scores: np.ndarray,
    pos_weights: np.ndarray,
    fpr_targets=DEFAULT_FPR_TARGETS,
    tpr_targets=DEFAULT_TPR_TARGETS,
) -> dict[str, float]:
    out = {
        "roc_auc": roc_auc(ref, pos_scores, pos_weights),
        "pr_auc": average_precision(ref, pos_scores, pos_weights),
    }
    for target in fpr_targets:
        out[f"recall@fpr={target:g}"] = recall_at_fpr(ref, pos_scores, pos_weights, target)
    for target in tpr_targets:
        out[f"reauth@tpr={target:g}"] = fpr_at_recall(ref, pos_scores, pos_weights, target)
    return out


def evaluate(
    y: np.ndarray,
    score: np.ndarray,
    weight: np.ndarray | None = None,
    cluster: np.ndarray | None = None,
    n_boot: int = 500,
    seed: int = 0,
    alpha: float = 0.05,
    fpr_targets=DEFAULT_FPR_TARGETS,
    tpr_targets=DEFAULT_TPR_TARGETS,
) -> TaskMetrics:
    """Điểm ước lượng + khoảng tin cậy bootstrap theo CỤM dương tính (mặc định mỗi dòng là một cụm).

    Chỉ lấy mẫu lại phía dương tính (xem docstring module). `cluster`: nhãn cụm của từng dòng (ví dụ IP
    tấn công hoặc user) — các dòng cùng cụm luôn được lấy cùng nhau vì chúng không độc lập.
    """
    y = np.asarray(y, dtype=bool)
    score = np.asarray(score, dtype=float)
    weight = np.ones(len(y)) if weight is None else np.asarray(weight, dtype=float)
    if np.isnan(score).any():
        raise ValueError("điểm có NaN — mô hình phải trả điểm cho mọi dòng")
    if y.sum() == 0 or (~y).sum() == 0:
        raise ValueError("cần cả ca dương tính lẫn âm tính")

    ref = NegativeReference.build(score[~y], weight[~y])
    pos_scores, pos_weights = score[y], weight[y]
    values = compute_metrics(ref, pos_scores, pos_weights, fpr_targets, tpr_targets)

    if cluster is None:
        pos_cluster = np.arange(len(pos_scores))
    else:
        _, pos_cluster = np.unique(np.asarray(cluster)[y], return_inverse=True)
    n_clusters = int(pos_cluster.max()) + 1
    order = np.argsort(pos_cluster, kind="stable")
    boundaries = np.searchsorted(pos_cluster[order], np.arange(n_clusters + 1))

    rng = np.random.default_rng(seed)
    draws = {name: [] for name in values}
    for _ in range(n_boot):
        chosen = rng.integers(0, n_clusters, n_clusters)
        idx = np.concatenate([order[boundaries[c]:boundaries[c + 1]] for c in chosen])
        sample = compute_metrics(ref, pos_scores[idx], pos_weights[idx], fpr_targets, tpr_targets)
        for name, value in sample.items():
            draws[name].append(value)
    ci = {
        name: (float(np.quantile(v, alpha / 2)), float(np.quantile(v, 1 - alpha / 2))) for name, v in draws.items()
    }
    return TaskMetrics(int(y.sum()), int((~y).sum()), values, ci)
