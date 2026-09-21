"""Kiểm định "dấu vân tay" của kẻ tấn công mô phỏng (MR4/MR6):  python -m ml.rba.audit [trainval]

Vấn đề: mô hình học từ kẻ tấn công mô phỏng có thể học CÁCH MÔ PHỎNG thay vì cách tấn công. Sáu phiên bản đầu của bộ
mô phỏng đều để lại dấu vân tay (bảy lỗi: chèn lệch nhịp; mượn IP của đăng nhập ngay trước; IP hoàn toàn mới; hồ sơ Targeted là
giá trị hay gặp nhất; hồ sơ Targeted là lần đăng nhập gần nhất; nạn nhân mỗi user một lần; chèn thay vì thay thế trong luồng sự kiện — chi tiết ở ml/rba/attackers.py) — mô hình học từ bản
đầu đạt recall 100% kể cả với kẻ tấn công "Targeted" bắt chước hoàn hảo, dấu hiệu chắc chắn của lối tắt.

Cách kiểm: với mỗi kiểu kẻ tấn công và mỗi NHÓM đặc trưng, huấn luyện một LightGBM nhỏ để tách đăng nhập giả khỏi đăng
nhập hợp lệ thành công (của tài khoản đã có lịch sử) cùng giai đoạn, chấm trên các user KHÔNG dùng khi học:
  - ROC-AUC: mức tách tổng thể;
  - recall khi báo nhầm 1% đăng nhập hợp lệ: mức tách ở điểm vận hành (chỉ số quan trọng hơn — AUC bị chi phối bởi phần
    lớn phân phối, còn cảnh báo thật chỉ hoạt động ở FPR nhỏ).

Kết quả mong đợi (mọi kiểu):
  - `cur`, `history`, `rhythm`, `rarity`, `infra_ip`, `infra_asn`: AUC ≈ 0,5 và recall ≈ 1% — đăng nhập giả thay thế đúng một đăng
    nhập thật (cùng nhịp, cùng lịch sử), IP/ASN mượn từ đăng nhập thật của người khác, số đếm toàn cục được bảo toàn nên độ
    hiếm của thuộc tính giống người thật. Nhích lên vài phần trăm là nhiễu chấp nhận được (recall ở FPR 1% ≲ 6%); cao hơn
    hẳn (AUC ≥ 0,6 hoặc recall ≥ 10%) = còn dấu vân tay, sửa bộ mô phỏng trước khi huấn luyện.
  - `novelty`, `freeman`: tín hiệu tấn công THẬT (thuộc tính lạ so với LỊCH SỬ nạn nhân) — cao với naive/VPN. Với Targeted
    (thuộc tính đúng bằng đăng nhập gốc, chỉ IP mới) chỉ còn các đặc trưng liên quan đến IP (`new_ip`, `llr_ip`) và tương tác
    "IP mới × khoảng cách ngắn từ lần thành công trước": AUC vừa phải, recall ở FPR 1% chủ yếu đến từ tương tác đó.
Kiểm định TÁCH RIÊNG từng giai đoạn (`trainval` in train rồi val): dương tính và âm tính phải cùng giai đoạn.

Kiểm định CÓ ĐIỀU KIỆN (`conditional`, MR8): kẻ tấn công mô phỏng LUÔN dùng IP mới với tài khoản, còn chỉ ~40% đăng nhập hợp lệ như vậy. So với toàn bộ
đăng nhập hợp lệ thì hai bên trông giống nhau ở nhóm `infra_ip`/`rarity` (AUC ≈ 0,5), nhưng so với đăng nhập hợp lệ CŨNG dùng IP mới thì lộ chênh lệch
(IP mượn từ đăng nhập của người khác nên hay đã có lịch sử hơn IP mới thật) — kiểm định tổng thể bỏ sót loại dấu vân tay này. Cột `n` là số đăng nhập giả
có IP mới. Xem docs/ml-explanations.md mục 6.
Cột `top` liệt kê 3 đặc trưng quan trọng nhất của mô hình `all` — nếu là đặc trưng hạ tầng/nhịp thì nghi có dấu vân tay.
"""

from __future__ import annotations

import sys

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from ml.rba import eval_tasks
from ml.rba.features import FEATURE_GROUPS, FEATURE_NAMES
from ml.rba.models import feature_matrix

GROUPS = ("cur", "novelty", "history", "rhythm", "freeman", "rarity", "infra_ip", "infra_asn")
ATTACKER_KINDS = ("naive", "vpn", "targeted")
_PARAMS = {"objective": "binary", "learning_rate": 0.1, "num_leaves": 15, "min_data_in_leaf": 50, "verbosity": -1, "num_threads": 8, "seed": 7}


def separability(pos: pd.DataFrame, neg: pd.DataFrame, features: list[str], seed: int, rounds: int = 120, fpr: float = 0.01) -> dict:
    """AUC, recall tại FPR `fpr` và 3 đặc trưng quan trọng nhất của một mô hình tách `pos` khỏi `neg`, chấm trên user giữ lại."""
    users = np.unique(np.r_[pos["user_id"].to_numpy(), neg["user_id"].to_numpy()])
    rng = np.random.default_rng(seed)
    train_users = set(rng.choice(users, int(0.7 * len(users)), replace=False))
    frame = pd.concat([pos.assign(_y=1), neg.assign(_y=0)])
    is_train = frame["user_id"].isin(train_users).to_numpy()
    y = frame["_y"].to_numpy()
    booster = lgb.train(
        _PARAMS, lgb.Dataset(feature_matrix(frame[is_train], features), label=y[is_train], feature_name=features), num_boost_round=rounds
    )
    score = booster.predict(feature_matrix(frame[~is_train], features))
    held = y[~is_train]
    threshold = np.quantile(score[held == 0], 1.0 - fpr)
    gains = booster.feature_importance(importance_type="gain")
    total = float(gains.sum()) or 1.0
    top = [(features[i], float(gains[i] / total)) for i in np.argsort(-gains)[:3]]
    return {"auc": float(roc_auc_score(held, score)), "recall": float((score[held == 1] > threshold).mean()), "top": top}


def audit(df: pd.DataFrame, attackers: pd.DataFrame, partitions: tuple[str, ...], negatives: int = 150_000, seed: int = 0, condition: str | None = None) -> dict:
    """{"auc": bảng, "recall": bảng, "top": {kiểu: [(đặc trưng, tỉ trọng)]}}; hàng = kiểu kẻ tấn công, cột = `all` và từng nhóm.
    `condition` (tên cột 0/1, ví dụ "new_ip"): chỉ so các đăng nhập có cột đó = 1 ở CẢ HAI phía (kiểm định có điều kiện)."""
    legit = df[
        df["partition"].isin(partitions) & ~df["in_warmup"] & (df["cur_success"] == 1) & ~df["is_attack_ip"] & ~df["is_ato"]
        & (df["u_n_success"] >= 1)  # kẻ tấn công mô phỏng chỉ nhắm vào tài khoản đã có lịch sử
    ]
    if condition:
        legit, attackers = legit[legit[condition] == 1], attackers[attackers[condition] == 1]
    legit = legit.sample(min(negatives, len(legit)), random_state=seed)
    auc_rows, recall_rows, top = {}, {}, {}
    for kind in ATTACKER_KINDS:
        pos = attackers[attackers["attacker_type"] == kind]
        results = {"all": separability(pos, legit, FEATURE_NAMES, seed)}
        for group in GROUPS:
            results[group] = separability(pos, legit, FEATURE_GROUPS[group], seed)
        auc_rows[kind] = {"n": len(pos), **{k: v["auc"] for k, v in results.items()}}
        recall_rows[kind] = {"n": len(pos), **{k: v["recall"] for k, v in results.items()}}
        top[kind] = results["all"]["top"]
    return {"auc": pd.DataFrame(auc_rows).T, "recall": pd.DataFrame(recall_rows).T, "top": top}


def to_markdown(table: pd.DataFrame, percent: bool = False) -> str:
    columns = ["all", *GROUPS]
    fmt = (lambda v: f"{v:.1%}") if percent else (lambda v: f"{v:.3f}")
    lines = ["| Kiểu | n | " + " | ".join(columns) + " |", "|---|---|" + "---|" * len(columns)]
    for kind, row in table.iterrows():
        lines.append(f"| {kind} | {int(row['n']):,} | " + " | ".join(fmt(row[c]) for c in columns) + " |")
    return "\n".join(lines)


def top_markdown(top: dict) -> str:
    return "\n".join(f"- {kind}: " + ", ".join(f"`{name}` {share:.0%}" for name, share in features) for kind, features in top.items())


def main() -> int:
    """`test`: bộ đánh giá. `trainval`: bộ huấn luyện và chọn mô hình, kiểm định TÁCH RIÊNG từng giai đoạn (train, val); thêm `conditional`
    để so riêng với đăng nhập hợp lệ cũng dùng IP mới. Gộp
    chung sẽ làm lệch tỉ lệ giai đoạn giữa dương và âm tính (dương tính val chiếm 27%, âm tính val chỉ ~17%) và hiện ra
    "dấu vân tay" giả ở nhóm lịch sử/hạ tầng."""
    which = "trainval" if "trainval" in sys.argv else "test"
    condition = "new_ip" if "conditional" in sys.argv else None
    df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
    if which == "test":
        runs = [("test", pd.read_parquet(eval_tasks.ATTACKERS_PARQUET), ("test",))]
    else:
        both = pd.read_parquet(eval_tasks.ATTACKERS_TRAINVAL_PARQUET)
        runs = [(period, both[both["period"] == period], (period,)) for period in ("train", "val")]
    for name, attackers, partitions in runs:
        result = audit(df, attackers, partitions, condition=condition)
        note = " — CÓ ĐIỀU KIỆN: chỉ so với đăng nhập hợp lệ cũng dùng IP mới" if condition else ""
        print(f"Kiểm định dấu vân tay — giai đoạn {name}{note} (tách đăng nhập giả khỏi đăng nhập thật, user chưa dùng khi học):\n")
        print("ROC-AUC (≈ 0,5 = không tách được):\n")
        print(to_markdown(result["auc"]))
        print("\nRecall khi báo nhầm 1% đăng nhập hợp lệ (≈ 1% = không tách được):\n")
        print(to_markdown(result["recall"], percent=True))
        print("\n3 đặc trưng quan trọng nhất của mô hình `all`:\n")
        print(top_markdown(result["top"]), "\n", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
