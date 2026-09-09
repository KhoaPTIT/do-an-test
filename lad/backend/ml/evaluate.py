"""Đánh giá đầy đủ bốn cấu hình, xuất bảng số liệu và biểu đồ cho báo cáo.

Chạy:  python ml/evaluate.py --data data/login_events.csv

Sinh ra trong thư mục docs/figures/:
    roc_curves.png            đường ROC của các cấu hình
    confusion_matrices.png    ma trận nhầm lẫn
    feature_importance.png    mức quan trọng của đặc trưng
    score_distribution.png    phân bố điểm rủi ro của hai lớp
    threshold_tradeoff.png    Precision, Recall, tỷ lệ báo động giả theo ngưỡng
    results.csv               bảng số liệu để chèn vào báo cáo

Bảng kết quả gồm bốn dòng, đúng như cấu trúc phần đánh giá của báo cáo:
    1. Chỉ rule
    2. Chỉ Isolation Forest
    3. Chỉ Random Forest
    4. Lai rule và Isolation Forest, tức cấu hình đang chạy thật
"""
import argparse
import csv
import sys
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app.config import ML_WEIGHT, RULE_WEIGHT, THRESHOLD_CHALLENGE
from app.detection.features import FEATURE_NAMES
from app.detection.rules import run_rules
from ml.replay import build_dataset


def metrics(y_true, y_pred, scores=None, name=""):
    from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                                 recall_score, roc_auc_score)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    row = {
        "Cấu hình": name,
        "Precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "Recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "F1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "AUC": round(roc_auc_score(y_true, scores), 4) if scores is not None else "",
        "FP rate (%)": round(fp / (fp + tn) * 100, 3) if (fp + tn) else 0.0,
        "TP": int(tp), "FP": int(fp), "FN": int(fn), "TN": int(tn),
    }
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/login_events.csv")
    ap.add_argument("--model", default="ml/models/detector.pkl")
    ap.add_argument("--train-ratio", type=float, default=0.7)
    ap.add_argument("--outdir", default="../docs/figures")
    args = ap.parse_args()

    from sklearn.metrics import confusion_matrix, roc_curve

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    bundle = joblib.load(args.model)
    scaler, iso, rf = bundle["scaler"], bundle["iso"], bundle["rf"]
    cal = bundle["calibration"]

    print("Đang tính đặc trưng và chấm điểm rule...")
    X, y, events, contexts = build_dataset(args.data)
    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    # Điểm rule tính lại bằng chính rule engine đang chạy thật
    rule_scores = np.array([
        min(sum(h.score for h in run_rules(ev, ctx)), 100.0)
        for ev, ctx in zip(events, contexts)
    ])

    split = int(len(X) * args.train_ratio)
    X_te, y_te = X[split:], y[split:]
    rule_te = rule_scores[split:]
    ctx_te = contexts[split:]

    X_te_s = scaler.transform(X_te)

    span = cal["normal_ref"] - cal["anomaly_ref"]
    iso_te = np.clip((cal["normal_ref"] - iso.decision_function(X_te_s)) / span * 100,
                     0, 100)
    rf_te = rf.predict_proba(X_te_s)[:, 1] * 100

    # Cấu hình lai: đúng công thức trong app/detection/scoring.py, kể cả
    # quy tắc lùi về dùng riêng rule khi tài khoản chưa đủ lịch sử.
    from app.config import ML_MIN_HISTORY
    hybrid_te = np.array([
        rule_te[i] if ctx_te[i]["history_count"] < ML_MIN_HISTORY
        else RULE_WEIGHT * rule_te[i] + ML_WEIGHT * iso_te[i]
        for i in range(len(rule_te))
    ])

    t = THRESHOLD_CHALLENGE
    configs = [
        ("Chỉ rule", rule_te, rule_te >= t),
        ("Chỉ Isolation Forest", iso_te, iso_te >= 50),
        ("Chỉ Random Forest", rf_te, rf_te >= 50),
        (f"Lai rule + ML (ngưỡng {t:.0f})", hybrid_te, hybrid_te >= t),
    ]

    rows = [metrics(y_te, pred.astype(int), score, name)
            for name, score, pred in configs]

    print("\n%-32s %9s %8s %8s %8s %10s" %
          ("Cấu hình", "Precision", "Recall", "F1", "AUC", "FP rate"))
    for r in rows:
        print("%-32s %9.3f %8.3f %8.3f %8.3f %9.2f%%" %
              (r["Cấu hình"], r["Precision"], r["Recall"],
               r["F1"], r["AUC"], r["FP rate (%)"]))

    with (outdir / "results.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # --- Đường ROC ---
    plt.figure(figsize=(7, 6))
    for name, score, _ in configs:
        fpr, tpr, _ = roc_curve(y_te, score)
        plt.plot(fpr, tpr, label=name, linewidth=1.6)
    plt.plot([0, 1], [0, 1], "--", color="#999", linewidth=1)
    plt.xlabel("Tỷ lệ báo động giả")
    plt.ylabel("Tỷ lệ phát hiện đúng")
    plt.title("Đường ROC của các cấu hình")
    plt.legend(loc="lower right")
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(outdir / "roc_curves.png", dpi=150)
    plt.close()

    # --- Ma trận nhầm lẫn ---
    fig, axes = plt.subplots(1, 4, figsize=(16, 4))
    for ax, (name, _, pred) in zip(axes, configs):
        cm = confusion_matrix(y_te, pred.astype(int), labels=[0, 1])
        ax.imshow(cm, cmap="Blues")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{cm[i, j]}", ha="center", va="center",
                        color="black" if cm[i, j] < cm.max() / 2 else "white")
        ax.set_xticks([0, 1], ["Dự đoán\nbình thường", "Dự đoán\ntấn công"])
        ax.set_yticks([0, 1], ["Thực tế\nbình thường", "Thực tế\ntấn công"])
        ax.set_title(name, fontsize=10)
    plt.tight_layout()
    plt.savefig(outdir / "confusion_matrices.png", dpi=150)
    plt.close()

    # --- Mức quan trọng của đặc trưng ---
    order = np.argsort(rf.feature_importances_)
    plt.figure(figsize=(8, 6))
    plt.barh([FEATURE_NAMES[i] for i in order],
             rf.feature_importances_[order], color="#378ADD")
    plt.xlabel("Mức đóng góp")
    plt.title("Mức quan trọng của đặc trưng theo Random Forest")
    plt.tight_layout()
    plt.savefig(outdir / "feature_importance.png", dpi=150)
    plt.close()

    # --- Phân bố điểm rủi ro ---
    plt.figure(figsize=(8, 5))
    plt.hist(hybrid_te[y_te == 0], bins=40, alpha=0.7,
             label="Đăng nhập hợp lệ", color="#639922", density=True)
    plt.hist(hybrid_te[y_te == 1], bins=40, alpha=0.7,
             label="Đăng nhập tấn công", color="#E24B4A", density=True)
    plt.axvline(t, color="#333", linestyle="--", linewidth=1.2,
                label=f"Ngưỡng cảnh báo ({t:.0f})")
    plt.xlabel("Điểm rủi ro")
    plt.ylabel("Mật độ")
    plt.title("Phân bố điểm rủi ro của cấu hình lai")
    plt.legend()
    plt.tight_layout()
    plt.savefig(outdir / "score_distribution.png", dpi=150)
    plt.close()

    # --- Đánh đổi theo ngưỡng ---
    from sklearn.metrics import precision_score, recall_score
    ths = np.arange(5, 100, 2.5)
    prec, rec, fprs = [], [], []
    for th in ths:
        pred = (hybrid_te >= th).astype(int)
        prec.append(precision_score(y_te, pred, zero_division=0))
        rec.append(recall_score(y_te, pred, zero_division=0))
        tn, fp, fn, tp = confusion_matrix(y_te, pred, labels=[0, 1]).ravel()
        fprs.append(fp / (fp + tn) if (fp + tn) else 0)

    plt.figure(figsize=(8, 5))
    plt.plot(ths, prec, label="Precision", linewidth=1.6)
    plt.plot(ths, rec, label="Recall", linewidth=1.6)
    plt.plot(ths, fprs, label="Tỷ lệ báo động giả", linewidth=1.6)
    plt.axvline(t, color="#333", linestyle="--", linewidth=1.2)
    plt.xlabel("Ngưỡng điểm rủi ro")
    plt.ylabel("Giá trị")
    plt.title("Đánh đổi khi thay đổi ngưỡng cảnh báo")
    plt.legend()
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(outdir / "threshold_tradeoff.png", dpi=150)
    plt.close()

    # --- Khả năng phát hiện theo từng loại tấn công ---
    print("\nKhả năng phát hiện theo loại tấn công (cấu hình lai):")
    ev_te = events[split:]
    by_type = {}
    for i, ev in enumerate(ev_te):
        if not ev.is_attack:
            continue
        k = ev.attack_type or "khác"
        b = by_type.setdefault(k, [0, 0])
        b[0] += 1
        if hybrid_te[i] >= t:
            b[1] += 1
    for k, (total, hit) in sorted(by_type.items()):
        print(f"  {k:22s} {hit}/{total}  ({hit / total * 100:.1f}%)")

    print(f"\nĐã lưu biểu đồ và bảng số liệu vào {outdir.resolve()}")


if __name__ == "__main__":
    main()
