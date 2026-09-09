"""Huấn luyện mô hình phát hiện bất thường.

Chạy:  python ml/train.py --data data/login_events.csv

Huấn luyện hai mô hình để so sánh trong báo cáo:

  Isolation Forest (không giám sát)
      Chỉ học từ dữ liệu bình thường, không cần nhãn tấn công.
      Đây là mô hình được đưa vào chạy thật, vì trong thực tế
      hiếm khi có sẵn nhãn cho các lần đăng nhập độc hại.

  Random Forest (có giám sát)
      Cần nhãn đầy đủ. Đóng vai trò mốc so sánh lý tưởng: nếu có nhãn thì
      làm được tới đâu. Chênh lệch giữa hai mô hình chính là cái giá phải
      trả cho việc không có nhãn.

Chia tập theo THỜI GIAN chứ không chia ngẫu nhiên. Chia ngẫu nhiên sẽ để
sự kiện của tương lai lọt vào tập huấn luyện, làm kết quả tốt lên một cách
giả tạo so với khi chạy thật.
"""
import argparse
import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detection.features import FEATURE_NAMES
from ml.replay import build_dataset


def evaluate(y_true, y_pred, name):
    from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                                 recall_score)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "model": name,
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "fp_rate": round(fp / (fp + tn) * 100, 3) if (fp + tn) else 0.0,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/login_events.csv")
    ap.add_argument("--out", default="ml/models/detector.pkl")
    ap.add_argument("--train-ratio", type=float, default=0.7,
                    help="tỷ lệ dữ liệu đầu dòng thời gian dùng để huấn luyện")
    ap.add_argument("--contamination", type=float, default=0.04)
    ap.add_argument("--fp-budget", type=float, default=0.03,
                    help="tỷ lệ lần đăng nhập hợp lệ chấp nhận bị mô hình "
                         "chấm từ 50 điểm trở lên")
    args = ap.parse_args()

    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.preprocessing import StandardScaler

    print("Đang tính đặc trưng...")
    X, y, events, _ = build_dataset(args.data)
    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    # Chia theo thời gian: build_dataset đã trả về theo thứ tự tăng dần
    split = int(len(X) * args.train_ratio)
    X_tr, X_te = X[:split], X[split:]
    y_tr, y_te = y[:split], y[split:]

    print(f"Tập huấn luyện: {len(X_tr)} mẫu ({y_tr.sum()} tấn công)")
    print(f"Tập kiểm thử  : {len(X_te)} mẫu ({y_te.sum()} tấn công)")
    if y_te.sum() == 0:
        raise SystemExit("Tập kiểm thử không có mẫu tấn công nào. "
                         "Hãy sinh lại dữ liệu với nhiều ngày hơn.")

    scaler = StandardScaler().fit(X_tr)
    X_tr_s, X_te_s = scaler.transform(X_tr), scaler.transform(X_te)

    # --- Isolation Forest: chỉ học từ phần dữ liệu bình thường ---
    print("\nHuấn luyện Isolation Forest...")
    iso = IsolationForest(n_estimators=300,
                          contamination=args.contamination,
                          max_samples="auto", random_state=42, n_jobs=-1)
    iso.fit(X_tr_s[y_tr == 0])

    # Hiệu chỉnh thang điểm: quy đổi decision_function về thang 0-100.
    #
    # Cách làm: neo mốc 50 điểm vào một ngân sách báo động giả cho trước.
    # Nếu chấp nhận 3% lần đăng nhập hợp lệ bị mô hình chấm từ 50 điểm trở lên,
    # thì mốc 50 điểm phải rơi đúng vào phân vị 3 của điểm thô trên dữ liệu
    # bình thường. Từ hai ràng buộc "phân vị 50 ứng với 0 điểm" và
    # "phân vị 3 ứng với 50 điểm", suy ra hai mốc quy đổi tuyến tính.
    #
    # Cách này tốt hơn việc chọn hệ số bằng cảm tính, vì nó cho phép trả lời
    # câu hỏi "vì sao lấy ngưỡng đó" bằng một đại lượng có ý nghĩa vận hành.
    raw_normal = iso.decision_function(X_tr_s[y_tr == 0])
    normal_ref = float(np.percentile(raw_normal, 50))
    raw_at_budget = float(np.percentile(raw_normal, args.fp_budget * 100))
    anomaly_ref = 2 * raw_at_budget - normal_ref

    calibration = {"normal_ref": normal_ref, "anomaly_ref": anomaly_ref,
                   "fp_budget": args.fp_budget}
    print(f"  Ngân sách báo động giả: {args.fp_budget * 100:.1f}%")
    print(f"  Mốc 0 điểm tại {normal_ref:.4f}, "
          f"mốc 50 điểm tại {raw_at_budget:.4f}, "
          f"mốc 100 điểm tại {anomaly_ref:.4f}")

    def to_score(raw):
        span = normal_ref - anomaly_ref
        return np.clip((normal_ref - raw) / span * 100, 0, 100)

    iso_score_te = to_score(iso.decision_function(X_te_s))

    # --- Random Forest có giám sát ---
    print("Huấn luyện Random Forest...")
    rf = RandomForestClassifier(n_estimators=400, class_weight="balanced",
                                min_samples_leaf=2, random_state=42, n_jobs=-1)
    rf.fit(X_tr_s, y_tr)
    rf_prob_te = rf.predict_proba(X_te_s)[:, 1]

    # --- So sánh trên tập kiểm thử ---
    results = [
        evaluate(y_te, (iso_score_te >= 50).astype(int), "Isolation Forest (ngưỡng 50)"),
        evaluate(y_te, (rf_prob_te >= 0.5).astype(int), "Random Forest (ngưỡng 0.5)"),
    ]
    auc_iso = roc_auc_score(y_te, iso_score_te)
    auc_rf = roc_auc_score(y_te, rf_prob_te)
    results[0]["auc"] = round(auc_iso, 4)
    results[1]["auc"] = round(auc_rf, 4)

    print("\n--- Kết quả trên tập kiểm thử ---")
    for r in results:
        print(f"{r['model']}")
        print(f"  Precision {r['precision']:.3f}  Recall {r['recall']:.3f}  "
              f"F1 {r['f1']:.3f}  AUC {r['auc']:.3f}  "
              f"Tỷ lệ báo động giả {r['fp_rate']:.2f}%")
        print(f"  TP {r['tp']}  FP {r['fp']}  FN {r['fn']}  TN {r['tn']}")

    print("\n--- Mức quan trọng của đặc trưng (Random Forest) ---")
    order = np.argsort(rf.feature_importances_)[::-1]
    for i in order[:10]:
        print(f"  {FEATURE_NAMES[i]:30s} {rf.feature_importances_[i]:.4f}")

    bundle = {
        "scaler": scaler, "iso": iso, "rf": rf,
        "features": FEATURE_NAMES,
        "calibration": calibration,
        "metrics": {r["model"]: r for r in results},
        "trained_at": datetime.utcnow().isoformat(timespec="seconds"),
        "n_train": int(len(X_tr)), "n_test": int(len(X_te)),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out)
    print(f"\nĐã lưu mô hình vào {out}")


if __name__ == "__main__":
    main()
