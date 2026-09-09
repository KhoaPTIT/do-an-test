"""Nạp dữ liệu mô phỏng vào cơ sở dữ liệu để dashboard có thứ hiển thị.

Chạy:  python seed_database.py --data data/login_events.csv --reset

Script ghi thẳng vào database thay vì gọi API, vì gọi API cho hai chục nghìn
bản ghi sẽ rất chậm. Điểm rủi ro vẫn được tính bằng đúng rule engine và
mô hình mà API dùng, nên kết quả hiển thị trên dashboard giống hệt như khi
dữ liệu đi qua API.

Xử lý theo hai lượt để chạy nhanh:
  Lượt 1  duyệt sự kiện theo thời gian, tính đặc trưng và bối cảnh
  Lượt 2  chấm điểm ML cho toàn bộ theo lô, rồi ghép với điểm rule

Chấm điểm theo lô nhanh hơn gọi mô hình từng dòng khoảng ba mươi lần,
vì thư viện tính toán tối ưu cho ma trận chứ không tối ưu cho một hàng.
"""
import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.config import (ML_MIN_HISTORY, ML_WEIGHT, RULE_WEIGHT)
from app.database import SessionLocal, init_db
from app.detection.rules import run_rules
from app.detection.scoring import decide, severity_of
from app.models import Alert, BlockedIP, LoginEvent, User
from app.utils.device import parse_ua
from ml.replay import Replayer, event_from_csv_row

BATCH = 1000


def batch_ml_scores(X):
    """Chấm điểm bất thường cho toàn bộ ma trận đặc trưng một lần."""
    try:
        import joblib
        from app.config import MODEL_PATH
        bundle = joblib.load(MODEL_PATH)
    except Exception:
        print("Chưa có mô hình, hệ thống sẽ chỉ dùng luật.")
        return None

    cal = bundle["calibration"]
    span = cal["normal_ref"] - cal["anomaly_ref"]
    raw = bundle["iso"].decision_function(bundle["scaler"].transform(X))
    return np.clip((cal["normal_ref"] - raw) / span * 100, 0, 100)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/login_events.csv")
    ap.add_argument("--reset", action="store_true",
                    help="xóa sạch dữ liệu cũ trước khi nạp")
    args = ap.parse_args()

    init_db()
    db = SessionLocal()

    if args.reset:
        db.query(Alert).delete()
        db.query(LoginEvent).delete()
        db.query(BlockedIP).delete()
        db.query(User).delete()
        db.commit()
        print("Đã xóa dữ liệu cũ")

    with open(args.data, newline="", encoding="utf-8") as f:
        rows = sorted(csv.DictReader(f), key=lambda r: r["timestamp"])
    print(f"Đọc {len(rows)} bản ghi từ {args.data}")

    # Lượt 1: đặc trưng, bối cảnh, điểm rule
    print("Lượt 1: tính đặc trưng và điểm luật...")
    replayer = Replayer()
    events, feats, rule_scores, rule_hits_all = [], [], [], []
    for r in rows:
        ev = event_from_csv_row(r)
        f_vec, ctx = replayer.process(ev)
        hits = run_rules(ev, ctx)
        events.append((ev, ctx))
        feats.append(f_vec)
        rule_scores.append(min(sum(h.score for h in hits), 100.0))
        rule_hits_all.append([h.to_dict() for h in hits])

    # Lượt 2: điểm ML theo lô
    print("Lượt 2: chấm điểm mô hình theo lô...")
    ml_all = batch_ml_scores(np.array(feats, dtype=float))

    # Tạo trước tài khoản
    usernames = sorted({ev.username for ev, _ in events})
    existing = {u.username for u in db.query(User).all()}
    db.add_all([User(username=n, email=f"{n}@example.edu.vn")
                for n in usernames if n not in existing])
    db.commit()
    user_ids = {u.username: u.id for u in db.query(User).all()}

    print("Lượt 3: ghi vào cơ sở dữ liệu...")
    n_alerts = 0
    for i, (ev, ctx) in enumerate(events):
        rule_score = rule_scores[i]
        use_ml = ml_all is not None and ctx["history_count"] >= ML_MIN_HISTORY
        ml_score = float(ml_all[i]) if use_ml else None

        final = (RULE_WEIGHT * rule_score + ML_WEIGHT * ml_score
                 if ml_score is not None else rule_score)
        decision = decide(final)
        dev = parse_ua(ev.user_agent)

        row = LoginEvent(
            user_id=user_ids[ev.username], username=ev.username,
            ip_address=ev.ip_address, country=ev.country, city=ev.city,
            latitude=ev.latitude, longitude=ev.longitude,
            network_type=ev.network_type, user_agent=ev.user_agent,
            device_type=dev["device_type"], os_family=dev["os"],
            browser_family=dev["browser"],
            device_fingerprint=ev.device_fingerprint,
            login_successful=ev.login_successful, timestamp=ev.timestamp,
            risk_score=round(final, 2), rule_score=round(rule_score, 2),
            ml_score=round(ml_score, 2) if ml_score is not None else None,
            decision=decision, rule_hits=rule_hits_all[i],
            is_attack=ev.is_attack, attack_type=ev.attack_type,
        )
        db.add(row)

        if decision in ("challenge", "block"):
            db.flush()
            reasons = "; ".join(h["detail"] for h in rule_hits_all[i])
            db.add(Alert(
                event_id=row.id, severity=severity_of(final, decision),
                title=f"Đăng nhập rủi ro: {ev.username}",
                description=reasons or "Mô hình học máy phát hiện hành vi lệch chuẩn.",
                created_at=ev.timestamp,
            ))
            n_alerts += 1

        if (i + 1) % BATCH == 0:
            db.commit()

    db.commit()
    db.close()
    print(f"Hoàn tất: {len(events)} sự kiện, {n_alerts} cảnh báo")


if __name__ == "__main__":
    main()
