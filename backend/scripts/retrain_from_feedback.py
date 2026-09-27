"""MR15 — "Vòng phản hồi": script chạy ĐỊNH KỲ (không phải ngay mỗi lần admin bấm "Đúng"/"Báo nhầm", xem
`POST /alerts/{id}/feedback` ở `app/routers/alerts.py`) — đọc LẠI TOÀN BỘ `Alert.status` đã có phản hồi
(`resolved`/`false_positive`), tính lại `threshold_delta` cho TỪNG tài khoản đủ mẫu (`app/detection/adaptive_threshold.py`)
và GHI ĐÈ `UserRiskProfile` (không cộng dồn theo từng lần chạy — mỗi lần tính LẠI TỪ ĐẦU trên toàn bộ lịch sử phản hồi
tích luỹ đến hiện tại, nên kết quả không phụ thuộc đã chạy script này bao nhiêu lần trước đó, chỉ phụ thuộc dữ liệu
phản hồi HIỆN CÓ — tính chất quan trọng để kiểm chứng bằng mô phỏng nhiều vòng, xem `feedback_loop_sim.py`).

KHÔNG PHẢI retrain mô hình học máy — chỉ tính lại một con số (`threshold_delta`) cho mỗi tài khoản, xem lý do ở
docstring `app/detection/adaptive_threshold.py` và `app/models.py::UserRiskProfile`.

Chạy: cd backend && venv\\Scripts\\python.exe -m scripts.retrain_from_feedback [--dry-run]
"""

from __future__ import annotations

import argparse

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.detection.adaptive_threshold import MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD, compute_delta
from app.models import Alert, AuditLog, UserRiskProfile

_FEEDBACK_STATUSES = ("resolved", "false_positive")


def tally_feedback(db: Session) -> dict[int, tuple[int, int]]:
    """`{user_id: (tổng phản hồi, số phản hồi "báo nhầm")}` — chỉ tính alert CÓ tài khoản thật (bỏ qua tên đăng nhập
    không tồn tại, không có `UserRiskProfile` để chỉnh) và ĐÃ có phản hồi (`status` trong `_FEEDBACK_STATUSES`)."""
    total = dict(
        db.query(Alert.user_id, func.count(Alert.id))
        .filter(Alert.user_id.isnot(None), Alert.status.in_(_FEEDBACK_STATUSES))
        .group_by(Alert.user_id)
        .all()
    )
    false_positive = dict(
        db.query(Alert.user_id, func.count(Alert.id)).filter(Alert.user_id.isnot(None), Alert.status == "false_positive").group_by(Alert.user_id).all()
    )
    return {user_id: (count, false_positive.get(user_id, 0)) for user_id, count in total.items()}


def retrain(db: Session, *, dry_run: bool = False) -> list[dict]:
    """Tính lại `threshold_delta` cho mọi tài khoản đủ mẫu, GHI (trừ khi `dry_run`) và trả danh sách thay đổi (kể cả
    khi delta không đổi — dùng cho báo cáo/mô phỏng, xem `feedback_loop_sim.py`)."""
    changes = []
    for user_id, (feedback_count, false_positive_count) in tally_feedback(db).items():
        if feedback_count < MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD:
            continue
        new_delta = compute_delta(feedback_count, false_positive_count)
        profile = db.get(UserRiskProfile, user_id)
        old_delta = profile.threshold_delta if profile is not None else 0.0
        if profile is None:
            profile = UserRiskProfile(user_id=user_id)
            db.add(profile)
        profile.threshold_delta = new_delta
        profile.feedback_count = feedback_count
        profile.false_positive_count = false_positive_count
        changes.append(
            {"user_id": user_id, "feedback_count": feedback_count, "false_positive_count": false_positive_count, "old_delta": old_delta, "new_delta": new_delta}
        )

    if dry_run:
        db.rollback()
        return changes

    if changes:
        db.add(
            AuditLog(
                actor="system", action="retrain_thresholds", target_type="user_risk_profile",
                detail={"n_users_considered": len(changes), "n_users_adjusted": sum(1 for c in changes if c["new_delta"] > 0)},
            )
        )
    db.commit()
    return changes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Chỉ in kết quả, không ghi DB")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        changes = retrain(db, dry_run=args.dry_run)
    finally:
        db.close()

    if not changes:
        print("Không có tài khoản nào đủ phản hồi để tính ngưỡng riêng.")
        return
    print(f"{'user_id':>8} {'phan hoi':>10} {'bao nham':>10} {'delta cu':>10} {'delta moi':>10}")
    for c in changes:
        print(f"{c['user_id']:>8} {c['feedback_count']:>10} {c['false_positive_count']:>10} {c['old_delta']:>10.1f} {c['new_delta']:>10.1f}")
    if args.dry_run:
        print("(--dry-run: chưa ghi DB)")


if __name__ == "__main__":
    main()
