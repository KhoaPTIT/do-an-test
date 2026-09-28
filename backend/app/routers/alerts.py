"""GET /alerts — danh sách cảnh báo phân trang cho dashboard (nhiệm vụ 4.3).
POST /alerts/{id}/feedback — "Đúng"/"Báo nhầm" (MR15, "vòng phản hồi"): ghi vào chính alert + nhật ký kiểm toán. CHỈ
ghi nhận phản hồi — KHÔNG chỉnh ngưỡng ngay lúc bấm, việc đó là của `backend/scripts/retrain_from_feedback.py` (script
ĐỊNH KỲ, đọc lại toàn bộ phản hồi đã tích luỹ — xem docstring ở đó).

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1).
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import Alert, AuditLog
from app.schemas import AlertFeedbackRequest, AlertOut, PaginatedAlerts

router = APIRouter()

# MR13: mặc định "priority" (novelty × độ tin cậy × importance, alert_intelligence.priority_score) — đúng bullet "xếp
# hạng ưu tiên" của MR13, thay vì luôn mới nhất lên đầu; "recent" giữ lại hành vi CŨ (MR12 trở về trước) cho ai cần.
# NULLS LAST: alert tầng 1-2-3 cũ (trước MR13, không có priority_score) rơi xuống cuối thay vì chen lên đầu vì NULL.
_SORTS = {
    "priority": (Alert.priority_score.desc().nulls_last(), Alert.created_at.desc()),
    "recent": (Alert.created_at.desc(),),
}


@router.get("/alerts", response_model=PaginatedAlerts)
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("priority", pattern="^(priority|recent)$"),
    attack_family: str | None = Query(None, description="Lọc theo họ tấn công GỢI Ý (MR13) — khớp CHÍNH XÁC"),
    rule_id: str | None = Query(None, description="Lọc theo mã luật đã sinh ra cảnh báo (MR12)"),
    campaign_id: int | None = Query(None, description="Lọc theo chiến dịch (MR14)"),
    status: str | None = Query(None, pattern="^(open|acknowledged|resolved|false_positive)$", description="Lọc theo trạng thái xử lý (MR12/15)"),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_admin),
):
    query = db.query(Alert)
    if attack_family:
        query = query.filter(Alert.attack_family == attack_family)
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id)
    if campaign_id is not None:
        query = query.filter(Alert.campaign_id == campaign_id)
    if status:
        query = query.filter(Alert.status == status)

    query = query.order_by(*_SORTS[sort])
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedAlerts(items=items, total=total, page=page, page_size=page_size)


@router.post("/alerts/{alert_id}/feedback", response_model=AlertOut)
def submit_alert_feedback(
    alert_id: int,
    payload: AlertFeedbackRequest,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Không thấy cảnh báo")

    # Cho phép GHI ĐÈ (quản trị viên đổi ý) — mỗi lần vẫn thêm một dòng audit_log MỚI (nhật ký không xoá lịch sử cũ).
    alert.status = "resolved" if payload.correct else "false_positive"
    alert.feedback = payload.note

    db.add(
        AuditLog(
            actor=admin.get("username", "admin"),
            action="feedback_correct" if payload.correct else "feedback_false_positive",
            target_type="alert",
            target_id=alert.id,
            detail={"note": payload.note, "user_id": alert.user_id, "alert_type": alert.alert_type},
        )
    )
    db.commit()
    db.refresh(alert)
    return alert
