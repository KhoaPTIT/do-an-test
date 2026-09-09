"""Endpoint quản lý cảnh báo và hành động của quản trị viên."""
from datetime import datetime

from app.utils.timeutil import utcnow
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, BlockedIP, LoginEvent
from app.schemas import AlertOut, AlertUpdate, BlockIPIn
from app.security import require_api_key

router = APIRouter(prefix="/api/v1", tags=["alerts"])


def _to_out(alert: Alert) -> AlertOut:
    """Gộp thông tin cảnh báo với sự kiện gốc để dashboard chỉ cần gọi 1 lần."""
    ev = alert.event
    return AlertOut(
        id=alert.id, event_id=alert.event_id, severity=alert.severity,
        title=alert.title, description=alert.description,
        status=alert.status, analyst_note=alert.analyst_note,
        created_at=alert.created_at, resolved_at=alert.resolved_at,
        username=ev.username if ev else None,
        ip_address=ev.ip_address if ev else None,
        country=ev.country if ev else None,
        city=ev.city if ev else None,
        risk_score=ev.risk_score if ev else None,
        decision=ev.decision if ev else None,
        rule_hits=ev.rule_hits if ev else None,
        timestamp=ev.timestamp if ev else None,
    )


@router.get("/alerts", response_model=List[AlertOut],
            dependencies=[Depends(require_api_key)])
def list_alerts(status: Optional[str] = None,
                severity: Optional[str] = None,
                limit: int = Query(100, le=500),
                offset: int = 0,
                db: Session = Depends(get_db)):
    q = db.query(Alert)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    rows = q.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
    return [_to_out(a) for a in rows]


@router.get("/alerts/{alert_id}", response_model=AlertOut,
            dependencies=[Depends(require_api_key)])
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(404, "Không tìm thấy cảnh báo")
    return _to_out(alert)


@router.patch("/alerts/{alert_id}", response_model=AlertOut,
              dependencies=[Depends(require_api_key)])
def update_alert(alert_id: int, payload: AlertUpdate,
                 db: Session = Depends(get_db)):
    """Quản trị viên cập nhật trạng thái xử lý cảnh báo.

    Đây là điểm bắt đầu của vòng phản hồi: khi analyst đánh dấu một cảnh báo
    là báo động giả, nhãn đó được ghi ngược vào sự kiện gốc và sẽ được
    ml/retrain_from_feedback.py dùng để huấn luyện lại mô hình.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(404, "Không tìm thấy cảnh báo")

    alert.status = payload.status
    alert.analyst_note = payload.analyst_note
    if payload.status in ("resolved", "false_positive"):
        alert.resolved_at = utcnow()

    # Ghi nhãn ngược vào sự kiện gốc
    if alert.event is not None:
        if payload.status == "false_positive":
            alert.event.is_attack = False
            alert.event.attack_type = None
        elif payload.status == "resolved":
            alert.event.is_attack = True
            alert.event.attack_type = alert.event.attack_type or "confirmed_by_analyst"

    db.commit()
    db.refresh(alert)
    return _to_out(alert)


@router.post("/blocked-ips", dependencies=[Depends(require_api_key)])
def block_ip(payload: BlockIPIn, db: Session = Depends(get_db)):
    """Chặn một địa chỉ IP. Các lần đăng nhập sau từ IP này bị từ chối ngay."""
    existing = db.query(BlockedIP).filter(
        BlockedIP.ip_address == payload.ip_address).first()
    if existing:
        return {"ip_address": payload.ip_address, "status": "đã bị chặn trước đó"}

    db.add(BlockedIP(ip_address=payload.ip_address, reason=payload.reason))
    db.commit()
    return {"ip_address": payload.ip_address, "status": "đã chặn"}


@router.get("/blocked-ips", dependencies=[Depends(require_api_key)])
def list_blocked(db: Session = Depends(get_db)):
    return db.query(BlockedIP).order_by(BlockedIP.created_at.desc()).all()


@router.delete("/blocked-ips/{ip_address}", dependencies=[Depends(require_api_key)])
def unblock_ip(ip_address: str, db: Session = Depends(get_db)):
    row = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
    if row is None:
        raise HTTPException(404, "IP không có trong danh sách chặn")
    db.delete(row)
    db.commit()
    return {"ip_address": ip_address, "status": "đã bỏ chặn"}
