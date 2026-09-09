"""Endpoint tiếp nhận và chấm điểm sự kiện đăng nhập."""
from datetime import datetime

from app.utils.timeutil import utcnow
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.config import LOOKBACK_DAYS
from app.database import get_db
from app.detection.features import EventData, build_context_from_db
from app.detection.scoring import assess
from app.models import Alert, BlockedIP, LoginEvent, User
from app.schemas import EventOut, LoginEventIn, RiskResponse
from app.security import require_api_key
from app.utils.device import fingerprint, parse_ua
from app.utils.geoip import lookup_ip

router = APIRouter(prefix="/api/v1", tags=["events"])


def _get_or_create_user(db: Session, username: str) -> User:
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        user = User(username=username)
        db.add(user)
        db.flush()
    return user


@router.post("/login-event", response_model=RiskResponse,
             dependencies=[Depends(require_api_key)])
def ingest_login_event(payload: LoginEventIn, db: Session = Depends(get_db)):
    """Nhận một sự kiện đăng nhập, chấm điểm rủi ro và trả về quyết định.

    Ứng dụng gọi endpoint này ngay sau khi kiểm tra mật khẩu, rồi dựa vào
    trường decision để cho qua, bắt xác thực hai lớp, hay từ chối.
    """
    ts = payload.timestamp or utcnow()
    geo = lookup_ip(payload.ip_address)
    dev = parse_ua(payload.user_agent)

    user = _get_or_create_user(db, payload.username)

    event = EventData(
        username=payload.username,
        ip_address=payload.ip_address,
        timestamp=ts,
        login_successful=payload.login_successful,
        country=geo["country"], city=geo["city"],
        latitude=geo["lat"], longitude=geo["lon"],
        network_type=geo["network_type"],
        device_fingerprint=fingerprint(payload.user_agent, payload.ip_address),
        device_type=dev["device_type"],
        user_agent=payload.user_agent,
    )

    ctx = build_context_from_db(db, event, lookback_days=LOOKBACK_DAYS)
    result = assess(event, ctx)

    # IP đã bị analyst chặn thì chặn thẳng, không cần chấm điểm lại
    if db.query(BlockedIP).filter(BlockedIP.ip_address == payload.ip_address).first():
        result["decision"] = "block"
        result["risk_score"] = 100.0
        result["severity"] = "critical"
        result["rule_hits"].append({
            "code": "R00", "name": "IP trong danh sách chặn", "score": 100,
            "detail": "Địa chỉ IP đã bị quản trị viên chặn thủ công.",
        })

    row = LoginEvent(
        user_id=user.id, username=payload.username,
        ip_address=payload.ip_address,
        country=event.country, city=event.city,
        latitude=event.latitude, longitude=event.longitude,
        network_type=event.network_type,
        user_agent=payload.user_agent, device_type=dev["device_type"],
        os_family=dev["os"], browser_family=dev["browser"],
        device_fingerprint=event.device_fingerprint,
        login_successful=payload.login_successful, timestamp=ts,
        risk_score=result["risk_score"], rule_score=result["rule_score"],
        ml_score=result["ml_score"], decision=result["decision"],
        rule_hits=result["rule_hits"],
        is_attack=payload.is_attack, attack_type=payload.attack_type,
    )
    db.add(row)
    db.flush()

    if result["decision"] in ("challenge", "block"):
        reasons = "; ".join(h["detail"] for h in result["rule_hits"])
        db.add(Alert(
            event_id=row.id,
            severity=result["severity"],
            title=f"Đăng nhập rủi ro: {payload.username}",
            description=reasons or "Mô hình học máy phát hiện hành vi lệch chuẩn.",
        ))

    db.commit()
    return RiskResponse(event_id=row.id, **result)


@router.get("/events", response_model=List[EventOut],
            dependencies=[Depends(require_api_key)])
def list_events(username: Optional[str] = None,
                decision: Optional[str] = None,
                min_risk: float = 0.0,
                limit: int = Query(100, le=1000),
                offset: int = 0,
                db: Session = Depends(get_db)):
    """Danh sách sự kiện cho dashboard, có lọc."""
    q = db.query(LoginEvent)
    if username:
        q = q.filter(LoginEvent.username.ilike(f"%{username}%"))
    if decision:
        q = q.filter(LoginEvent.decision == decision)
    if min_risk > 0:
        q = q.filter(LoginEvent.risk_score >= min_risk)
    return (q.order_by(LoginEvent.timestamp.desc())
             .offset(offset).limit(limit).all())


@router.get("/events/{event_id}", response_model=EventOut,
            dependencies=[Depends(require_api_key)])
def get_event(event_id: int, db: Session = Depends(get_db)):
    return db.query(LoginEvent).filter(LoginEvent.id == event_id).first()


@router.get("/users/{username}/history", response_model=List[EventOut],
            dependencies=[Depends(require_api_key)])
def user_history(username: str, limit: int = Query(30, le=200),
                 db: Session = Depends(get_db)):
    """Lịch sử đăng nhập gần đây của một tài khoản.

    Analyst cần màn hình này để phán đoán: lần đăng nhập đang xét
    có thật sự lệch khỏi thói quen của người dùng hay không.
    """
    return (db.query(LoginEvent)
              .filter(LoginEvent.username == username)
              .order_by(LoginEvent.timestamp.desc())
              .limit(limit).all())
