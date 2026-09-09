"""Số liệu tổng hợp phục vụ dashboard."""
from datetime import datetime, timedelta

from app.utils.timeutil import utcnow

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection.ml_model import model_info
from app.models import Alert, LoginEvent
from app.security import require_api_key

router = APIRouter(prefix="/api/v1/stats", tags=["stats"])


@router.get("/overview", dependencies=[Depends(require_api_key)])
def overview(db: Session = Depends(get_db)):
    now = utcnow()
    day_ago = now - timedelta(hours=24)

    total = db.query(LoginEvent).count()
    events_24h = db.query(LoginEvent).filter(LoginEvent.timestamp >= day_ago).count()
    blocked_24h = (db.query(LoginEvent)
                     .filter(LoginEvent.decision == "block",
                             LoginEvent.timestamp >= day_ago).count())
    challenged_24h = (db.query(LoginEvent)
                        .filter(LoginEvent.decision == "challenge",
                                LoginEvent.timestamp >= day_ago).count())
    open_alerts = db.query(Alert).filter(Alert.status == "open").count()
    avg_risk = db.query(func.avg(LoginEvent.risk_score)).filter(
        LoginEvent.timestamp >= day_ago).scalar()

    return {
        "total_events": total,
        "events_24h": events_24h,
        "blocked_24h": blocked_24h,
        "challenged_24h": challenged_24h,
        "open_alerts": open_alerts,
        "avg_risk_24h": round(avg_risk or 0.0, 1),
        "model": model_info(),
    }


@router.get("/timeline", dependencies=[Depends(require_api_key)])
def timeline(days: int = Query(7, ge=1, le=90), db: Session = Depends(get_db)):
    """Số sự kiện và số lần bị chặn theo từng ngày."""
    since = utcnow() - timedelta(days=days)
    rows = (db.query(LoginEvent.timestamp, LoginEvent.decision)
              .filter(LoginEvent.timestamp >= since).all())

    buckets = {}
    for ts, decision in rows:
        key = ts.date().isoformat()
        b = buckets.setdefault(key, {"date": key, "total": 0,
                                     "challenge": 0, "block": 0})
        b["total"] += 1
        if decision in ("challenge", "block"):
            b[decision] += 1

    return sorted(buckets.values(), key=lambda r: r["date"])


@router.get("/rule-frequency", dependencies=[Depends(require_api_key)])
def rule_frequency(db: Session = Depends(get_db)):
    """Rule nào kích hoạt nhiều nhất, kèm tỷ lệ báo động giả của rule đó.

    Đây là số liệu để hiệu chỉnh: rule nào sinh nhiều báo động giả
    thì nên giảm điểm hoặc siết lại điều kiện.
    """
    events = (db.query(LoginEvent)
                .filter(LoginEvent.rule_hits.isnot(None)).all())

    stats = {}
    fp_event_ids = {
        a.event_id for a in db.query(Alert).filter(
            Alert.status == "false_positive").all()
    }

    for ev in events:
        for hit in (ev.rule_hits or []):
            code = hit.get("code", "?")
            s = stats.setdefault(code, {
                "code": code, "name": hit.get("name", ""),
                "count": 0, "false_positive": 0,
            })
            s["count"] += 1
            if ev.id in fp_event_ids:
                s["false_positive"] += 1

    out = []
    for s in stats.values():
        s["fp_rate"] = round(s["false_positive"] / s["count"] * 100, 1) if s["count"] else 0.0
        out.append(s)
    return sorted(out, key=lambda r: -r["count"])


@router.get("/geo", dependencies=[Depends(require_api_key)])
def geo_distribution(limit: int = 15, db: Session = Depends(get_db)):
    """Phân bố sự kiện theo quốc gia, kèm số lần bị chặn."""
    rows = (db.query(LoginEvent.country,
                     func.count(LoginEvent.id).label("total"))
              .group_by(LoginEvent.country)
              .order_by(func.count(LoginEvent.id).desc())
              .limit(limit).all())

    blocked = dict(
        db.query(LoginEvent.country, func.count(LoginEvent.id))
          .filter(LoginEvent.decision == "block")
          .group_by(LoginEvent.country).all()
    )

    return [{"country": c or "Unknown", "total": t,
             "blocked": blocked.get(c, 0)} for c, t in rows]
