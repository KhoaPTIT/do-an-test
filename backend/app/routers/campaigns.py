"""GET /campaigns, GET /campaigns/{id} — API "chiến dịch" (MR14): chiến dịch được `app/detection/pipeline.py` gán khi
nhiều tài khoản KHÁC NHAU bị tấn công từ CÙNG hạ tầng (IP/ASN) trong 24h (`app/detection/campaign_correlation.py`).

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1) — xem app/dependencies.py.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import Alert, Campaign, LoginEvent, User
from app.schemas import (
    CampaignDetail,
    CampaignGraph,
    CampaignGraphEdge,
    CampaignGraphNode,
    CampaignOut,
    CampaignTimelineItem,
    PaginatedCampaigns,
)

router = APIRouter()


def _targeted_accounts_count(db: Session, campaign_id: int) -> int:
    """Số tài khoản KHÁC NHAU bị nhắm: user_id khác NULL đếm phân biệt, CỘNG 1 nếu có ít nhất một alert nhắm vào
    tên đăng nhập KHÔNG TỒN TẠI (mọi tên không tồn tại gộp thành một mục "tài khoản không tồn tại" trên UI)."""
    distinct_users = db.query(func.count(func.distinct(Alert.user_id))).filter(Alert.campaign_id == campaign_id, Alert.user_id.isnot(None)).scalar() or 0
    has_unknown = db.query(Alert.id).filter(Alert.campaign_id == campaign_id, Alert.user_id.is_(None)).first() is not None
    return distinct_users + (1 if has_unknown else 0)


def _campaign_out(db: Session, campaign: Campaign) -> CampaignOut:
    return CampaignOut(
        id=campaign.id, label=campaign.label, attack_family=campaign.attack_family, status=campaign.status,
        alert_count=campaign.alert_count, targeted_accounts=_targeted_accounts_count(db, campaign.id),
        first_seen_at=campaign.first_seen_at, last_seen_at=campaign.last_seen_at,
    )


@router.get("/campaigns", response_model=PaginatedCampaigns)
def list_campaigns(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status", pattern="^(open|closed)$"),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_admin),
):
    query = db.query(Campaign)
    if status_filter:
        query = query.filter(Campaign.status == status_filter)
    query = query.order_by(Campaign.last_seen_at.desc())
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedCampaigns(items=[_campaign_out(db, c) for c in items], total=total, page=page, page_size=page_size)


@router.get("/campaigns/{campaign_id}", response_model=CampaignDetail)
def get_campaign(campaign_id: int, db: Session = Depends(get_db), _admin: dict = Depends(require_admin)):
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Không thấy chiến dịch")

    rows = (
        db.query(Alert, LoginEvent, User)
        .join(LoginEvent, Alert.login_event_id == LoginEvent.id)
        .outerjoin(User, Alert.user_id == User.id)
        .filter(Alert.campaign_id == campaign_id)
        .order_by(Alert.created_at)
        .all()
    )

    timeline = [
        CampaignTimelineItem(
            alert_id=a.id, user_id=a.user_id, username=user.username if user is not None else None,
            alert_type=a.alert_type, severity=a.severity, risk_score=a.risk_score, message=a.message, created_at=a.created_at,
        )
        for a, le, user in rows
    ]
    targeted_usernames = sorted({user.username for _, _, user in rows if user is not None})
    if any(user is None for _, _, user in rows):
        targeted_usernames.append("(tên đăng nhập không tồn tại)")

    nodes: dict[str, CampaignGraphNode] = {}
    edges: set[tuple[str, str]] = set()

    def node(kind: str, key: str, label: str) -> str:
        node_id = f"{kind}:{key}"
        nodes.setdefault(node_id, CampaignGraphNode(id=node_id, kind=kind, label=label))
        return node_id

    for _a, le, user in rows:
        user_label = user.username if user is not None else f"? {le.attempted_username}"
        user_node = node("user", user_label, user_label)
        if le.ip_address:
            edges.add((user_node, node("ip", le.ip_address, le.ip_address)))
        if le.asn is not None:
            edges.add((user_node, node("asn", str(le.asn), f"AS{le.asn}")))
        if le.device_type and le.device_type != "unknown":
            edges.add((user_node, node("device", le.device_type, le.device_type)))

    graph = CampaignGraph(nodes=list(nodes.values()), edges=[CampaignGraphEdge(source=s, target=t) for s, t in sorted(edges)])

    base = _campaign_out(db, campaign)
    return CampaignDetail(**base.model_dump(), timeline=timeline, targeted_usernames=targeted_usernames, graph=graph)
