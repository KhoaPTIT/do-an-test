"""Pydantic schema cho request/response — field snake_case theo docs/api-contract.md."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    success: bool
    message: str


class AdminLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class AdminLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginEventOut(BaseModel):
    """Dùng cho GET /login-events (nhiệm vụ 4.3)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None
    attempted_username: str
    success: bool
    ip_address: str
    country: str | None
    city: str | None
    risk_score: int | None
    ml_anomaly_score: float | None
    is_synthetic: bool
    created_at: datetime

    # MR12: parse UA + tra ASN trong pipeline nền, điểm/hành động của hybrid risk engine (MR11)
    asn: int | None = None
    os_name: str | None = None
    browser_name: str | None = None
    device_type: str | None = None
    hybrid_risk_score: int | None = None
    hybrid_action: str | None = None


class PaginatedLoginEvents(BaseModel):
    items: list[LoginEventOut]
    total: int
    page: int
    page_size: int


class AlertOut(BaseModel):
    """Dùng cho GET /alerts (nhiệm vụ 4.3)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    login_event_id: int
    user_id: int | None
    alert_type: str
    severity: str
    risk_score: int
    message: str
    resolved: bool
    created_at: datetime

    # MR12: gắn với luật/mô hình đã sinh ra cảnh báo, giải thích, chiến dịch (MR14), trạng thái xử lý chi tiết hơn `resolved`
    rule_id: str | None = None
    attack_family: str | None = None
    explanation: dict | None = None
    campaign_id: int | None = None
    status: str = "open"

    # MR13: cảnh báo thông minh v2 — attack_family (trên) LUÔN là GỢI Ý, độ tin cậy đi kèm ở đây; chống trùng lặp; ưu tiên
    attack_family_confidence: float | None = None
    occurrence_count: int = 1
    last_seen_at: datetime | None = None
    priority_score: float | None = None


class PaginatedAlerts(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int


# --------------------------------------------------------------------------------------------- MR14: chiến dịch


class CampaignOut(BaseModel):
    """Dùng cho GET /campaigns — danh sách chiến dịch (MR14)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    label: str
    attack_family: str | None
    status: str
    alert_count: int
    targeted_accounts: int  # số tài khoản KHÁC NHAU bị nhắm — tính lúc truy vấn, không lưu cột riêng (tránh state lệch)
    first_seen_at: datetime
    last_seen_at: datetime


class PaginatedCampaigns(BaseModel):
    items: list[CampaignOut]
    total: int
    page: int
    page_size: int


class CampaignTimelineItem(BaseModel):
    """Một alert trong chiến dịch, sắp theo thời gian — nhiệm vụ 'timeline' của trang chiến dịch."""

    alert_id: int
    user_id: int | None
    username: str | None  # None nếu tài khoản không tồn tại (tên đăng nhập bị dò)
    alert_type: str
    severity: str
    risk_score: int
    message: str
    created_at: datetime


class CampaignGraphNode(BaseModel):
    id: str  # "user:alice" | "ip:1.2.3.4" | "asn:15169" | "device:mobile"
    kind: str  # "user" | "ip" | "asn" | "device"
    label: str


class CampaignGraphEdge(BaseModel):
    source: str
    target: str


class CampaignGraph(BaseModel):
    nodes: list[CampaignGraphNode]
    edges: list[CampaignGraphEdge]


class CampaignDetail(CampaignOut):
    """GET /campaigns/{id} — thêm timeline, danh sách tài khoản bị nhắm, đồ thị liên kết user-IP-ASN-thiết bị."""

    timeline: list[CampaignTimelineItem]
    targeted_usernames: list[str]
    graph: CampaignGraph
