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

    # MR12: gắn với luật/mô hình đã sinh ra cảnh báo, giải thích, chiến dịch (MR13), trạng thái xử lý chi tiết hơn `resolved`
    rule_id: str | None = None
    attack_family: str | None = None
    explanation: dict | None = None
    campaign_id: int | None = None
    status: str = "open"


class PaginatedAlerts(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int
