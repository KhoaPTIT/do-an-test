"""Pydantic schema cho request/response — field snake_case theo docs/api-contract.md."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    success: bool
    message: str


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
    is_synthetic: bool
    created_at: datetime


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


class PaginatedAlerts(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int
