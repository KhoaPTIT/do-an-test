"""Khai báo dữ liệu vào ra của API, kèm kiểm tra hợp lệ."""
import ipaddress
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class LoginEventIn(BaseModel):
    """Dữ liệu ứng dụng gửi lên mỗi khi có một lần đăng nhập."""
    username: str = Field(..., min_length=1, max_length=100)
    ip_address: str = Field(..., max_length=45)
    user_agent: str = Field("", max_length=512)
    login_successful: bool = True
    timestamp: Optional[datetime] = None

    # Chỉ dùng khi nạp dữ liệu mô phỏng, ứng dụng thật không gửi trường này.
    is_attack: bool = False
    attack_type: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def check_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Địa chỉ IP không hợp lệ")
        return v

    @field_validator("username")
    @classmethod
    def strip_username(cls, v: str) -> str:
        return v.strip()


class RuleHit(BaseModel):
    code: str
    name: str
    score: int
    detail: str


class RiskResponse(BaseModel):
    event_id: int
    risk_score: float
    rule_score: float
    ml_score: Optional[float]
    decision: str
    severity: str
    mode: str
    rule_hits: List[RuleHit]


class AlertOut(BaseModel):
    id: int
    event_id: int
    severity: str
    title: str
    description: Optional[str]
    status: str
    analyst_note: Optional[str]
    created_at: datetime
    resolved_at: Optional[datetime]

    username: Optional[str] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    risk_score: Optional[float] = None
    decision: Optional[str] = None
    rule_hits: Optional[list] = None
    timestamp: Optional[datetime] = None


class AlertUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|investigating|resolved|false_positive)$")
    analyst_note: str = Field("", max_length=1000)


class EventOut(BaseModel):
    id: int
    username: str
    ip_address: str
    country: Optional[str]
    city: Optional[str]
    device_type: Optional[str]
    login_successful: bool
    timestamp: datetime
    risk_score: Optional[float]
    rule_score: Optional[float]
    ml_score: Optional[float]
    decision: Optional[str]
    rule_hits: Optional[list]
    is_attack: bool

    model_config = {"from_attributes": True}


class BlockIPIn(BaseModel):
    ip_address: str
    reason: str = Field("", max_length=255)

    @field_validator("ip_address")
    @classmethod
    def check_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)
        return v
