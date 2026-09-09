"""Các bảng dữ liệu của hệ thống."""
from datetime import datetime

from app.utils.timeutil import utcnow

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey,
                        Index, Integer, String)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    """Tài khoản được hệ thống giám sát."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255))
    created_at = Column(DateTime, default=utcnow)


class LoginEvent(Base):
    """Một lần đăng nhập, thành công hay thất bại đều được ghi nhận."""
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    username = Column(String(100), index=True, nullable=False)

    # Thông tin mạng và vị trí
    ip_address = Column(String(45), index=True, nullable=False)
    country = Column(String(80))
    city = Column(String(120))
    latitude = Column(Float)
    longitude = Column(Float)
    network_type = Column(String(30))   # residential / hosting / tor / unknown

    # Thông tin thiết bị
    user_agent = Column(String(512))
    device_type = Column(String(50))
    os_family = Column(String(50))
    browser_family = Column(String(50))
    device_fingerprint = Column(String(64), index=True)

    login_successful = Column(Boolean, default=True, nullable=False)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)

    # Kết quả phân tích
    risk_score = Column(Float, default=0.0)
    rule_score = Column(Float, default=0.0)
    ml_score = Column(Float)
    decision = Column(String(20), index=True)     # allow / challenge / block
    rule_hits = Column(JSON, default=list)

    # Nhãn thật, chỉ có khi sinh dữ liệu mô phỏng hoặc analyst xác nhận.
    # Dùng để tính Precision / Recall ở phần đánh giá.
    is_attack = Column(Boolean, default=False, index=True)
    attack_type = Column(String(50))

    alerts = relationship("Alert", back_populates="event",
                          cascade="all, delete-orphan")

    __table_args__ = (Index("ix_user_time", "user_id", "timestamp"),)


class Alert(Base):
    """Cảnh báo sinh ra khi một sự kiện vượt ngưỡng rủi ro."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey("login_events.id"), nullable=False)

    severity = Column(String(20), index=True)   # low / medium / high / critical
    title = Column(String(255))
    description = Column(String(1000))

    # open -> investigating -> resolved | false_positive
    status = Column(String(30), default="open", index=True)
    analyst_note = Column(String(1000))

    created_at = Column(DateTime, default=utcnow, index=True)
    resolved_at = Column(DateTime)

    event = relationship("LoginEvent", back_populates="alerts")


class BlockedIP(Base):
    """Danh sách IP bị analyst chặn từ dashboard."""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    reason = Column(String(255))
    created_at = Column(DateTime, default=utcnow)
