"""Schema 6 bảng gốc (Tuần 1) + bảng `admins` bổ sung ở Tuần 5 — xem mô tả
đầy đủ ở docs/db-schema.md.

Quy ước: tên bảng số nhiều snake_case, PK luôn là `id` (trừ user_baseline
dùng user_id vì quan hệ 1-1), FK đặt tên `<bảng_số_ít>_id`, mọi timestamp
kết thúc bằng `_at`.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    """Tài khoản của web app mẫu — người dùng cuối đăng nhập, không phải admin."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    login_events: Mapped[list["LoginEvent"]] = relationship(back_populates="user")
    baseline: Mapped["UserBaseline"] = relationship(back_populates="user", uselist=False)
    known_devices: Mapped[list["KnownDevice"]] = relationship(back_populates="user")
    known_locations: Mapped[list["KnownLocation"]] = relationship(back_populates="user")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="user")


class LoginEvent(Base):
    """Một lần thử đăng nhập — thành công hay thất bại đều được ghi lại.

    Bảng quan trọng nhất của hệ thống: mọi rule ở Tuần 3-4 truy vấn từ đây.
    """

    __tablename__ = "login_events"
    __table_args__ = (
        Index("ix_login_events_user_created", "user_id", "created_at"),
        Index("ix_login_events_ip_address", "ip_address"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Nullable: username gửi lên không tồn tại (dò tài khoản) vẫn phải log lại.
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    attempted_username: Mapped[str] = mapped_column(String(64), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # đủ chỗ cho IPv6
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Kết quả tra GeoIP (Tuần 3) — để NULL khi lookup thất bại thay vì raise lỗi.
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Điền bởi detection engine (Tuần 4)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Điểm bất thường từ ML tầng 3 (Tuần 7) — CHẠY SONG SONG risk_score, không
    # thay thế. Càng cao càng bất thường theo Isolation Forest, thang không cố định.
    ml_anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Đánh dấu dữ liệu giả lập để tách khỏi dữ liệu demo thật (nhiệm vụ 2.3)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User | None"] = relationship(back_populates="login_events")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="login_event")


class UserBaseline(Base):
    """Hồ sơ hành vi 'bình thường' của user, dùng cho behavioral scoring (Tuần 4)."""

    __tablename__ = "user_baseline"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    avg_login_hour: Mapped[float | None] = mapped_column(Float, nullable=True)
    stddev_login_hour: Mapped[float | None] = mapped_column(Float, nullable=True)
    # < 10 => vẫn ở "chế độ học" (mục 4.1), chưa áp rule phụ thuộc baseline.
    successful_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="baseline")


class KnownDevice(Base):
    """Thiết bị (theo fingerprint) đã từng đăng nhập thành công."""

    __tablename__ = "known_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    device_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="known_devices")


class KnownLocation(Base):
    """Vị trí (quốc gia/thành phố) đã từng đăng nhập thành công."""

    __tablename__ = "known_locations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="known_locations")


class Alert(Base):
    """Cảnh báo sinh ra khi rule tầng 1 khớp hoặc risk_score vượt ngưỡng (mục 4.2: >70 = cao)."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    login_event_id: Mapped[int] = mapped_column(ForeignKey("login_events.id"), nullable=False, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    # brute_force | credential_stuffing | impossible_travel | high_risk_score | ml_anomaly (Tuần 7)
    alert_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # low | medium | high — ánh xạ từ risk_score theo mục 4.2 (<40 / 40-70 / >70)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    login_event: Mapped["LoginEvent"] = relationship(back_populates="alerts")
    user: Mapped["User | None"] = relationship(back_populates="alerts")


class Admin(Base):
    """Tài khoản quản trị (nhiệm vụ 5.1) — TÁCH BIỆT HOÀN TOÀN khỏi `users`
    (web app mẫu). Không liên kết FK với users/login_events/alerts.
    """

    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
