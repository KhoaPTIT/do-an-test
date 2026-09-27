"""Schema 6 bảng gốc (Tuần 1) + `admins` (Tuần 5) + 5 bảng mới của MR12 (`campaigns`, `blocklist`, `response_actions`,
`audit_log`, `model_registry`) — xem mô tả đầy đủ ở docs/db-schema.md.

Quy ước: tên bảng số nhiều snake_case, PK luôn là `id` (trừ user_baseline
dùng user_id vì quan hệ 1-1), FK đặt tên `<bảng_số_ít>_id`, mọi timestamp
kết thúc bằng `_at`.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
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
    # MR13: hệ số nhân trong công thức xếp hạng ưu tiên cảnh báo (novelty × độ tin cậy × importance, xem
    # app/detection/alert_intelligence.py). Demo KHÔNG có khái niệm "tài khoản quan trọng" thật (không role/tier) nên
    # mặc định 1.0 cho mọi user — placeholder có chủ đích cho hệ thống thật (ví dụ gắn theo phòng ban/chức vụ từ HR),
    # chỉnh tay qua script/DB để kiểm chứng công thức hoạt động đúng khi khác nhau.
    importance: Mapped[float] = mapped_column(Float, default=1.0, server_default="1.0", nullable=False)

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
        Index("ix_login_events_asn", "asn"),
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

    # --- MR12: parse UA + tra ASN trong pipeline nền, cùng schema với RBA (ml/rba/features.py) để đặc trưng
    # tính từ luồng thật và đặc trưng huấn luyện trên RBA có cùng ý nghĩa. NULL khi tra/parse thất bại, không raise.
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    browser_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(16), nullable=True)  # mobile | desktop | tablet | bot | unknown (app/utils/device.py)

    # Điểm 0-100 và hành động của hybrid risk engine (MR11: app/detection/hybrid/) — CHẠY SONG SONG risk_score/ml_anomaly_score,
    # không thay thế. hybrid_action: allow | alert | step_up | lock (chỉ là ĐỀ XUẤT, xem bảng response_actions — chưa tự khoá tài khoản).
    hybrid_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hybrid_action: Mapped[str | None] = mapped_column(String(16), nullable=True)

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
    __table_args__ = (Index("ix_alerts_dedup_lookup", "user_id", "attack_family", "status"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    login_event_id: Mapped[int] = mapped_column(ForeignKey("login_events.id"), nullable=False, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    # brute_force | credential_stuffing | impossible_travel | high_risk_score | ml_anomaly (Tuần 7) | hybrid_risk (MR12)
    alert_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # low | medium | high — ánh xạ từ risk_score theo mục 4.2 (<40 / 40-70 / >70)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    # --- MR12: gắn cảnh báo với luật/mô hình đã sinh ra nó và với chiến dịch (MR13 gom thành campaign) ---
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # mã luật (app/detection/engine/registry.py) đã khớp; None nếu chỉ do ML/tầng 1-2 cũ
    attack_family: Mapped[str | None] = mapped_column(String(64), nullable=True)  # dự trữ cho MR13 (gán họ tấn công)
    explanation: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # danh sách đóng góp (RiskResult.contributions của MR11), để hiển thị "vì sao"
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    # open | acknowledged | resolved | false_positive — cờ `resolved` cũ GIỮ NGUYÊN (tương thích ngược); `status` chi tiết hơn cho MR13/14
    status: Mapped[str] = mapped_column(String(16), server_default="open", nullable=False)
    feedback: Mapped[str | None] = mapped_column(Text, nullable=True)  # phản hồi ngắn của quản trị viên (đúng/sai cảnh báo, ghi chú)

    # --- MR13: cảnh báo thông minh v2 (app/detection/alert_intelligence.py) ---
    # độ tin cậy [0,1] của attack_family (= trọng số của bằng chứng dẫn đầu trong RiskResult.contributions) — LUÔN là gợi ý, không phải khẳng định
    attack_family_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    # chống trùng lặp: cùng (user_id hoặc IP) + attack_family trong cửa sổ ngắn GỘP vào 1 hàng thay vì tạo hàng mới (xem dedup_window trong alert_intelligence.py)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1", nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # novelty_level × attack_family_confidence × User.importance — dùng để sắp xếp GET /alerts (mặc định), không thay severity/risk_score
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    login_event: Mapped["LoginEvent"] = relationship(back_populates="alerts")
    user: Mapped["User | None"] = relationship(back_populates="alerts")
    campaign: Mapped["Campaign | None"] = relationship(back_populates="alerts")


class Admin(Base):
    """Tài khoản quản trị (nhiệm vụ 5.1) — TÁCH BIỆT HOÀN TOÀN khỏi `users`
    (web app mẫu). Không liên kết FK với users/login_events/alerts.
    """

    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ------------------------------------------------------------------------------------------------ MR12: 5 bảng mới cho tích hợp realtime


class Campaign(Base):
    """Gom nhiều `Alert` được coi là CÙNG một đợt tấn công (MR14 "tương quan chiến dịch" quyết định gán alert nào vào
    campaign nào dựa trên IP/ASN/UA/khoảng thời gian gần nhau; MR12 chỉ tạo bảng và cột `campaign_id` trên `alerts` để
    dùng ngay, MR13 vẫn chưa gán gì vào đây — MR13 chỉ chống trùng lặp CÙNG một (user/IP, họ tấn công), khác với gom
    chiến dịch CÙNG hạ tầng NHIỀU tài khoản của MR14)."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    attack_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), server_default="open", nullable=False)  # open | closed
    alert_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="campaign")


class BlocklistEntry(Base):
    """Bản lưu DB của `app.detection.engine.intel.Blocklist` (MR9: trong bộ nhớ, dùng cho replay/test). Luồng thật nạp lại bảng này thành một
    `Blocklist` trong bộ nhớ mỗi lần chấm (có cache TTL ngắn — `app/detection/rule_engine_runtime.py`), vì `Blocklist.match()` cần tra cứu nhanh,
    không phải truy vấn SQL cho mỗi lần đăng nhập. Chưa có hành động chặn THẬT (từ chối đăng nhập) — luật `blocklist_hit` mới chỉ tạo cảnh báo/ghi
    đè điểm rủi ro; hành động chặn thật là việc của MR16."""

    __tablename__ = "blocklist"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_blocklist_kind_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # ip | cidr | asn | username (app/detection/engine/intel.py BLOCK_KINDS)
    value: Mapped[str] = mapped_column(String(128), nullable=False)  # đã chuẩn hoá (Blocklist._normalize): IP/CIDR dạng chính tắc, ASN là số, username viết thường
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by: Mapped[str] = mapped_column(String(64), server_default="admin", nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # None = vĩnh viễn
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ResponseAction(Base):
    """Hành động ứng phó mà hybrid risk engine (MR11) ĐỀ XUẤT khi điểm gộp đạt mức `step_up` hoặc `lock` (`app.detection.hybrid.combine_risk`),
    hoặc do luật ghi đè (`overridden_by`). `status='recommended'` nghĩa là mới chỉ ghi nhận đề xuất — CHƯA có gì thực thi việc khoá/yêu cầu xác
    thực thêm thật sự (không có luồng MFA/khoá tài khoản ở web app mẫu); thực thi thật là việc của MR16, đúng như luật `blocklist_hit` đã ghi chú."""

    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    login_event_id: Mapped[int | None] = mapped_column(ForeignKey("login_events.id"), nullable=True, index=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    action: Mapped[str] = mapped_column(String(16), nullable=False)  # step_up | lock (app.detection.hybrid.calibration.ACTIONS, trừ allow/alert)
    status: Mapped[str] = mapped_column(String(16), server_default="recommended", nullable=False)  # recommended | executed | reverted
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), server_default="system", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """Nhật ký thao tác chung (MR12): ai/cái gì làm gì lên tài nguyên nào. Hiện chỉ được ghi tự động bởi hệ thống khi tạo `ResponseAction`
    (`actor='system'`); quản trị viên thao tác tay (duyệt cảnh báo, thêm blocklist...) sẽ ghi thêm khi các router đó được xây (MR13+)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)  # "system" hoặc username quản trị viên
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)  # "login_event" | "alert" | "blocklist" | ...
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class ModelRegistryEntry(Base):
    """Phiên bản mô hình đã nạp (MR12: "nạp model theo phiên bản, fallback an toàn"). `is_active` đánh dấu phiên bản đang dùng; nạp lỗi (file
    thiếu/hỏng, `feature_signature` lệch) thì `app/detection/hybrid_runtime.py` bỏ qua ML, không sập luồng — giống triết lý `ml_model.py` tầng 3."""

    __tablename__ = "model_registry"
    __table_args__ = (UniqueConstraint("name", "version", name="uq_model_registry_name_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)  # "hybrid_cp2"
    version: Mapped[str] = mapped_column(String(64), nullable=False)  # "cp2"
    artifact_path: Mapped[str] = mapped_column(Text, nullable=False)
    profile_path: Mapped[str | None] = mapped_column(Text, nullable=True)  # app/detection/hybrid/profiles/*.json (trọng số luật + ngưỡng + hiệu chỉnh ML)
    feature_signature: Mapped[str | None] = mapped_column(String(32), nullable=True)  # ml.rba.features.feature_signature() lúc train — đối chiếu để phát hiện lệch phiên bản
    metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    trained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
