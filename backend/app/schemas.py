"""Pydantic schema cho request/response — field snake_case theo docs/api-contract.md."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    success: bool
    message: str
    # MR16 "phản ứng tự động (mô phỏng)" — bước xác thực thêm khi hybrid risk engine đề xuất step_up cho CHÍNH lần thử
    # này (mật khẩu đã đúng). ⚠️ `demo_otp_code` CHỈ vì đây là OTP GIẢ LẬP (không có nhà cung cấp SMS/email nào tích
    # hợp) — hệ thống thật KHÔNG BAO GIỜ trả mã trực tiếp trong response.
    step_up_required: bool = False
    challenge_id: int | None = None
    demo_otp_code: str | None = None
    # MR16 — tài khoản hoặc IP đang bị khoá tạm (Blocklist, app/detection/engine/intel.py).
    locked: bool = False
    # Trang đăng nhập GỘP: cùng một form cho cả người dùng web app mẫu lẫn quản trị viên — backend tự phân quyền theo
    # tài khoản. `role="admin"` kèm `access_token` (JWT như POST /admin/login) để frontend chuyển thẳng vào /dashboard.
    role: str = "user"
    access_token: str | None = None


class OtpVerifyRequest(BaseModel):
    """POST /login/verify-otp (MR16)."""

    challenge_id: int = Field(gt=0)
    code: str = Field(min_length=1, max_length=12)


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

    # Phase 4.1: model bất thường (app/detection/ml_runtime.py) — giá trị THẬT ghi lúc chấm, NULL = không có điểm
    # (model chưa nạp hoặc lần thử ngoài phạm vi chấm — lý do ở ml_details.reason)
    ml_is_anomaly: bool | None = None
    ml_threshold: float | None = None
    ml_model_version: str | None = None
    ml_details: dict | None = None


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


class AlertFeedbackRequest(BaseModel):
    """POST /alerts/{id}/feedback (MR15) — quản trị viên xác nhận cảnh báo đúng hay báo nhầm."""

    correct: bool  # True = "Đúng" (cảnh báo hợp lý), False = "Báo nhầm"
    note: str | None = Field(default=None, max_length=500)


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


# ----------------------------------------------------------------------------------------- MR16: blocklist / mở khoá


class BlocklistEntryOut(BaseModel):
    """Dùng cho GET /blocklist — danh sách khoá tạm/chặn (tự động từ MR16 + thủ công từ MR9) để quản trị viên xem và mở khoá."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str  # ip | cidr | asn | username
    value: str
    reason: str | None
    added_by: str
    expires_at: datetime | None  # None = vĩnh viễn (chỉ có thể do quản trị viên đặt tay — MR16 tự động luôn có hạn)
    created_at: datetime


class PaginatedBlocklist(BaseModel):
    items: list[BlocklistEntryOut]
    total: int
    page: int
    page_size: int


# --------------------------------------------------------------------------------------------- MR17: cấu hình luật


class RuleParamOut(BaseModel):
    name: str
    kind: str  # bool | int | float | str | list — suy từ kiểu của default (app.detection.engine.registry.Param)
    description: str
    unit: str
    minimum: float | None
    maximum: float | None
    default: Any
    value: Any  # giá trị HIỆU LỰC hiện tại (override nếu có, mặc định nếu không)


class RuleOut(BaseModel):
    """Dùng cho GET /rules — một luật với trạng thái HIỆU LỰC hiện tại (mặc định của sổ đăng ký GHÉP với ghi đè quản
    trị viên, nếu có), để dựng giao diện bật/tắt + chỉnh tham số (checklist MR17 "chỉnh ngưỡng và bật/tắt rule")."""

    id: str
    title: str
    category: str
    severity: str
    description: str
    notes: str
    techniques: list[str]
    needs: list[str]
    default_mode: str
    mode: str  # HIỆU LỰC hiện tại (override nếu có, default_mode nếu không)
    is_overridden: bool
    params: list[RuleParamOut]
    updated_by: str | None = None
    updated_at: datetime | None = None


class RuleUpdateRequest(BaseModel):
    """PUT /rules/{id} — CHỈ field có mặt trong request mới bị đổi (vd chỉ gửi `mode` thì `params` override hiện có,
    nếu có, giữ nguyên); gửi `params` thì GHI ĐÈ TOÀN BỘ bộ tham số override (không merge từng key với override cũ)."""

    mode: str | None = None
    params: dict[str, Any] | None = None


# --------------------------------------------------------------------------------------- MR17: sức khoẻ mô hình


class ModelVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    version: str
    is_active: bool
    feature_signature: str | None
    metrics: dict | None
    trained_at: datetime | None
    created_at: datetime


class FeatureDriftOut(BaseModel):
    feature: str
    psi: float | None  # None = không đủ dữ liệu (NaN)
    verdict: str
    n_reference: int
    n_current: int


class ModelHealthOut(BaseModel):
    versions: list[ModelVersionOut]
    drift_computed_at: datetime | None  # None = chưa từng tính (n_current quá ít hoặc lỗi đọc file tham chiếu)
    drift_low_confidence: bool
    drift_n_reference: int
    drift_n_current: int
    drift_top_features: list[FeatureDriftOut]  # sắp theo PSI giảm dần, tối đa 15 đặc trưng trôi nhiều nhất


# ------------------------------------------------------------------------------------------- MR17: hồ sơ rủi ro user


class KnownDeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    device_fingerprint: str
    user_agent: str | None
    first_seen_at: datetime
    last_seen_at: datetime


class KnownLocationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    country: str | None
    city: str | None
    first_seen_at: datetime
    last_seen_at: datetime


class UserRiskProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    threshold_delta: float
    feedback_count: int
    false_positive_count: int


class UserProfileOut(BaseModel):
    """GET /users/{id}/profile — checklist MR17 "hồ sơ rủi ro theo user (timeline, alert, thiết bị/quốc gia quen)"."""

    id: int
    username: str
    created_at: datetime
    importance: float
    timeline: list[LoginEventOut]  # gần đây nhất trước, giới hạn LIMIT trong router (không phân trang — xem docstring router)
    alerts: list[AlertOut]
    known_devices: list[KnownDeviceOut]
    known_locations: list[KnownLocationOut]
    risk_profile: UserRiskProfileOut | None  # None = chưa đủ phản hồi để có ngưỡng riêng (MR15), dùng ngưỡng nhóm
