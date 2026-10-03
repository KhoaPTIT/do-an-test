"""Harness chạy lần đăng nhập qua `run_detection_pipeline` THẬT (rule engine → hybrid → attribution → ghi Alert), trên
SQLite in-memory + fakeredis riêng, GeoIP/threat intel lấy từ TEST FIXTURE.

`setattr_fn` là cách vá trạng thái module dùng chung: pytest truyền `monkeypatch.setattr` (tự hoàn tác sau mỗi test,
không rò rỉ sang test khác — lý do `scripts/attack_scenario_runner.py` MR18 không chạy trong pytest), runner độc lập
dùng `setattr` thường (mỗi kịch bản một `VerificationEnv` mới).

Thành phần ML của hybrid (`hybrid_cp2`) bị TẮT có chủ đích: artifact cần bộ RBA ~9GB không có trong repo, và kết quả
kiểm chứng không được phụ thuộc vào nó — hồ sơ hybrid dùng đúng hồ sơ dự phòng mà một bản clone mới sẽ dùng.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

import fakeredis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — đăng ký toàn bộ bảng vào Base.metadata trước create_all
from app.detection.attribution import build_verdict as _ORIGINAL_BUILD_VERDICT  # hàm GỐC, chụp trước mọi lần bọc
from app.database import Base
from app.models import Alert, BlocklistEntry, LoginEvent, User
from app.security import hash_password
from app.utils.device import compute_device_fingerprint
from verification.fixtures import fixture_lookup_asn, fixture_lookup_ip, fixture_threat_intel

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
FIREFOX_UA = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
SAFARI_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
MOBILE_UA = "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
EDGE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/120.0.0.0 Safari/537.36"
CURL_UA = "curl/8.7.1"
PY_REQUESTS_UA = "python-requests/2.31.0"
DETECTION_ALERT_TYPES = ("hybrid_risk", "behavior_anomaly")


@dataclass(frozen=True)
class AlertRow:
    id: int
    login_event_id: int
    user_id: int | None
    alert_type: str
    rule_id: str | None
    severity: str
    risk_score: int
    message: str
    explanation: dict[str, Any] | None
    occurrence_count: int

    @property
    def primary_detector(self) -> str | None:
        return (self.explanation or {}).get("primary_detector")

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "login_event_id": self.login_event_id, "user_id": self.user_id, "alert_type": self.alert_type,
            "rule_id": self.rule_id, "severity": self.severity, "risk_score": self.risk_score, "message": self.message,
            "explanation": self.explanation, "occurrence_count": self.occurrence_count,
        }


_PASSWORD_HASH: str | None = None


def _password_hash() -> str:
    """Băm MỘT lần rồi dùng lại (bcrypt cố ý chậm; runner tạo hàng nghìn tài khoản). Pipeline không bao giờ đọc hash."""
    global _PASSWORD_HASH
    if _PASSWORD_HASH is None:
        _PASSWORD_HASH = hash_password("CorrectHorse123!")
    return _PASSWORD_HASH


def install_fixture_telemetry(setattr_fn: Callable[[Any, str, Any], None], redis_client) -> None:
    """Vá nguồn TELEMETRY của pipeline sang TEST FIXTURE: GeoIP/ASN, threat intel, Redis; tắt thành phần ML của hybrid
    (xem docstring module). Không đụng DB — `VerificationEnv` tự lo, test HTTP dùng DB của fixture `db_session`."""
    import app.detection.pipeline as pipeline_module
    import app.detection.rate_counter as rate_counter_module
    import app.detection.rule_engine_runtime as runtime_module
    from app.detection import hybrid_runtime

    setattr_fn(rate_counter_module, "redis_client", redis_client)
    setattr_fn(pipeline_module, "redis_client", redis_client)  # pipeline import thẳng tên này (credential_stuffing tầng 1 đọc zcard)
    setattr_fn(pipeline_module, "lookup_ip", fixture_lookup_ip)
    setattr_fn(pipeline_module, "lookup_asn", fixture_lookup_asn)
    setattr_fn(runtime_module, "_THREAT_INTEL", fixture_threat_intel())
    hybrid = hybrid_runtime.get_engine()
    setattr_fn(hybrid, "profile", hybrid_runtime._FALLBACK_PROFILE)
    runtime_module.invalidate_blocklist_cache()
    runtime_module.invalidate_rule_config_cache()


class VerificationEnv:
    def __init__(self, setattr_fn: Callable[[Any, str, Any], None] = setattr, ml_model_dir=None) -> None:
        """`ml_model_dir`: None (mặc định) = model bất thường TẮT — đúng cấu hình đo 20 hành vi luật của Phase 3; một thư mục
        artifact = nạp model đó cho lần chạy này (thí nghiệm luật vs ML, Phase 4.1)."""
        import app.detection.pipeline as pipeline_module
        from app.detection import ml_runtime

        runtime = ml_runtime.MLRuntime()
        if ml_model_dir is None:
            runtime.disable("tắt trong môi trường kiểm chứng (VerificationEnv(ml_model_dir=None))")
        else:
            runtime.load(ml_model_dir)
        setattr_fn(ml_runtime, "_runtime", runtime)
        self.ml_runtime = runtime

        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(bind=engine)
        self.session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        self.redis = fakeredis.FakeRedis(decode_responses=True)
        setattr_fn(pipeline_module, "SessionLocal", self.session_factory)
        install_fixture_telemetry(setattr_fn, self.redis)
        self._user_ids: dict[str, int] = {}
        # Ghi lại verdict THẬT mà pipeline tính cho từng lần thử (bọc — không thay — `attribution.build_verdict`), để đo
        # độ chính xác quy kết theo từng sự kiện thay vì đoán từ alert đã gộp trùng lặp.
        from app.detection import attribution as attribution_module

        self.verdicts: list = []

        def _recording_build_verdict(*args, **kwargs):
            verdict = _ORIGINAL_BUILD_VERDICT(*args, **kwargs)
            self.verdicts.append(verdict)
            return verdict

        setattr_fn(attribution_module, "build_verdict", _recording_build_verdict)

    # ------------------------------------------------------------------------------------------------ chuẩn bị dữ liệu

    def add_user(self, username: str) -> int:
        db = self.session_factory()
        try:
            user = User(username=username, password_hash=_password_hash())
            db.add(user)
            db.commit()
            self._user_ids[username] = user.id
            return user.id
        finally:
            db.close()

    def user_id(self, username: str) -> int | None:
        return self._user_ids.get(username)

    def add_history(self, username: str, *, ip: str, ts: datetime, user_agent: str = CHROME_UA, success: bool = True) -> None:
        """Lịch sử đăng nhập TRƯỚC kịch bản, ghi thẳng `LoginEvent` (không chấm điểm) — kèm GeoIP/ASN/dấu vân tay thiết
        bị tính Y HỆT pipeline sẽ tính (bài học MR18: thiếu các trường này làm lịch sử trông "chưa từng thấy")."""
        geo, asn = fixture_lookup_ip(ip), fixture_lookup_asn(ip)
        db = self.session_factory()
        try:
            db.add(LoginEvent(
                user_id=self._user_ids.get(username), attempted_username=username, success=success, ip_address=ip, user_agent=user_agent,
                device_fingerprint=compute_device_fingerprint(user_agent), country=geo.country if geo else None, city=geo.city if geo else None,
                latitude=geo.latitude if geo else None, longitude=geo.longitude if geo else None, asn=asn.asn if asn else None,
                is_synthetic=True, created_at=ts,
            ))
            db.commit()
        finally:
            db.close()

    def add_block(self, kind: str, value: str, *, expires_at: datetime | None = None, added_by: str = "admin") -> None:
        from app.detection.rule_engine_runtime import invalidate_blocklist_cache

        db = self.session_factory()
        try:
            db.add(BlocklistEntry(kind=kind, value=value, reason="kiểm chứng", added_by=added_by, expires_at=expires_at))
            db.commit()
        finally:
            db.close()
        invalidate_blocklist_cache()

    # ------------------------------------------------------------------------------------------------ chạy

    def login(self, username: str, *, success: bool, ip: str, ts: datetime, user_agent: str | None = CHROME_UA):
        from app.detection.pipeline import run_detection_pipeline

        return asyncio.run(run_detection_pipeline(
            username=username, user_id=self._user_ids.get(username), success=success, ip=ip, user_agent=user_agent, timestamp=ts,
        ))

    # ------------------------------------------------------------------------------------------------ đọc kết quả

    def alerts(self) -> list[AlertRow]:
        db = self.session_factory()
        try:
            return [
                AlertRow(a.id, a.login_event_id, a.user_id, a.alert_type, a.rule_id, a.severity, a.risk_score, a.message, a.explanation, a.occurrence_count)
                for a in db.query(Alert).order_by(Alert.id).all()
            ]
        finally:
            db.close()

    def detection_alerts(self) -> list[AlertRow]:
        """Mọi cảnh báo của lớp phát hiện có quy kết (`hybrid_risk`, `behavior_anomaly`) — không gồm alert tầng 1/2/3 cũ."""
        return [a for a in self.alerts() if a.alert_type in DETECTION_ALERT_TYPES]

    def detector_alerts(self, rule_id: str) -> list[AlertRow]:
        """Cảnh báo quy kết cho ĐÚNG detector này (`rule_id` = detector) — không tính alert của detector khác, không tính
        alert tầng 1/2/3 cũ (`alert_type` khác)."""
        return [a for a in self.detection_alerts() if a.rule_id == rule_id]

    def events(self) -> list[LoginEvent]:
        db = self.session_factory()
        try:
            return db.query(LoginEvent).filter(LoginEvent.is_synthetic.is_(False)).order_by(LoginEvent.id).all()
        finally:
            db.close()
