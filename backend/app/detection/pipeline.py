"""Detection engine chạy BẤT ĐỒNG BỘ sau khi API /login đã trả response
(nhiệm vụ 5.2) — GeoIP, rule tầng 1, risk score tầng 2, baseline, known
device/location đều chuyển vào đây (trước ở routers/auth.py, chặn response).
Alert mới được broadcast qua WebSocket ngay sau khi commit (nhiệm vụ 5.3).

Mở SESSION DB RIÊNG (không dùng session được inject qua Depends(get_db) của
request — session đó đã đóng khi response được trả về, dùng lại sẽ lỗi).
"""

from __future__ import annotations

from datetime import datetime

from app.database import SessionLocal
from app.detection.baseline import (
    is_known_location,
    record_known_device_if_new,
    record_known_location_if_new,
    update_baseline_after_successful_login,
)
from app.detection.geoip import lookup_ip
from app.detection.rate_counter import check_fail_count
from app.detection.rules import (
    GeoPoint,
    is_brute_force,
    is_credential_stuffing,
    is_impossible_travel,
    register_login_failure,
)
from app.detection.scoring import SUCCESS_AFTER_FAIL_STREAK_MIN_FAILS, classify_severity, compute_risk_score
from app.models import Alert, LoginEvent, User, UserBaseline
from app.utils.device import compute_device_fingerprint
from app.ws_manager import ws_manager

_RULE_TIER1_RISK_SCORE = 80
_RULE_TIER1_SEVERITY = "high"

_ALERT_MESSAGES = {
    "brute_force": "Phát hiện dò mật khẩu liên tiếp cho tài khoản '{target}'.",
    "credential_stuffing": "Phát hiện thử nhiều tài khoản khác nhau từ cùng IP {target}.",
    "impossible_travel": "Đăng nhập từ vị trí cách xa bất thường so với lần trước trong thời gian quá ngắn.",
}


async def run_detection_pipeline(
    *,
    username: str,
    user_id: int | None,
    success: bool,
    ip: str,
    user_agent: str | None,
    timestamp: datetime,
) -> None:
    db = SessionLocal()
    alert_payloads: list[dict] = []

    try:
        user = db.get(User, user_id) if user_id else None
        geo = lookup_ip(ip)
        device_fingerprint = compute_device_fingerprint(user_agent)

        # Đọc counter TRƯỚC khi register_login_failure cập nhật thêm.
        recent_fail_count = check_fail_count(f"fail:{username}")

        event = LoginEvent(
            user_id=user_id,
            attempted_username=username,
            success=success,
            ip_address=ip,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            country=geo.country if geo else None,
            city=geo.city if geo else None,
            latitude=geo.latitude if geo else None,
            longitude=geo.longitude if geo else None,
            is_synthetic=False,
            created_at=timestamp,
        )
        db.add(event)
        db.flush()

        # (alert_type, target hiển thị trong message, extra field cho payload WebSocket)
        triggered: list[tuple[str, str, dict]] = []

        if user is not None:
            previous_event = (
                db.query(LoginEvent)
                .filter(LoginEvent.user_id == user.id, LoginEvent.id != event.id)
                .order_by(LoginEvent.created_at.desc())
                .first()
            )
            if previous_event is not None:
                previous_point = GeoPoint(previous_event.latitude, previous_event.longitude, previous_event.created_at)
                current_point = GeoPoint(event.latitude, event.longitude, event.created_at)
                if is_impossible_travel(previous_point, current_point):
                    # Kèm toạ độ điểm TRƯỚC để frontend vẽ đường nối 2 điểm trên bản đồ (nhiệm vụ 5.3).
                    triggered.append(
                        (
                            "impossible_travel",
                            "",
                            {"previous_latitude": previous_event.latitude, "previous_longitude": previous_event.longitude},
                        )
                    )

        is_brute_force_flag = False
        if not success:
            register_login_failure(username, ip)
            is_brute_force_flag = is_brute_force(username)
            if is_brute_force_flag:
                triggered.append(("brute_force", username, {}))
            if is_credential_stuffing(ip):
                triggered.append(("credential_stuffing", ip, {}))

        alert_records: list[tuple[Alert, dict]] = []
        for alert_type, target, extra in triggered:
            alert_obj = Alert(
                login_event_id=event.id,
                user_id=user_id,
                alert_type=alert_type,
                severity=_RULE_TIER1_SEVERITY,
                risk_score=_RULE_TIER1_RISK_SCORE,
                message=_ALERT_MESSAGES[alert_type].format(target=target),
            )
            db.add(alert_obj)
            alert_records.append((alert_obj, extra))

        if user is not None:
            baseline = db.query(UserBaseline).filter(UserBaseline.user_id == user.id).first()
            login_hour = event.created_at.hour + event.created_at.minute / 60
            known_location = is_known_location(db, user.id, event.country, event.city)
            had_fail_streak = recent_fail_count >= SUCCESS_AFTER_FAIL_STREAK_MIN_FAILS

            risk_score, _factors = compute_risk_score(
                baseline=baseline,
                login_hour=login_hour,
                is_new_location=not known_location,
                consecutive_fail=is_brute_force_flag,
                success_after_fail_streak=success and had_fail_streak,
            )
            event.risk_score = risk_score

            severity = classify_severity(risk_score)
            if severity != "low":
                alert_obj = Alert(
                    login_event_id=event.id,
                    user_id=user.id,
                    alert_type="high_risk_score",
                    severity=severity,
                    risk_score=risk_score,
                    message=f"Risk score {risk_score}/100 ({severity}) cho tài khoản '{user.username}'.",
                )
                db.add(alert_obj)
                alert_records.append((alert_obj, {}))

            if success:
                update_baseline_after_successful_login(db, user, event)
                record_known_device_if_new(db, user, device_fingerprint, user_agent)
                record_known_location_if_new(db, user, event.country, event.city)

        db.commit()

        # Đọc dữ liệu để broadcast TRƯỚC khi đóng session (object hết hạn sau khi đóng).
        for alert_obj, extra in alert_records:
            alert_payloads.append(
                {
                    "id": alert_obj.id,
                    "login_event_id": alert_obj.login_event_id,
                    "user_id": alert_obj.user_id,
                    "username": username,
                    "alert_type": alert_obj.alert_type,
                    "severity": alert_obj.severity,
                    "risk_score": alert_obj.risk_score,
                    "message": alert_obj.message,
                    "latitude": event.latitude,
                    "longitude": event.longitude,
                    "created_at": alert_obj.created_at.isoformat() if alert_obj.created_at else timestamp.isoformat(),
                    **extra,
                }
            )
    finally:
        db.close()

    for payload in alert_payloads:
        await ws_manager.broadcast_json({"type": "alert", "data": payload})
