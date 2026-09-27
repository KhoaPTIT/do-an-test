"""Detection engine chạy BẤT ĐỒNG BỘ sau khi API /login đã trả response
(nhiệm vụ 5.2) — GeoIP, rule tầng 1, risk score tầng 2, baseline, known
device/location đều chuyển vào đây (trước ở routers/auth.py, chặn response).
Alert mới được broadcast qua WebSocket ngay sau khi commit (nhiệm vụ 5.3).

Mở SESSION DB RIÊNG (không dùng session được inject qua Depends(get_db) của
request — session đó đã đóng khi response được trả về, dùng lại sẽ lỗi).

Message của Alert đều được DIỄN GIẢI CỤ THỂ (không chỉ nói "bất thường" hay
1 con số điểm) — nâng cấp sau Tuần 7: admin đọc alert phải hiểu ngay tình
huống là gì mà không cần vào tra log riêng.

MR12 nối thêm rule engine v2 (MR9-10) + hybrid risk engine (MR11) — mục "MR12" ở cuối hàm — CHẠY SONG SONG tầng 1-2-3
ở trên, KHÔNG THAY THẾ (đúng triết lý xuyên suốt module này). Toàn khối MR12 được cô lập trong một `try/except` RIÊNG:
lỗi ở đó (đặc trưng RBA, rule engine, mô hình ML) không bao giờ làm mất alert của tầng 1-2-3 hay làm hỏng `event` đã ghi.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime

from app.database import SessionLocal
from app.detection import hybrid_runtime, ml_model, perf
from app.detection.baseline import (
    is_known_location,
    record_known_device_if_new,
    record_known_location_if_new,
    update_baseline_after_successful_login,
)
from app.detection.engine.types import LoginAttempt
from app.detection.geoip import lookup_asn, lookup_ip
from app.detection.rate_counter import check_fail_count, redis_client
from app.detection.rba_live_features import compute_rba_features, event_record_for
from app.detection.rule_engine_runtime import build_rule_engine
from app.detection.rules import (
    CREDENTIAL_STUFFING_FAIL_THRESHOLD,
    CREDENTIAL_STUFFING_MIN_DISTINCT_USERNAMES,
    IMPOSSIBLE_TRAVEL_SPEED_KMH,
    BRUTE_FORCE_THRESHOLD,
    GeoPoint,
    haversine_distance,
    is_brute_force,
    is_credential_stuffing,
    is_impossible_travel,
    register_login_failure,
)
from app.detection.scoring import SUCCESS_AFTER_FAIL_STREAK_MIN_FAILS, classify_severity, compute_risk_score, explain_factors
from app.models import Alert, AuditLog, LoginEvent, ResponseAction, User, UserBaseline
from app.utils.device import compute_device_fingerprint, parse_user_agent
from app.ws_manager import ws_manager
from ml.features import compute_realtime_features

logger = logging.getLogger("pipeline")

_RULE_TIER1_RISK_SCORE = 80
_RULE_TIER1_SEVERITY = "high"

# MR12: điểm 0-100 của hybrid risk engine (MR11) -> severity của Alert khi hành động đề xuất không phải "allow".
_HYBRID_SEVERITY = {"alert": "medium", "step_up": "high", "lock": "high"}


def _brute_force_message(username: str, fail_count: int) -> str:
    return f"Dò mật khẩu '{username}': {fail_count} lần sai/5 phút (ngưỡng {BRUTE_FORCE_THRESHOLD})."


def _credential_stuffing_message(ip: str, distinct_usernames: int, fail_count: int) -> str:
    return (
        f"IP {ip} thử {distinct_usernames} tài khoản khác nhau, {fail_count} lần sai/5 phút "
        f"(ngưỡng {CREDENTIAL_STUFFING_MIN_DISTINCT_USERNAMES} TK / {CREDENTIAL_STUFFING_FAIL_THRESHOLD} lần)."
    )


def _impossible_travel_message(distance_km: float, elapsed_minutes: float, speed_kmh: float) -> str:
    return f"Cách {distance_km:.0f}km chỉ sau {elapsed_minutes:.1f} phút (~{speed_kmh:,.0f} km/h, ngưỡng {IMPOSSIBLE_TRAVEL_SPEED_KMH:.0f})."


def _run_detection_pipeline_sync(
    *,
    username: str,
    user_id: int | None,
    success: bool,
    ip: str,
    user_agent: str | None,
    timestamp: datetime,
) -> list[dict]:
    """Toàn bộ việc (GeoIP, DB, Redis, rule engine, ML) — MỌI THAO TÁC ĐỀU ĐỒNG BỘ (SQLAlchemy dùng driver psycopg2
    đồng bộ, redis-py đồng bộ, LightGBM/scikit-learn CPU-bound), không có `await` nào bên trong. Vì vậy hàm này CỐ Ý
    KHÔNG phải `async def`: `run_detection_pipeline` bên dưới chạy nó trong `asyncio.to_thread` — nếu để `async def` và
    gọi trực tiếp trên vòng lặp sự kiện (như trước MR12), toàn bộ thời gian chạy (đo được p50 ~vài chục ms, p95 có lúc
    tới hàng trăm ms — xem docs/realtime-integration.md) sẽ CHẶN vòng lặp sự kiện DÙNG CHUNG cho mọi kết nối khác; đo tải
    (nhiều request /login đồng thời) trước khi sửa cho thấy timeout thật sự, không phải giả thuyết suông."""
    db = SessionLocal()
    alert_payloads: list[dict] = []
    pipeline_started = time.perf_counter()

    try:
        user = db.get(User, user_id) if user_id else None
        geo = lookup_ip(ip)
        device_fingerprint = compute_device_fingerprint(user_agent)
        # MR12: parse UA + tra ASN — không chặn /login (toàn hàm này đã chạy nền), lỗi/thiếu dữ liệu trả None chứ không raise.
        parsed_ua = parse_user_agent(user_agent)
        asn_result = lookup_asn(ip)

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
            asn=asn_result.asn if asn_result else None,
            os_name=parsed_ua.os,
            browser_name=parsed_ua.browser,
            device_type=parsed_ua.device_type,
            is_synthetic=False,
            created_at=timestamp,
        )
        db.add(event)
        db.flush()

        # (alert_type, message, extra field cho payload WebSocket)
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
                    distance_km = haversine_distance(
                        previous_event.latitude, previous_event.longitude, event.latitude, event.longitude
                    )
                    elapsed_minutes = (event.created_at - previous_event.created_at).total_seconds() / 60
                    speed_kmh = distance_km / (elapsed_minutes / 60) if elapsed_minutes > 0 else float("inf")
                    # Kèm toạ độ điểm TRƯỚC để frontend vẽ đường nối 2 điểm trên bản đồ (nhiệm vụ 5.3).
                    triggered.append(
                        (
                            "impossible_travel",
                            _impossible_travel_message(distance_km, elapsed_minutes, speed_kmh),
                            {"previous_latitude": previous_event.latitude, "previous_longitude": previous_event.longitude},
                        )
                    )

        is_brute_force_flag = False
        if not success:
            register_login_failure(username, ip)
            is_brute_force_flag = is_brute_force(username)
            if is_brute_force_flag:
                fail_count = check_fail_count(f"fail:{username}")
                triggered.append(("brute_force", _brute_force_message(username, fail_count), {}))
            if is_credential_stuffing(ip):
                distinct_usernames = redis_client.zcard(f"cred_stuffing:{ip}")
                fail_count_ip = check_fail_count(f"fail_ip:{ip}")
                triggered.append(
                    ("credential_stuffing", _credential_stuffing_message(ip, distinct_usernames, fail_count_ip), {})
                )

        alert_records: list[tuple[Alert, dict]] = []
        for alert_type, message, extra in triggered:
            alert_obj = Alert(
                login_event_id=event.id,
                user_id=user_id,
                alert_type=alert_type,
                severity=_RULE_TIER1_SEVERITY,
                risk_score=_RULE_TIER1_RISK_SCORE,
                message=message,
            )
            db.add(alert_obj)
            alert_records.append((alert_obj, extra))

        if user is not None:
            baseline = db.query(UserBaseline).filter(UserBaseline.user_id == user.id).first()
            login_hour = event.created_at.hour + event.created_at.minute / 60
            known_location = is_known_location(db, user.id, event.country, event.city)
            had_fail_streak = recent_fail_count >= SUCCESS_AFTER_FAIL_STREAK_MIN_FAILS

            risk_score, factors = compute_risk_score(
                baseline=baseline,
                login_hour=login_hour,
                is_new_location=not known_location,
                consecutive_fail=is_brute_force_flag,
                success_after_fail_streak=success and had_fail_streak,
            )
            event.risk_score = risk_score

            severity = classify_severity(risk_score)
            if severity != "low":
                explanation = explain_factors(factors, baseline=baseline, login_hour=login_hour)
                alert_obj = Alert(
                    login_event_id=event.id,
                    user_id=user.id,
                    alert_type="high_risk_score",
                    severity=severity,
                    risk_score=risk_score,
                    message=f"'{user.username}' — risk {risk_score}/100 ({severity}): {explanation}.",
                )
                db.add(alert_obj)
                alert_records.append((alert_obj, {}))

            # --- Tầng 3: ML, THAM KHẢO — chạy SONG SONG, không thay thế tầng 1-2 (nhiệm vụ 7.1) ---
            # Đọc is_known_*/lịch sử TRƯỚC khi record_known_*_if_new() cập nhật
            # bên dưới, cho đúng ý nghĩa "chưa từng thấy" (giống lúc train offline).
            ml_features = compute_realtime_features(
                db,
                user_id=user.id,
                baseline=baseline,
                country=event.country,
                city=event.city,
                latitude=event.latitude,
                longitude=event.longitude,
                device_fingerprint=device_fingerprint,
                created_at=event.created_at,
            )
            ml_result = ml_model.predict(ml_features)
            if ml_result is not None:
                event.ml_anomaly_score = ml_result["anomaly_score"]
                if ml_result["is_anomaly"]:
                    ml_explanation = ml_model.explain(ml_features)
                    alert_obj = Alert(
                        login_event_id=event.id,
                        user_id=user.id,
                        alert_type="ml_anomaly",
                        severity="medium",
                        risk_score=risk_score,
                        message=f"ML bất thường (điểm {ml_result['anomaly_score']:.2f}, tham khảo): {ml_explanation}.",
                    )
                    db.add(alert_obj)
                    alert_records.append((alert_obj, {}))

            if success:
                update_baseline_after_successful_login(db, user, event)
                record_known_device_if_new(db, user, device_fingerprint, user_agent)
                record_known_location_if_new(db, user, event.country, event.city)

        # --- MR12: rule engine v2 (MR9-10) + hybrid risk engine (MR11) — CHẠY SONG SONG tầng 1-2-3 ở trên, KHÔNG THAY
        # THẾ. Cô lập trong try/except RIÊNG: lỗi ở đây không được làm mất alert tầng 1-2-3 đã ghi hay làm sập luồng.
        try:
            with perf.timer("hybrid"):
                attempt = LoginAttempt(
                    ts=event.created_at.timestamp(), username=username, success=success, ip=ip, user_key=str(user_id) if user_id else None,
                    asn=event.asn, country=event.country, city=event.city, latitude=event.latitude, longitude=event.longitude,
                    user_agent=user_agent, browser=parsed_ua.browser, os=parsed_ua.os, device_type=parsed_ua.device_type,
                )
                with perf.timer("rule_engine"):
                    evaluation = build_rule_engine(db, before=event.created_at).evaluate(attempt)
                with perf.timer("rba_features"):
                    features = compute_rba_features(db, event_record_for(event))
                risk_result = hybrid_runtime.get_engine().evaluate(features, evaluation.hits)
                event.hybrid_risk_score = risk_result.score
                event.hybrid_action = risk_result.action

                if risk_result.action != "allow":
                    top_rule = next((c.source for c in risk_result.contributions if c.source != "ml"), None)
                    reasons = "; ".join(f"{c.label} ({c.weight:.0%})" for c in risk_result.contributions[:3])
                    hybrid_alert = Alert(
                        login_event_id=event.id, user_id=user_id, alert_type="hybrid_risk",
                        severity=_HYBRID_SEVERITY[risk_result.action], risk_score=risk_result.score,
                        message=f"Hybrid risk engine: điểm {risk_result.score}/100, đề xuất '{risk_result.action}' — {reasons}.",
                        rule_id=risk_result.overridden_by or top_rule,
                        explanation={"contributions": [{"source": c.source, "label": c.label, "weight": round(c.weight, 4), "group": c.group} for c in risk_result.contributions]},
                    )
                    db.add(hybrid_alert)
                    db.flush()
                    alert_records.append((hybrid_alert, {}))

                    if risk_result.action in ("step_up", "lock"):
                        response_action = ResponseAction(
                            login_event_id=event.id, alert_id=hybrid_alert.id, user_id=user_id, action=risk_result.action,
                            reason=f"Hybrid risk engine đề xuất (điểm {risk_result.score}/100): {reasons}.",
                        )
                        db.add(response_action)
                        db.flush()
                        db.add(
                            AuditLog(
                                actor="system", action=f"recommend_{risk_result.action}", target_type="login_event", target_id=event.id,
                                detail={"response_action_id": response_action.id, "alert_id": hybrid_alert.id, "score": risk_result.score},
                            )
                        )
        except Exception:  # noqa: BLE001 — MR12 không bao giờ được làm mất alert tầng 1-2-3 hay làm sập luồng đăng nhập
            logger.exception("lỗi ở khối MR12 (rule engine/hybrid) cho user_id=%s ip=%s — bỏ qua, tầng 1-2-3 không bị ảnh hưởng", user_id, ip)

        db.commit()
        perf.record("pipeline", (time.perf_counter() - pipeline_started) * 1000)

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
                    "rule_id": alert_obj.rule_id,
                    "created_at": alert_obj.created_at.isoformat() if alert_obj.created_at else timestamp.isoformat(),
                    **extra,
                }
            )
    finally:
        db.close()

    return alert_payloads


async def run_detection_pipeline(
    *,
    username: str,
    user_id: int | None,
    success: bool,
    ip: str,
    user_agent: str | None,
    timestamp: datetime,
) -> None:
    """Wrapper mỏng: chạy toàn bộ việc ĐỒNG BỘ ở trên trong một thread riêng (`asyncio.to_thread`) rồi mới broadcast
    WebSocket (thao tác `await` DUY NHẤT thật sự cần vòng lặp sự kiện — xem `WebSocketManager.broadcast_json`). Nhiều
    lần đăng nhập đến CÙNG LÚC giờ chạy `_run_detection_pipeline_sync` song song ở các thread khác nhau thay vì nối đuôi
    nhau trên một vòng lặp sự kiện duy nhất."""
    alert_payloads = await asyncio.to_thread(
        _run_detection_pipeline_sync, username=username, user_id=user_id, success=success, ip=ip, user_agent=user_agent, timestamp=timestamp,
    )
    for payload in alert_payloads:
        await ws_manager.broadcast_json({"type": "alert", "data": payload})
