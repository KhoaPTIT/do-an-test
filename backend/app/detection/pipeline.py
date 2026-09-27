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

MR13 (`app/detection/alert_intelligence.py`, THUẦN không đụng DB) làm giàu alert `hybrid_risk` NGAY TRONG khối MR12 ở
trên: novelty so với lịch sử tài khoản, họ tấn công GỢI Ý, ưu tiên hiển thị, và chống trùng lặp — cùng (tài khoản hoặc
IP) + họ tấn công trong 15 phút GỘP vào một hàng `Alert` thay vì tạo hàng mới.

MR14 (mục "MR14" ở cuối hàm, `app/detection/campaign_correlation.py`) gán `Alert.campaign_id` khi NHIỀU TÀI KHOẢN
khác nhau bị nhắm từ CÙNG hạ tầng (IP/ASN) trong 24h.

MR15 (`app/detection/adaptive_threshold.py`) đọc `UserRiskProfile` (nếu tài khoản đã đủ phản hồi "báo nhầm" ròng, cập
nhật ĐỊNH KỲ bởi `backend/scripts/retrain_from_feedback.py`, KHÔNG PHẢI ngay lúc chấm) và NỚI LỎNG riêng `ActionBands`
cho tài khoản đó trước khi gọi `hybrid_runtime`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime

from app.database import SessionLocal
from app.detection import alert_intelligence, hybrid_runtime, ml_model, perf
from app.detection.adaptive_threshold import apply_delta
from app.detection.baseline import (
    is_known_location,
    record_known_device_if_new,
    record_known_location_if_new,
    update_baseline_after_successful_login,
)
from app.detection.campaign_correlation import LIVE_CAMPAIGN_WINDOW
from app.detection.engine.types import LoginAttempt
from app.detection.geoip import lookup_asn, lookup_ip
from app.detection.rate_counter import check_fail_count, redis_client
from app.detection.rba_live_features import build_features_and_summary, event_record_for
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
from app.models import Alert, AuditLog, Campaign, LoginEvent, ResponseAction, User, UserBaseline, UserRiskProfile
from app.utils.device import compute_device_fingerprint, parse_user_agent
from app.utils.time import ensure_utc
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
                    # Cùng bug thật đã sửa ở is_impossible_travel (app/detection/rules.py, phát hiện ở MR13): previous_event.created_at
                    # đọc lại từ SQLite (test) mất tzinfo trong khi event.created_at vừa gán vẫn aware.
                    elapsed_minutes = (ensure_utc(event.created_at) - ensure_utc(previous_event.created_at)).total_seconds() / 60
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
                    event_record = event_record_for(event)
                    features, history_summary = build_features_and_summary(db, event_record)
                # MR15: ngưỡng THÍCH NGHI riêng cho tài khoản này nếu đã đủ phản hồi (adaptive_threshold.apply_delta),
                # NHÓM (mặc định) nếu chưa có hàng UserRiskProfile hay user_id là None (tên đăng nhập không tồn tại).
                user_bands = None
                if user_id is not None:
                    risk_profile = db.get(UserRiskProfile, user_id)
                    if risk_profile is not None and risk_profile.threshold_delta > 0:
                        user_bands = apply_delta(hybrid_runtime.get_engine().profile.bands, risk_profile.threshold_delta)
                risk_result = hybrid_runtime.get_engine().evaluate(features, evaluation.hits, bands=user_bands)
                event.hybrid_risk_score = risk_result.score
                event.hybrid_action = risk_result.action

                if risk_result.action != "allow":
                    # --- MR13: gán họ tấn công gợi ý, novelty, ưu tiên (app/detection/alert_intelligence.py — thuần, không đụng DB) ---
                    ml_component = hybrid_runtime.get_engine().ml_component(features)
                    family, confidence = alert_intelligence.suggest_attack_family(risk_result, ml_component=ml_component)
                    novelty_facts = alert_intelligence.compute_novelty(event_record, history_summary) if history_summary is not None else []
                    importance = user.importance if user is not None else 1.0
                    priority = alert_intelligence.priority_score(novelty_facts, confidence, importance)
                    top_rule = next((c.source for c in risk_result.contributions if c.source != "ml"), None)

                    # --- MR13: chống trùng lặp — cùng (tài khoản, hoặc IP nếu tài khoản không tồn tại) + họ tấn công,
                    # trong DEDUP_WINDOW gần nhất và còn "open" thì GỘP vào alert đó thay vì tạo hàng mới.
                    # ⚠️ Lọc theo THỜI ĐIỂM ĐĂNG NHẬP (LoginEvent.created_at, JOIN), KHÔNG PHẢI lúc hàng Alert được ghi
                    # (Alert.created_at, server_default=func.now()) — bug thật cùng lớp đã sửa ở MR14 (app/detection/
                    # campaign_correlation.py): hai mốc trùng nhau khi chấm gần thời gian thực, nhưng lệch hẳn khi nạp
                    # lại/mô phỏng nhiều "ngày" trong thời gian chạy thật ngắn (lộ ra qua MR15's feedback_loop_sim.py,
                    # vốn cố tình cách các vòng 1 NGÀY GIẢ trong khi cả script chạy thật chỉ mất vài giây — dedup theo
                    # Alert.created_at sẽ coi MỌI vòng trước đó là "trong cửa sổ 15 phút" vì đều được GHI gần như cùng
                    # một thời điểm THẬT, dù các vòng cách nhau cả ngày về mặt "thời điểm đăng nhập"). ---
                    existing_alert = None
                    if family is not None:
                        dedup_query = (
                            db.query(Alert)
                            .join(LoginEvent, Alert.login_event_id == LoginEvent.id)
                            .filter(Alert.attack_family == family, Alert.status == "open", LoginEvent.created_at >= event.created_at - alert_intelligence.DEDUP_WINDOW)
                        )
                        if user_id is not None:
                            dedup_query = dedup_query.filter(Alert.user_id == user_id)
                        else:
                            dedup_query = dedup_query.filter(Alert.user_id.is_(None), LoginEvent.ip_address == ip)
                        existing_alert = dedup_query.order_by(Alert.created_at.desc()).first()

                    # "action" đã lưu ở lần trước là mức TỆ NHẤT của cả đợt tính đến lúc đó (xem combined_action bên dưới) — không phải riêng lần đó.
                    previous_action = (existing_alert.explanation or {}).get("action", "alert") if existing_alert is not None else "allow"
                    escalated = existing_alert is not None and alert_intelligence.action_escalated(previous_action, risk_result.action)
                    combined_action = risk_result.action if existing_alert is None or escalated else previous_action
                    occurrence_count = (existing_alert.occurrence_count + 1) if existing_alert is not None else 1
                    message = alert_intelligence.build_alert_message(
                        risk_result, novelty_facts=novelty_facts, family=family, confidence=confidence, occurrence_count=occurrence_count
                    )
                    explanation = {
                        "contributions": [{"source": c.source, "label": c.label, "weight": round(c.weight, 4), "group": c.group} for c in risk_result.contributions],
                        "action": combined_action,  # mức TỆ NHẤT tính đến lần này (không phải riêng risk_result.action) — dùng lại ở lần dedup SAU
                    }

                    if existing_alert is not None:
                        hybrid_alert = existing_alert
                        hybrid_alert.risk_score = max(hybrid_alert.risk_score, risk_result.score)
                        hybrid_alert.severity = _HYBRID_SEVERITY[combined_action]
                        hybrid_alert.message = message
                        hybrid_alert.explanation = explanation
                        hybrid_alert.rule_id = risk_result.overridden_by or top_rule or hybrid_alert.rule_id
                        hybrid_alert.attack_family_confidence = confidence
                        hybrid_alert.occurrence_count = occurrence_count
                        hybrid_alert.last_seen_at = event.created_at
                        hybrid_alert.priority_score = max(hybrid_alert.priority_score or 0.0, priority)
                    else:
                        hybrid_alert = Alert(
                            login_event_id=event.id, user_id=user_id, alert_type="hybrid_risk",
                            severity=_HYBRID_SEVERITY[risk_result.action], risk_score=risk_result.score, message=message,
                            rule_id=risk_result.overridden_by or top_rule, explanation=explanation, attack_family=family,
                            attack_family_confidence=confidence, occurrence_count=1, last_seen_at=event.created_at, priority_score=priority,
                        )
                        db.add(hybrid_alert)
                    db.flush()
                    alert_records.append((hybrid_alert, {}))

                    # Không lặp lại ĐÚNG đề xuất cũ mỗi lần trùng — chỉ ghi thêm khi MỚI hoặc mức đề xuất đã TĂNG (vd alert -> lock).
                    if risk_result.action in ("step_up", "lock") and (existing_alert is None or escalated):
                        reasons = "; ".join(f"{c.label} ({c.weight:.0%})" for c in risk_result.contributions[:3])
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

        # --- MR14: tương quan chiến dịch — gom alert của BẤT KỲ tầng nào (1-3 hoặc hybrid_risk) CÙNG hạ tầng (IP hoặc
        # ASN) NHẮM VÀO NHIỀU TÀI KHOẢN KHÁC NHAU trong LIVE_CAMPAIGN_WINDOW thành một Campaign. Khác chống trùng lặp
        # của MR13 (chỉ gộp CÙNG một tài khoản/IP lặp lại) — ở đây là NHIỀU tài khoản chia sẻ hạ tầng. Cô lập riêng:
        # lỗi ở đây không được làm mất các alert đã tạo/commit ở trên (app/detection/campaign_correlation.py).
        try:
            if alert_records and (event.ip_address is not None or event.asn is not None):
                # ⚠️ Lọc theo THỜI ĐIỂM ĐĂNG NHẬP (LoginEvent.created_at), KHÔNG PHẢI lúc hàng Alert được ghi
                # (Alert.created_at, server_default=func.now()) — hai mốc này trùng nhau trong vận hành bình thường
                # (chấm gần như ngay khi xảy ra) nhưng KHÔNG PHẢI luôn vậy (nạp lại/backfill); test MR14 tự tạo timestamp
                # giả cũng lộ ra sai khác này ngay. So sánh chuẩn hoá múi giờ bằng ensure_utc() (đọc lại từ SQLite mất
                # tzinfo — cùng lớp lỗi đã sửa ở MR9/MR12/MR13). Quét toàn bảng alerts: chấp nhận được ở quy mô hiện tại
                # (chỉ chạy khi CÓ alert mới, không phải mọi lần đăng nhập) — cùng tinh thần GlobalCountsCache (MR12).
                now = ensure_utc(event.created_at)
                window_start = now - LIVE_CAMPAIGN_WINDOW
                matches = [
                    (a, ensure_utc(le.created_at))
                    for a, le in db.query(Alert, LoginEvent).join(LoginEvent, Alert.login_event_id == LoginEvent.id).filter(Alert.login_event_id != event.id)
                    if window_start <= ensure_utc(le.created_at) <= now
                    and ((event.ip_address is not None and le.ip_address == event.ip_address) or (event.asn is not None and le.asn == event.asn))
                    and not (le.user_id is not None and le.user_id == user_id)  # loại chính tài khoản này lặp lại — đó là việc của MR13, không phải "nhiều tài khoản"
                ]
                existing_campaign_id = next((a.campaign_id for a, _ in matches if a.campaign_id is not None), None)
                campaign = db.get(Campaign, existing_campaign_id) if existing_campaign_id is not None else None
                if campaign is None and matches:
                    shared = f"ASN {event.asn}" if event.asn is not None else f"IP {event.ip_address}"
                    earliest = min((ts for _, ts in matches), default=now)
                    campaign = Campaign(label=f"Chiến dịch qua {shared}", first_seen_at=earliest, last_seen_at=now)
                    db.add(campaign)
                    db.flush()

                if campaign is not None:
                    for alert_obj in (*(a for a, _ in matches), *(a for a, _ in alert_records)):
                        if alert_obj.campaign_id is None:
                            alert_obj.campaign_id = campaign.id
                            campaign.alert_count += 1
                        if campaign.attack_family is None and alert_obj.attack_family is not None:
                            campaign.attack_family = alert_obj.attack_family
                    if now > ensure_utc(campaign.last_seen_at):
                        campaign.last_seen_at = now
                    if now < ensure_utc(campaign.first_seen_at):
                        campaign.first_seen_at = now
                    db.flush()
        except Exception:  # noqa: BLE001 — MR14 không bao giờ được làm mất alert đã tạo ở tầng 1-3/MR12-13
            logger.exception("lỗi ở khối MR14 (tương quan chiến dịch) cho user_id=%s ip=%s — bỏ qua, các alert khác không bị ảnh hưởng", user_id, ip)

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
                    "attack_family": alert_obj.attack_family,  # MR13 — gợi ý, xem alert_obj.attack_family_confidence
                    "priority_score": alert_obj.priority_score,
                    "occurrence_count": alert_obj.occurrence_count,
                    "campaign_id": alert_obj.campaign_id,  # MR14 — None nếu chưa thuộc chiến dịch nào
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
