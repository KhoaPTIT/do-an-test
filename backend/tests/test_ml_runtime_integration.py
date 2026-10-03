"""Model bất thường trong luồng /login THẬT (Phase 4.1G–I): lưu kết quả ML, cảnh báo chỉ-ML, ML + luật, ML không tự khoá,
thiếu model thì rơi về 20 detector luật, API trả kết quả ML thật."""

from datetime import timedelta

import pytest

from app.detection import hybrid_runtime, ml_runtime
from app.detection.attribution import ML_ONLY_DETECTOR, ML_SIGNAL
from app.detection.hybrid import ActionBands, HybridProfile, RuleWeights
from app.detection.hybrid.calibration import RuleWeightEntry
from app.models import Admin, BlocklistEntry, LoginEvent
from app.security import hash_password
from tests.behavior_detection.conftest import HOME_IP, JP_IP, T0, seed_user
from verification.harness import CHROME_UA, CURL_UA, SAFARI_UA, VerificationEnv


@pytest.fixture()
def env_ml(monkeypatch, trained_ml_model_dir):
    return VerificationEnv(setattr_fn=monkeypatch.setattr, ml_model_dir=trained_ml_model_dir)


@pytest.fixture()
def env_no_ml(monkeypatch):
    return VerificationEnv(setattr_fn=monkeypatch.setattr)


def _events(env):
    db = env.session_factory()
    try:
        return db.query(LoginEvent).filter(LoginEvent.is_synthetic.is_(False)).order_by(LoginEvent.id).all()
    finally:
        db.close()


def _force_ml(monkeypatch, env, *, is_anomaly=True, score=0.9):
    """Ép model trả về một dự đoán cố định (kiểm luồng gộp/quy kết độc lập với chất lượng model)."""
    prediction = ml_runtime.MLPrediction(available=True, in_scope=True, model_name="isolation_forest", model_version="forced",
                                         anomaly_score=score, threshold=0.6, is_anomaly=is_anomaly, top_features=({"feature": "is_new_device", "z": 3.0},))
    monkeypatch.setattr(env.ml_runtime, "predict", lambda db, event: prediction)
    return prediction


def test_real_model_scores_a_mature_success_and_persists_the_result(env_ml):
    seed_user(env_ml, "alice", days=20)
    env_ml.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=CHROME_UA)
    env_ml.login("alice", success=True, ip=JP_IP, ts=T0 + timedelta(minutes=20), user_agent=SAFARI_UA)
    normal, odd = _events(env_ml)
    for e in (normal, odd):
        assert e.ml_anomaly_score is not None and e.ml_threshold is not None and e.ml_model_version
        assert e.ml_details["in_scope"] is True and e.ml_is_anomaly == (e.ml_anomaly_score >= e.ml_threshold)
    assert odd.ml_anomaly_score > normal.ml_anomaly_score and odd.ml_is_anomaly is True
    alert = env_ml.detection_alerts()[-1]
    assert alert.explanation["ml"]["is_anomaly"] is True and alert.explanation["ml"]["model"] == "isolation_forest"


def test_failed_logins_are_not_scored_by_the_model(env_ml):
    seed_user(env_ml, "alice", days=20)
    env_ml.login("alice", success=False, ip=JP_IP, ts=T0, user_agent=CHROME_UA)
    (event,) = _events(env_ml)
    assert event.ml_anomaly_score is None and event.ml_is_anomaly is None and event.ml_details["reason"] == "out_of_scope"


def test_ml_only_anomaly_creates_an_ml_alert_that_does_not_step_up_or_lock(env_no_ml, monkeypatch):
    seed_user(env_no_ml, "alice", days=20)
    _force_ml(monkeypatch, env_no_ml)
    env_no_ml.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=CHROME_UA)  # không luật nào khớp
    (alert,) = env_no_ml.detection_alerts()
    exp = alert.explanation
    assert alert.rule_id is None and exp["primary_detector"] == ML_ONLY_DETECTOR and exp["alert_reason"] == "score_threshold"
    assert exp["action"] == "alert" and exp["ml"]["is_anomaly"] is True and exp["ml"]["anomaly_score"] == 0.9
    (event,) = _events(env_no_ml)
    assert event.hybrid_action == "alert" and event.ml_is_anomaly is True


def test_realtime_alert_payload_carries_the_explanation_with_ml(env_no_ml, monkeypatch):
    """Dashboard nhận cảnh báo qua WebSocket: payload phải mang `explanation` (detector, bằng chứng, khối ml) như GET /alerts."""
    seed_user(env_no_ml, "alice", days=20)
    _force_ml(monkeypatch, env_no_ml)
    result = env_no_ml.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=CHROME_UA)
    (payload,) = [p for p in result.alert_payloads if p["explanation"]]
    assert payload["explanation"]["primary_detector"] == ML_ONLY_DETECTOR and payload["explanation"]["ml"]["anomaly_score"] == 0.9


def test_ml_agreeing_with_a_rule_is_a_secondary_signal(env_no_ml, monkeypatch):
    seed_user(env_no_ml, "alice", days=20)
    _force_ml(monkeypatch, env_no_ml)
    env_no_ml.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=CURL_UA)  # scripted_client khớp
    (alert,) = env_no_ml.detection_alerts()
    assert alert.rule_id == "scripted_client" and ML_SIGNAL in alert.explanation["secondary_signals"]
    assert alert.explanation["ml"]["is_anomaly"] is True


def test_ml_never_locks_an_account_through_the_pipeline(env_no_ml, monkeypatch):
    """Luật một mình 80 (step_up) + ML ⇒ 89 ≥ 85: hành động bị chốt ở step_up, không mục khoá nào được tạo."""
    monkeypatch.setattr(hybrid_runtime.get_engine(), "profile",
                        HybridProfile(RuleWeights(entries={"scripted_client": RuleWeightEntry(0.8, True)}), ActionBands(40, 65, 85), None))
    seed_user(env_no_ml, "alice", days=20)
    _force_ml(monkeypatch, env_no_ml)
    env_no_ml.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=CURL_UA)
    (event,) = _events(env_no_ml)
    assert event.hybrid_risk_score >= 85 and event.hybrid_action == "step_up"
    (alert,) = env_no_ml.detection_alerts()
    assert alert.explanation["ml_lock_suppressed"] is True
    db = env_no_ml.session_factory()
    try:
        assert db.query(BlocklistEntry).count() == 0
    finally:
        db.close()


def test_missing_model_falls_back_to_the_rules(env_no_ml):
    assert env_no_ml.ml_runtime.available is False
    seed_user(env_no_ml, "alice", days=20)
    env_no_ml.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=CURL_UA)
    (event,) = _events(env_no_ml)
    assert event.ml_anomaly_score is None and event.ml_details == {"model": None, "available": False, "in_scope": False, "reason": "model_not_loaded", "top_features": []}
    assert [a.rule_id for a in env_no_ml.detection_alerts()] == ["scripted_client"]  # 20 detector luật vẫn chạy


# ------------------------------------------------------------------------------------------------ API


def _admin_headers(client, db_session):
    db_session.add(Admin(username="admin", password_hash=hash_password("MatKhauQuanTri123!")))
    db_session.commit()
    token = client.post("/admin/login", json={"username": "admin", "password": "MatKhauQuanTri123!"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_login_events_api_returns_the_stored_ml_result(client, db_session):
    db_session.add(LoginEvent(
        attempted_username="alice", success=True, ip_address="192.0.2.10", is_synthetic=False, created_at=T0,
        ml_anomaly_score=0.71, ml_is_anomaly=True, ml_threshold=0.59, ml_model_version="v3-x",
        ml_details={"model": "isolation_forest", "available": True, "in_scope": True, "reason": None, "top_features": [{"feature": "is_new_device", "z": 3.1}]},
    ))
    db_session.commit()
    item = client.get("/login-events", headers=_admin_headers(client, db_session)).json()["items"][0]
    assert (item["ml_anomaly_score"], item["ml_is_anomaly"], item["ml_threshold"], item["ml_model_version"]) == (0.71, True, 0.59, "v3-x")
    assert item["ml_details"]["model"] == "isolation_forest"


def test_ml_status_reports_a_loaded_model(client, db_session, ml_on):
    status = client.get("/ml/status", headers=_admin_headers(client, db_session)).json()
    assert status["ml_available"] is True and status["model_name"] == "isolation_forest" and status["model_version"] == ml_on.model.model_version
    assert status["feature_signature"] == status["code_feature_signature"] and status["artifact_files"] == {"model.joblib": True, "metadata.json": True}
    assert status["can_lock"] is False and status["last_load_error"] is None


def test_ml_status_reports_why_no_model_is_loaded(client, db_session):
    status = client.get("/ml/status", headers=_admin_headers(client, db_session)).json()
    assert status["ml_available"] is False and status["model_version"] is None and status["last_load_error"]


def test_ml_status_requires_an_admin(client):
    assert client.get("/ml/status").status_code in (401, 403)
