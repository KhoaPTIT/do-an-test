"""Kiểm thử tự động.

Chạy:  pytest tests/ -v

Bộ kiểm thử tập trung vào những chỗ dễ sai và khó phát hiện bằng mắt:
tính đúng của từng luật, quy tắc chống rò rỉ dữ liệu tương lai, cơ chế
lùi về dùng riêng luật khi thiếu lịch sử, và các lớp bảo vệ của API.
"""
from datetime import datetime, timedelta

import pytest

from app.detection.features import (EventData, compute_context,
                                    extract_features, haversine_km)
from app.detection.rules import (rule_brute_force, rule_credential_stuffing,
                                 rule_impossible_travel, rule_new_country,
                                 rule_odd_hour, run_rules)
from app.detection.scoring import assess, decide
from app.utils.device import fingerprint, parse_ua
from app.utils.geoip import lookup_ip

BASE = datetime(2026, 3, 15, 10, 0, 0)

HANOI = dict(country="Vietnam", city="Ha Noi", latitude=21.028, longitude=105.854)
MOSCOW = dict(country="Russia", city="Moscow", latitude=55.755, longitude=37.617)


def ev(username="user001", ip="14.161.1.1", ts=BASE, success=True,
       device="dev-a", network="residential", device_type="desktop", **geo):
    g = {**HANOI, **geo}
    return EventData(username=username, ip_address=ip, timestamp=ts,
                     login_successful=success, network_type=network,
                     device_fingerprint=device, device_type=device_type, **g)


def history(n=10, ip="14.161.1.1", device="dev-a", hour=10, **geo):
    """Sinh n lần đăng nhập quen thuộc, mới nhất trước."""
    return [ev(ip=ip, device=device,
               ts=BASE - timedelta(days=i + 1, hours=BASE.hour - hour), **geo)
            for i in range(n)]


def ctx_for(event, hist, failed=0, distinct=0):
    return compute_context(event, hist, failed, distinct)


# --- Hàm tính khoảng cách ---

class TestHaversine:
    def test_same_point_is_zero(self):
        assert haversine_km(21.0, 105.8, 21.0, 105.8) == 0

    def test_hanoi_to_moscow(self):
        d = haversine_km(21.028, 105.854, 55.755, 37.617)
        assert 6000 < d < 7500          # khoảng cách thực tế xấp xỉ 6700 km

    def test_missing_coordinates_returns_zero(self):
        assert haversine_km(None, 105.8, 21.0, 105.8) == 0


# --- Từng luật ---

class TestRules:
    def test_new_country_fires(self):
        e = ev(**MOSCOW)
        hit = rule_new_country(e, ctx_for(e, history(10)))
        assert hit is not None and hit.code == "R01"

    def test_new_country_silent_without_enough_history(self):
        """Tài khoản mới chưa đủ lịch sử thì không thể kết luận là bất thường."""
        e = ev(**MOSCOW)
        assert rule_new_country(e, ctx_for(e, history(1))) is None

    def test_impossible_travel_fires(self):
        hist = [ev(ts=BASE - timedelta(hours=1))]        # Hà Nội, 1 giờ trước
        e = ev(ts=BASE, **MOSCOW)                         # Moscow, bây giờ
        hit = rule_impossible_travel(e, ctx_for(e, hist))
        assert hit is not None and hit.code == "R02"

    def test_plausible_travel_does_not_fire(self):
        """Hà Nội sang Moscow trong 12 giờ là bay thẳng, hoàn toàn hợp lệ."""
        hist = [ev(ts=BASE - timedelta(hours=12))]
        e = ev(ts=BASE, **MOSCOW)
        assert rule_impossible_travel(e, ctx_for(e, hist)) is None

    def test_brute_force_threshold(self):
        e = ev()
        assert rule_brute_force(e, ctx_for(e, history(), failed=4)) is None
        assert rule_brute_force(e, ctx_for(e, history(), failed=5)) is not None

    def test_credential_stuffing_threshold(self):
        e = ev()
        assert rule_credential_stuffing(e, ctx_for(e, history(), distinct=9)) is None
        assert rule_credential_stuffing(e, ctx_for(e, history(), distinct=10)) is not None

    def test_odd_hour_tolerates_neighbouring_hours(self):
        """Đăng nhập lúc 11h khi thói quen là 10h thì không phải bất thường."""
        hist = history(12, hour=10)
        e = ev(ts=BASE.replace(hour=11))
        assert rule_odd_hour(e, ctx_for(e, hist)) is None

    def test_odd_hour_fires_far_from_habit(self):
        hist = history(12, hour=10)
        e = ev(ts=BASE.replace(hour=3))
        hit = rule_odd_hour(e, ctx_for(e, hist))
        assert hit is not None and hit.code == "R06"

    def test_tor_network_flagged(self):
        e = ev(network="tor")
        codes = {h.code for h in run_rules(e, ctx_for(e, history()))}
        assert "R07" in codes

    def test_bot_user_agent_flagged(self):
        e = ev(device_type="bot")
        codes = {h.code for h in run_rules(e, ctx_for(e, history()))}
        assert "R08" in codes

    def test_normal_login_triggers_nothing(self):
        """Đây là kiểm thử quan trọng nhất: hành vi bình thường phải im lặng.

        Cùng IP quen, cùng thiết bị quen, cùng quốc gia, đúng khung giờ quen.
        Nếu kiểm thử này đỏ nghĩa là hệ thống sẽ làm phiền người dùng thật.
        """
        hist = history(20, hour=10)
        e = ev(ts=BASE.replace(hour=10) + timedelta(minutes=20))
        assert run_rules(e, ctx_for(e, hist)) == []


# --- Chấm điểm và quyết định ---

class TestScoring:
    def test_thresholds(self):
        assert decide(10) == "allow"
        assert decide(45) == "challenge"
        assert decide(85) == "block"

    def test_normal_login_is_allowed(self):
        hist = history(20, hour=10)
        e = ev(ts=BASE.replace(hour=10) + timedelta(minutes=20))
        assert assess(e, ctx_for(e, hist))["decision"] == "allow"

    def test_obvious_attack_is_blocked(self):
        hist = history(20)
        e = ev(ip="185.220.101.5", network="tor", device_type="bot",
               device="dev-x", **MOSCOW)
        result = assess(e, ctx_for(e, hist, failed=8))
        assert result["decision"] == "block"
        assert result["risk_score"] >= 70

    def test_cold_start_falls_back_to_rules(self):
        """Tài khoản chưa đủ lịch sử: hệ thống phải lùi về chế độ chỉ dùng luật
        thay vì để mô hình đoán bừa trên dữ liệu không đủ."""
        e = ev()
        result = assess(e, ctx_for(e, history(2)))
        assert result["mode"] == "rule_only"
        assert result["ml_score"] is None

    def test_rule_score_is_capped(self):
        hist = history(20)
        e = ev(ip="185.220.101.5", network="tor", device_type="bot",
               device="dev-x", ts=BASE.replace(hour=3), **MOSCOW)
        result = assess(e, ctx_for(e, hist, failed=20, distinct=50))
        assert result["rule_score"] <= 100


# --- Chống rò rỉ dữ liệu tương lai ---

class TestNoDataLeakage:
    def test_context_only_uses_given_history(self):
        """compute_context không được tự đi tìm dữ liệu ở đâu khác.
        Lịch sử rỗng thì mọi đại lượng lịch sử phải bằng không.
        """
        e = ev()
        c = ctx_for(e, [])
        assert c["history_count"] == 0
        assert c["known_countries"] == set()
        assert c["travel_distance_km"] == 0
        assert c["travel_speed_kmh"] == 0

    def test_feature_vector_length_matches_names(self):
        from app.detection.features import FEATURE_NAMES
        e = ev()
        assert len(extract_features(e, ctx_for(e, history()))) == len(FEATURE_NAMES)

    def test_features_are_finite(self):
        """Tốc độ di chuyển có thể tiến tới vô cùng khi hai lần đăng nhập
        cách nhau vài giây. Đặc trưng vẫn phải là số hữu hạn."""
        import math
        hist = [ev(ts=BASE - timedelta(seconds=2))]
        e = ev(ts=BASE, **MOSCOW)
        for v in extract_features(e, ctx_for(e, hist)):
            assert math.isfinite(v)


# --- Tiện ích ---

class TestUtils:
    def test_bot_agents_detected(self):
        for ua in ["python-requests/2.31.0", "curl/8.4.0", "Go-http-client/1.1"]:
            assert parse_ua(ua)["device_type"] == "bot"

    def test_browser_parsed(self):
        ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/122.0 Safari/537.36")
        p = parse_ua(ua)
        assert p["os"] == "Windows" and p["browser"] == "Chrome"

    def test_fingerprint_ignores_ip(self):
        """Đổi mạng không được làm thiết bị trở thành thiết bị lạ."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0 Safari/537.36"
        assert fingerprint(ua, "14.161.1.1") == fingerprint(ua, "203.0.113.9")

    def test_fingerprint_differs_across_devices(self):
        a = "Mozilla/5.0 (Windows NT 10.0) Chrome/122.0 Safari/537.36"
        b = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile Safari/604.1"
        assert fingerprint(a) != fingerprint(b)

    def test_geoip_known_prefix(self):
        assert lookup_ip("14.161.5.5")["country"] == "Vietnam"

    def test_geoip_tor_prefix(self):
        assert lookup_ip("185.220.101.5")["network_type"] == "tor"

    def test_geoip_invalid_input(self):
        assert lookup_ip("không-phải-ip")["country"] == "Unknown"


# --- API ---

@pytest.fixture
def client(tmp_path, monkeypatch):
    """Ứng dụng dùng database SQLite tạm, mỗi lần kiểm thử một file riêng."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")

    import importlib
    from fastapi.testclient import TestClient

    import app.config, app.database, app.main
    importlib.reload(app.config)
    importlib.reload(app.database)
    importlib.reload(app.main)

    app.database.init_db()
    return TestClient(app.main.app)


HEADERS = {"X-API-Key": "demo-api-key-doi-truoc-khi-nop"}


class TestAPI:
    def test_health_needs_no_key(self, client):
        assert client.get("/health").json() == {"status": "ok"}

    def test_missing_key_rejected(self, client):
        assert client.get("/api/v1/alerts").status_code == 422

    def test_wrong_key_rejected(self, client):
        r = client.get("/api/v1/alerts", headers={"X-API-Key": "sai"})
        assert r.status_code == 401

    def test_ingest_returns_decision(self, client):
        r = client.post("/api/v1/login-event", headers=HEADERS, json={
            "username": "alice", "ip_address": "14.161.2.3",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/122.0 Safari/537.36",
            "login_successful": True,
        })
        assert r.status_code == 200
        assert r.json()["decision"] in ("allow", "challenge", "block")

    def test_invalid_ip_rejected(self, client):
        r = client.post("/api/v1/login-event", headers=HEADERS, json={
            "username": "alice", "ip_address": "999.999.1.1",
            "user_agent": "x", "login_successful": True,
        })
        assert r.status_code == 422

    def test_blocked_ip_is_denied(self, client):
        ip = "203.0.113.77"
        client.post("/api/v1/blocked-ips", headers=HEADERS,
                    json={"ip_address": ip, "reason": "kiểm thử"})
        r = client.post("/api/v1/login-event", headers=HEADERS, json={
            "username": "bob", "ip_address": ip,
            "user_agent": "Mozilla/5.0 Chrome/122.0", "login_successful": True,
        })
        assert r.json()["decision"] == "block"

    def test_brute_force_creates_alert(self, client):
        for _ in range(8):
            client.post("/api/v1/login-event", headers=HEADERS, json={
                "username": "carol", "ip_address": "185.220.101.9",
                "user_agent": "python-requests/2.31.0", "login_successful": False,
            })
        alerts = client.get("/api/v1/alerts", headers=HEADERS).json()
        assert len(alerts) > 0

    def test_false_positive_updates_event_label(self, client):
        """Vòng phản hồi: đánh dấu báo động giả phải ghi nhãn ngược
        vào sự kiện gốc để dùng cho lần huấn luyện sau."""
        client.post("/api/v1/login-event", headers=HEADERS, json={
            "username": "dave", "ip_address": "185.220.101.11",
            "user_agent": "curl/8.4.0", "login_successful": True,
        })
        alerts = client.get("/api/v1/alerts", headers=HEADERS).json()
        assert alerts, "Cần ít nhất một cảnh báo để kiểm thử"

        aid = alerts[0]["id"]
        r = client.patch(f"/api/v1/alerts/{aid}", headers=HEADERS,
                         json={"status": "false_positive",
                               "analyst_note": "người dùng thật, đã xác minh"})
        assert r.status_code == 200
        assert r.json()["status"] == "false_positive"

        ev_id = r.json()["event_id"]
        event = client.get(f"/api/v1/events/{ev_id}", headers=HEADERS).json()
        assert event["is_attack"] is False

    def test_stats_overview_shape(self, client):
        d = client.get("/api/v1/stats/overview", headers=HEADERS).json()
        for key in ("total_events", "events_24h", "open_alerts", "model"):
            assert key in d
