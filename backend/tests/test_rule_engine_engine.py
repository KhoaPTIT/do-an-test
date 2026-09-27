"""MR9 — bộ máy chấm luật: chế độ shadow/off, cấu hình, luật lỗi, nhãn không bị lộ, hai kho cho cùng kết quả, độ phức tạp."""

import random
import time
from datetime import datetime, timezone

import fakeredis

from app.detection.engine import Finding, LoginAttempt, MemoryStore, RedisStore, RuleConfig, RuleEngine, ThreatIntel
from app.detection.engine.registry import RuleSpec, rule
from app.detection.geoip import GeoResult

T0 = 1_700_000_000.0


def make(t, username="alice", success=False, ip="10.0.0.1", exists=True, **kw):
    return LoginAttempt(ts=T0 + t, username=username, success=success, ip=ip, user_key=f"u-{username}" if exists else None, **kw)


def signature(result):
    """Kết quả của một lần chấm ở dạng so sánh được: (mã luật, thông điệp, chế độ)."""
    return [(h.rule_id, h.message, h.mode) for h in result.hits], dict(result.skipped)


# ------------------------------------------------------------------------------------------------ chế độ và cấu hình


def test_shadow_rules_are_reported_but_never_enforced_and_off_rules_are_not_run():
    config = RuleConfig.from_dict({"rules": {"brute_force": {"mode": "shadow"}, "scripted_client": {"mode": "off"}}})
    engine = RuleEngine(config)
    results = [engine.evaluate(make(i, user_agent="curl/8.4.0")) for i in range(5)]
    last = results[-1]
    assert [h.rule_id for h in last.shadowed] == ["brute_force"] and last.hits[0].mode == "shadow"
    assert all(h.rule_id != "brute_force" for h in last.enforced)
    assert all("scripted_client" not in r.by_rule() and "scripted_client" not in r.skipped for r in results)  # off: không chạy, cũng không "bỏ qua"


def test_config_parameters_change_the_behaviour_of_a_rule():
    strict = RuleEngine(RuleConfig.from_dict({"rules": {"brute_force": {"params": {"threshold": 3, "window_s": 60}}}}))
    results = [strict.evaluate(make(i * 5)) for i in range(4)]
    assert [any(h.rule_id == "brute_force" for h in r.hits) for r in results] == [False, False, True, True]
    assert results[2].by_rule()["brute_force"].message == "Dò mật khẩu 'alice': 3 lần sai/60 giây (ngưỡng 3)."  # thông điệp phản ánh tham số mới
    slow = [strict.evaluate(make(100 + i * 30)) for i in range(3)]  # cửa sổ 60 giây: mỗi lần chỉ còn tối đa 2 lần sai trong cửa sổ
    assert not any(h.rule_id == "brute_force" for r in slow for h in r.hits)


def test_changing_the_config_keeps_the_window_state():
    engine = RuleEngine()
    for i in range(4):
        engine.evaluate(make(i))
    engine.set_config(RuleConfig.from_dict({"rules": {"brute_force": {"params": {"threshold": 6}}}}))  # nâng ngưỡng giữa chừng
    assert not any(h.rule_id == "brute_force" for h in engine.evaluate(make(4)).hits)  # 5 lần: dưới ngưỡng mới (mặc định thì đã báo)
    sixth = engine.evaluate(make(5))
    assert sixth.by_rule()["brute_force"].evidence["fails"] == 6  # 4 lần ghi trước khi đổi cấu hình vẫn được nhớ


def test_record_false_answers_the_question_without_changing_any_state():
    engine = RuleEngine()
    for i in range(4):
        engine.evaluate(make(i))
    peek = engine.evaluate(make(4), record=False)
    assert not any(h.rule_id == "brute_force" for h in peek.hits)  # lần thử "nếu như" không được tính vào số đếm
    assert engine.history.get("u-alice").last_event_ts == T0 + 3 and engine.stats.total_successes == 0  # lịch sử/thống kê cũng không đổi
    real = engine.evaluate(make(4))
    assert any(h.rule_id == "brute_force" for h in real.hits)  # lần thứ 5 THẬT mới chạm ngưỡng: lần xem thử không để lại dấu vết
    assert engine.history.get("u-alice").last_event_ts == T0 + 4


# ------------------------------------------------------------------------------------------------ độ bền


def test_a_failing_rule_is_recorded_without_stopping_the_others():
    registry: dict[str, RuleSpec] = {}
    rule(id="hong", title="hỏng", category="Tự động hoá", severity="low", description="luôn lỗi", registry=registry)(lambda ctx: 1 / 0)
    rule(id="tot", title="tốt", category="Tự động hoá", severity="high", description="luôn khớp", registry=registry)(lambda ctx: Finding("ổn", {"k": 1}, severity="medium"))
    result = RuleEngine(registry=registry).evaluate(make(0))
    assert "ZeroDivisionError" in result.errors["hong"] and [h.rule_id for h in result.hits] == ["tot"]
    assert result.hits[0].severity == "medium" and dict(result.hits[0].evidence) == {"k": 1}  # mức nêu trong Finding ghi đè mức mặc định của luật


def test_rules_never_see_the_labels_of_a_replayed_log():
    def scenario(flag):
        rng = random.Random(11)
        return [
            LoginAttempt(
                ts=T0 + i * 5, username=f"user{rng.randrange(8)}", success=rng.random() < 0.3, ip=f"10.0.0.{rng.randrange(4)}", user_key="k",
                labels={"is_attack_ip": flag, "is_ato": flag},
            )
            for i in range(300)
        ]

    a, b = RuleEngine(), RuleEngine()
    assert [signature(a.evaluate(x)) for x in scenario(True)] == [signature(b.evaluate(x)) for x in scenario(False)]


def test_time_is_the_events_time_not_the_wall_clock():
    """Replay log năm 2020 hôm nay phải cho đúng kết quả của năm 2020: cửa sổ tính theo `ts` của sự kiện."""
    old = RuleEngine()
    results = [old.evaluate(LoginAttempt(ts=1_580_000_000.0 + i, username="alice", success=False, ip="10.0.0.1", user_key="1")) for i in range(5)]
    assert any(h.rule_id == "brute_force" for h in results[4].hits)
    spread = RuleEngine()
    slow = [spread.evaluate(LoginAttempt(ts=1_580_000_000.0 + i * 3600, username="alice", success=False, ip="10.0.0.1", user_key="1")) for i in range(5)]
    assert not any(h.rule_id == "brute_force" for r in slow for h in r.hits)  # cách nhau 1 giờ: không bao giờ chạm ngưỡng 5 phút


def test_evaluation_helpers_and_timing():
    engine = RuleEngine(RuleConfig.from_dict({"rules": {"scripted_client": {"mode": "shadow"}}}))
    result = engine.evaluate(make(0, user_agent="curl/8.4.0", device_type="bot"))
    assert {h.rule_id for h in result.enforced} == {"bot_user_agent"} and {h.rule_id for h in result.shadowed} == {"scripted_client"}
    assert set(result.by_rule()) == {"bot_user_agent", "scripted_client"} and result.elapsed_ms > 0


# ------------------------------------------------------------------------------------------------ hai kho, cùng kết quả


def random_scenario(seed, n=700, gap=15.0):
    rng = random.Random(seed)
    users = [f"user{i}" for i in range(20)] + ["ghost1", "ghost2", "ghost3", "ghost4"]
    ips = [f"10.{i // 4}.{i % 4}.1" for i in range(10)] + ["185.220.101.1"]
    agents = ["Mozilla/5.0 (Windows NT 10.0) Chrome/120", "Mozilla/5.0 (X11; Linux) Firefox/121", "curl/8.4.0", "python-httpx/0.27.0", "Safari/605", None]
    geo = {"VN": (21.03, 105.85), "US": (40.71, -74.01), "DE": (52.52, 13.40), None: (None, None)}
    t, out = 0.0, []
    for _ in range(n):
        t += rng.expovariate(1 / gap)
        name = rng.choice(users)
        exists = name.startswith("user")
        country = rng.choice(list(geo))
        out.append(
            LoginAttempt(
                ts=T0 + t, username=name, success=exists and rng.random() < 0.3, ip=rng.choice(ips), user_key=f"k-{name}" if exists else None,
                asn=rng.choice([64500, 64501, 64502, None]), country=country, latitude=geo[country][0], longitude=geo[country][1],
                user_agent=rng.choice(agents), device_type=rng.choice(["desktop", "mobile", "bot", None]),
            )
        )
    return out


def engines():
    intel = ThreatIntel(tor=frozenset({"185.220.101.1"}), loaded={"tor": True, "datacenter": False, "vpn": False})
    memory = RuleEngine(store=MemoryStore(), intel=intel)
    redis = RuleEngine(store=RedisStore(fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True)), intel=intel)
    return memory, redis


def test_memory_and_redis_stores_give_identical_results_on_random_traffic():
    for seed in (1, 2, 3):
        memory, redis = engines()
        scenario = random_scenario(seed)
        left = [signature(memory.evaluate(a)) for a in scenario]
        right = [signature(redis.evaluate(a)) for a in scenario]
        assert left == right, f"seed {seed}: hai kho lệch nhau"
        fired = {rule_id for hits, _ in left for rule_id, _, _ in hits}
        assert len(fired) >= 6  # kịch bản đủ đa dạng để phép so sánh có ý nghĩa (nhiều luật thật sự khớp)


def test_sweeping_expired_keys_does_not_change_the_results_of_the_rules():
    """3.000 sự kiện trải hơn 2 ngày (cửa sổ dài nhất là 24 giờ, riêng `country_hop` tới 7 ngày): nhiều khoá hết hạn và bị dọn, kết quả vẫn phải y hệt."""
    once = [LoginAttempt(ts=T0 + i * 30, username=f"once{i}", success=False, ip=f"9.9.{i // 250}.{i % 250 + 1}") for i in range(1_500)]  # 12,5 giờ đầu: mỗi tên/IP chỉ một lần
    scenario = sorted(random_scenario(5, n=3_000, gap=60.0) + once, key=lambda a: a.ts)
    swept, plain = RuleEngine(store=MemoryStore(sweep_every=50)), RuleEngine(store=MemoryStore(sweep_every=0))
    assert [signature(swept.evaluate(a)) for a in scenario] == [signature(plain.evaluate(a)) for a in scenario]
    assert swept.store.keys() < plain.store.keys() - 1_000  # các khoá dùng một lần đã hết hạn và bị dọn


# ------------------------------------------------------------------------------------------------ dựng từ request thật


def test_login_attempt_from_request_parses_the_user_agent_and_geo():
    stamp = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)
    chrome = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    a = LoginAttempt.from_request(
        username="alice", user_id=5, success=True, ip="1.2.3.4", user_agent=chrome, timestamp=stamp, geo=GeoResult("VN", "Hanoi", 21.03, 105.85), asn=45899
    )
    assert a.ts == stamp.timestamp() and a.user_key == "5" and a.user_exists and a.asn == 45899
    assert (a.country, a.city, a.latitude, a.longitude, a.has_geo) == ("VN", "Hanoi", 21.03, 105.85, True)
    assert a.device_type == "mobile" and a.browser and a.os == "Android" and len(a.ua_hash) == 12
    anonymous = LoginAttempt.from_request(username="ghost", user_id=None, success=False, ip="9.9.9.9", user_agent=None, timestamp=stamp)
    assert anonymous.user_key is None and not anonymous.user_exists and anonymous.device_type == "unknown" and anonymous.ua_hash == "" and not anonymous.has_geo
    assert a.ua_hash == LoginAttempt.from_request(username="b", user_id=1, success=True, ip="1.1.1.1", user_agent=chrome, timestamp=stamp).ua_hash  # ổn định


# ------------------------------------------------------------------------------------------------ không có độ phức tạp bậc hai


def test_a_very_busy_ip_costs_the_same_per_event_as_a_quiet_one():
    """IP tấn công có hàng chục nghìn lần thử mỗi ngày: chi phí mỗi sự kiện bị chặn bởi ngưỡng (`CAP`), không tăng theo độ dài cửa sổ."""

    def run(n):
        engine = RuleEngine()
        started = time.perf_counter()
        for i in range(n):
            engine.evaluate(LoginAttempt(ts=T0 + i * 0.5, username=f"user{i % 3000}", success=False, ip="66.66.66.66", user_key=f"k{i % 3000}", asn=64500, user_agent=f"UA-{i % 7}"))
        return time.perf_counter() - started

    small, large = run(2_000), run(8_000)  # 4 lần số sự kiện: tuyến tính ≈ 4 lần thời gian, bậc hai ≈ 16 lần
    assert large < small * 10, f"nghi độ phức tạp bậc hai: {small:.2f}s -> {large:.2f}s"
