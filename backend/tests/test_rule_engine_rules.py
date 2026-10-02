"""MR9 — từng luật của rule engine v2: ca dương (phải báo) và ca âm (không được báo) trên dữ liệu tổng hợp nhỏ, chạy qua RuleEngine thật."""

import random

import httpx
import pytest

from app.detection.engine import CidrSet, LoginAttempt, MemoryGlobalStats, RuleConfig, RuleEngine, ThreatIntel

T0 = 1_700_000_000.0
HANOI, NEW_YORK = (21.03, 105.85), (40.71, -74.01)


def make(t, username="alice", success=False, ip="10.0.0.1", exists=True, **kw):
    """Một lần thử ở thời điểm T0 + t giây. `exists=False`: tên đăng nhập bịa (không có tài khoản)."""
    return LoginAttempt(ts=T0 + t, username=username, success=success, ip=ip, user_key=f"u-{username}" if exists else None, **kw)


def run(engine, attempts):
    return [engine.evaluate(a) for a in attempts]


def fired(results, rule_id):
    """Chỉ số các lần thử mà luật `rule_id` khớp."""
    return [i for i, r in enumerate(results) if any(h.rule_id == rule_id for h in r.hits)]


def hit(result, rule_id):
    return result.by_rule()[rule_id]


# ------------------------------------------------------------------------------------------------ brute_force


def test_brute_force_fires_from_the_threshold_within_the_window():
    results = run(RuleEngine(), [make(i * 10, ip=f"10.0.0.{i}") for i in range(6)])  # 6 lần sai vào alice, mỗi lần một IP khác
    assert fired(results, "brute_force") == [4, 5]  # từ lần sai thứ 5, như luật gốc (báo ở mỗi lần sai từ ngưỡng)
    first = hit(results[4], "brute_force")
    assert first.message == "Dò mật khẩu 'alice': 5 lần sai/5 phút (ngưỡng 5)."  # đúng chuỗi của pipeline hiện tại
    assert (first.severity, first.mode, first.techniques) == ("high", "enforce", ("T1110.001",)) and first.evidence["fails"] == 5


def test_brute_force_ignores_slow_scattered_or_successful_attempts():
    assert fired(run(RuleEngine(), [make(i * 10) for i in range(4)]), "brute_force") == []  # 4 lần: chưa đủ
    assert fired(run(RuleEngine(), [make(i * 90) for i in range(5)]), "brute_force") == []  # 5 lần nhưng trải 6 phút: cửa sổ 5 phút chỉ còn 4
    assert fired(run(RuleEngine(), [make(t) for t in (0, 75, 150, 225, 300)]), "brute_force") == []  # lần đầu cách đúng 300 giây: KHÔNG tính (cửa sổ mở)
    assert fired(run(RuleEngine(), [make(i, username="alice") for i in range(3)] + [make(i + 3, username="bob") for i in range(3)]), "brute_force") == []
    mixed = [make(i, success=(i == 2)) for i in range(6)]  # 5 sai + 1 đúng (thất bại áp đảo)
    assert fired(run(RuleEngine(), mixed), "brute_force") == [5]  # chỉ đủ 5 lần SAI ở lần thứ 6; nếu đếm cả thành công thì đã báo từ lần thứ 5
    # Milestone C (thay expectation cũ "5 sai xen 5 đúng thì báo ở lần thứ 10"): gõ sai LẪN TRONG nhiều lần đúng (tài khoản
    # dùng chung) không phải dò mật khẩu — lộ ra từ lưu lượng bình thường v3.
    interleaved = [make(i, success=(i % 2 == 0)) for i in range(10)]
    assert fired(run(RuleEngine(), interleaved), "brute_force") == []
    assert fired(run(RuleEngine(), [make(i, success=True) for i in range(20)]), "brute_force") == []


def test_brute_force_counts_unknown_usernames_like_the_original_rule():
    results = run(RuleEngine(), [make(i, username="khongco", exists=False) for i in range(5)])
    assert fired(results, "brute_force") == [4]


# ------------------------------------------------------------------------------------------------ credential_stuffing


def test_credential_stuffing_fires_for_many_usernames_from_one_ip():
    attacker = [make(i * 5, username=f"user{i % 5}", ip="9.9.9.9") for i in range(10)]  # 10 lần sai, 5 tên, 45 giây
    results = run(RuleEngine(), attacker)
    assert fired(results, "credential_stuffing") == [9]
    found = hit(results[9], "credential_stuffing")
    assert found.message == "IP 9.9.9.9 thử 5 tài khoản khác nhau, 10 lần sai/5 phút (ngưỡng 5 TK / 10 lần)."  # đúng chuỗi của pipeline hiện tại
    assert found.techniques == ("T1110.004",) and found.evidence["scope"] == "ip" and found.evidence["distinct_users"] == 5


def test_credential_stuffing_needs_many_usernames_and_many_failures():
    same_user = run(RuleEngine(), [make(i, ip="9.9.9.8") for i in range(12)])
    assert fired(same_user, "credential_stuffing") == [] and fired(same_user, "brute_force") != []  # một tên = dò mật khẩu, không phải nhồi
    assert fired(run(RuleEngine(), [make(i, username=f"u{i % 5}", ip="9.9.9.7") for i in range(9)]), "credential_stuffing") == []  # 9 lần
    assert fired(run(RuleEngine(), [make(i, username=f"u{i % 4}", ip="9.9.9.6") for i in range(12)]), "credential_stuffing") == []  # 4 tên
    slow = [make(i * 60, username=f"u{i % 6}", ip="9.9.9.5") for i in range(12)]  # trải 11 phút: cửa sổ 5 phút chỉ có ~5 lần
    assert fired(run(RuleEngine(), slow), "credential_stuffing") == []


def test_credential_stuffing_is_skipped_when_the_ip_mostly_succeeds():
    """Nhiều người dùng thật sau một cổng NAT: cùng số lần sai nhưng thành công chiếm đa số → không phải nhồi thông tin."""
    office = [make(i, username=f"staff{i}", ip="8.8.4.4", success=True) for i in range(25)]
    attacker_like = [make(30 + i * 2, username=f"user{i % 5}", ip="8.8.4.4") for i in range(10)]
    results = run(RuleEngine(), office + attacker_like)
    assert fired(results, "credential_stuffing") == []
    assert fired(run(RuleEngine(), attacker_like), "credential_stuffing") == [9]  # bỏ phần thành công đi thì báo


def test_credential_stuffing_also_works_per_asn_when_ips_rotate():
    botnet = [make(i, username=f"u{i % 25}", ip=f"10.1.0.{i % 8}", asn=64500) for i in range(40)]  # 8 IP cùng nhà mạng, mỗi IP chỉ 5 lần
    results = run(RuleEngine(), botnet)
    assert fired(results, "credential_stuffing") == [39]
    found = hit(results[39], "credential_stuffing")
    assert found.evidence["scope"] == "asn" and found.evidence["asn"] == 64500 and found.message.startswith("ASN 64500 thử 25 tài khoản")
    no_asn = [make(i, username=f"u{i % 25}", ip=f"10.1.0.{i % 8}") for i in range(40)]
    assert fired(run(RuleEngine(), no_asn), "credential_stuffing") == []  # không biết ASN thì không có phạm vi ASN


def test_credential_stuffing_halves_its_thresholds_when_user_agents_rotate():
    def burst(agents):
        return [make(i, username=f"u{i % 3}", ip="7.7.7.7", user_agent=agents[i % len(agents)]) for i in range(5)]

    rotating = run(RuleEngine(), burst(["UA-A", "UA-B", "UA-C", "UA-D"]))  # 5 lần sai, 3 tên, 4 UA khác nhau
    assert fired(rotating, "credential_stuffing") == [4]
    found = hit(rotating[4], "credential_stuffing")
    assert "nới do xoay User-Agent" in found.message and found.evidence["rotating_user_agent"] is True
    assert fired(run(RuleEngine(), burst(["UA-A"])), "credential_stuffing") == []  # cùng số lần sai nhưng một UA: chưa đủ ngưỡng gốc


# ------------------------------------------------------------------------------------------------ password_spray_slow


def test_slow_password_spray_is_caught_across_many_accounts():
    spray = [make(i * 1800, username=f"user{i}", ip="4.4.4.4") for i in range(20)]  # 20 tài khoản, mỗi 30 phút một lần, trải ~10 giờ
    results = run(RuleEngine(), spray)
    assert fired(results, "password_spray_slow") == [14, 15, 16, 17, 18, 19]  # từ tài khoản thứ 15
    found = hit(results[14], "password_spray_slow")
    assert found.techniques == ("T1110.003",) and found.evidence["distinct_users"] == 15 and found.evidence["fails_last_hour"] == 2
    assert "rải mật khẩu" in found.message
    assert fired(results, "credential_stuffing") == [] and fired(results, "brute_force") == []  # luật nhanh không bắt được: đúng là "chậm"


def test_password_spray_needs_many_accounts_few_tries_each_and_a_slow_rate():
    assert fired(run(RuleEngine(), [make(i * 1800, username=f"user{i}", ip="4.4.4.5") for i in range(14)]), "password_spray_slow") == []  # 14 tài khoản
    heavy = [make(k * 30, username=f"user{u}", ip="4.4.4.6") for k, (u, _) in enumerate((u, r) for u in range(15) for r in range(6))]  # dồn 6 lần vào từng tài khoản (quá 3 lần/tài khoản)
    assert fired(run(RuleEngine(), heavy), "password_spray_slow") == []
    fast = run(RuleEngine(), [make(i * 20, username=f"user{i}", ip="4.4.4.7") for i in range(130)])  # 3 lần/phút: sau ~2 giờ nhanh
    assert fired(fast, "password_spray_slow") and 129 not in fired(fast, "password_spray_slow")  # đủ nhanh (>120 lần/giờ) thì ngừng coi là "chậm"


def test_password_spray_also_works_per_asn():
    rotating = [make(i * 900, username=f"user{i}", ip=f"6.6.{i // 200}.{i % 200}", asn=64501) for i in range(60)]  # mỗi IP chỉ một tài khoản
    results = run(RuleEngine(), rotating)
    assert fired(results, "password_spray_slow")[0] == 39  # tài khoản thứ 40 của cùng ASN
    assert hit(results[39], "password_spray_slow").evidence["scope"] == "asn"


# ------------------------------------------------------------------------------------------------ distributed_bruteforce


def test_distributed_bruteforce_sees_one_account_attacked_from_many_ips():
    attempts = [make(i * 300, ip=f"3.3.3.{i % 5}") for i in range(8)]  # 8 lần sai vào alice, 5 IP, 35 phút
    results = run(RuleEngine(), attempts)
    assert fired(results, "distributed_bruteforce") == [7] and fired(results, "brute_force") == []
    found = hit(results[7], "distributed_bruteforce")
    assert found.evidence["distinct_ips"] == 5 and "8 lần sai từ 5 IP" in found.message and found.techniques == ("T1110.001", "T1090")


def test_distributed_bruteforce_needs_both_many_failures_and_many_ips():
    assert fired(run(RuleEngine(), [make(i * 300, ip=f"3.3.4.{i % 2}") for i in range(8)]), "distributed_bruteforce") == []  # 2 IP
    assert fired(run(RuleEngine(), [make(i * 300, ip=f"3.3.5.{i}") for i in range(4)]), "distributed_bruteforce") == []  # 4 lần sai
    assert fired(run(RuleEngine(), [make(i * 1300, ip=f"3.3.6.{i % 5}") for i in range(8)]), "distributed_bruteforce") == []  # trải quá 1 giờ: cửa sổ chỉ còn ~3 lần


# ------------------------------------------------------------------------------------------------ username_enumeration


def test_username_enumeration_counts_unknown_usernames_from_one_ip():
    results = run(RuleEngine(), [make(i * 30, username=f"ghost{i}", ip="2.2.2.2", exists=False) for i in range(8)])
    assert fired(results, "username_enumeration") == [7]
    found = hit(results[7], "username_enumeration")
    assert found.evidence["distinct_unknown_usernames"] == 8 and found.techniques == ("T1589",) and found.severity == "medium"


def test_username_enumeration_ignores_real_accounts_repeated_names_and_slow_probing():
    real = [make(i * 30, username=f"user{i}", ip="2.2.2.3") for i in range(12)]  # tài khoản có thật: đó là nhồi/rải, không phải dò danh sách
    assert fired(run(RuleEngine(), real), "username_enumeration") == []
    assert fired(run(RuleEngine(), [make(i, username="ghost", ip="2.2.2.4", exists=False) for i in range(20)]), "username_enumeration") == []  # một tên lặp lại
    assert fired(run(RuleEngine(), [make(i * 30, username=f"ghost{i}", ip="2.2.2.5", exists=False) for i in range(7)]), "username_enumeration") == []  # 7 tên
    assert fired(run(RuleEngine(), [make(i * 120, username=f"ghost{i}", ip="2.2.2.6", exists=False) for i in range(8)]), "username_enumeration") == []  # trải 14 phút
    ok = [make(i * 10, username=f"ghost{i}", ip="2.2.2.7", exists=False, success=True) for i in range(10)]
    assert fired(run(RuleEngine(), ok), "username_enumeration") == []  # chỉ tính lần thất bại


# ------------------------------------------------------------------------------------------------ success_after_failures


def test_success_after_a_failure_streak_is_flagged_even_from_other_ips():
    attempts = [make(i * 60, ip=f"5.5.5.{i % 3}") for i in range(5)] + [make(330, success=True, ip="5.5.5.9")]
    results = run(RuleEngine(), attempts)
    assert fired(results, "success_after_failures") == [5]
    found = hit(results[5], "success_after_failures")
    assert found.evidence["fails_before"] == 5 and "sau 5 lần sai" in found.message and found.severity == "high"


def test_success_after_failures_needs_enough_recent_failures_of_the_same_account():
    def after(fails, gap=60.0, username="alice"):
        return run(RuleEngine(), [make(i * gap) for i in range(fails)] + [make(fails * gap + 1, success=True, username=username)])

    assert fired(after(4), "success_after_failures") == []  # 4 lần: người dùng thật cũng gõ sai vài lần
    assert fired(after(5, gap=150.0), "success_after_failures") == []  # 5 lần nhưng trải 12 phút: quá cửa sổ 10 phút
    other = run(RuleEngine(), [make(i, username="bob") for i in range(6)] + [make(10, success=True, username="alice")])
    assert fired(other, "success_after_failures") == []  # sai vào bob, thành công vào alice
    unknown = run(RuleEngine(), [make(i, username="ghost", exists=False) for i in range(6)] + [make(10, success=True, username="ghost", exists=False)])
    assert fired(unknown, "success_after_failures") == [] and "success_after_failures" in unknown[-1].skipped  # tên bịa: bỏ qua vì thiếu tài khoản


# ------------------------------------------------------------------------------------------------ bot_user_agent, scripted_client


def test_bot_user_agent_follows_the_parsed_device_type():
    assert fired(run(RuleEngine(), [make(0, device_type="bot", user_agent="Googlebot/2.1")]), "bot_user_agent") == [0]
    for device in ("desktop", "mobile", "tablet", "unknown", None):
        assert fired(run(RuleEngine(), [make(0, device_type=device)]), "bot_user_agent") == [], device


@pytest.mark.parametrize(
    "agent, marker",
    [
        ("curl/8.4.0", "curl/"), ("Wget/1.21.4", "wget/"), ("python-requests/2.31.0", "python-requests"), ("python-httpx/0.27.0", "python-httpx"),
        ("Go-http-client/1.1", "go-http-client"), ("Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0", "headlesschrome"), ("Java/17.0.2", "java/"),
        ("Mozilla/5.0 (compatible; Hydra)", "hydra"), ("PostmanRuntime/7.36.0", "postmanruntime"),
    ],
)
def test_scripted_client_recognises_common_tools(agent, marker):
    results = run(RuleEngine(), [make(0, user_agent=agent)])
    assert fired(results, "scripted_client") == [0] and hit(results[0], "scripted_client").evidence["marker"] == marker


def test_scripted_client_ignores_real_browsers_and_android_apps():
    real = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "okhttp/4.12.0",  # thư viện của ứng dụng Android thật: cố ý không nằm trong danh sách
    ]
    assert all(fired(run(RuleEngine(), [make(0, user_agent=agent)]), "scripted_client") == [] for agent in real)


def test_scripted_client_does_not_treat_a_missing_user_agent_as_scripted_unless_configured():
    # Milestone B (B0.2), thay expectation cũ: UA trống là THIẾU telemetry, không phải bằng chứng client kịch bản.
    for empty in (None, "", "   "):
        assert fired(run(RuleEngine(), [make(0, user_agent=empty)]), "scripted_client") == []
    strict = RuleEngine(RuleConfig.from_dict({"rules": {"scripted_client": {"params": {"flag_empty_ua": True}}}}))  # hành vi cũ vẫn bật được qua cấu hình
    results = run(strict, [make(0, user_agent=None)])
    assert fired(results, "scripted_client") == [0] and hit(results[0], "scripted_client").evidence["marker"] == "(trống)"


def test_the_attack_simulation_scripts_are_recognised_by_their_default_user_agent():
    """attack-sim/*.py dùng httpx.Client() không đặt User-Agent: mặc định là 'python-httpx/<phiên bản>'."""
    agent = httpx.Client().headers["user-agent"]
    assert agent.startswith("python-httpx/")
    assert fired(run(RuleEngine(), [make(0, user_agent=agent)]), "scripted_client") == [0]


# ------------------------------------------------------------------------------------------------ ua_rotation, regular_rhythm


def test_user_agent_rotation_from_one_failing_ip():
    attempts = [make(i * 20, username=f"user{i}", ip="1.9.9.9", user_agent=f"Agent-{i % 5}") for i in range(8)]  # 8 lần sai, 5 UA
    results = run(RuleEngine(), attempts)
    assert fired(results, "ua_rotation") == [7]
    found = hit(results[7], "ua_rotation")
    assert found.evidence["distinct_user_agents"] == 5 and found.techniques == ("T1110.004",)


def test_user_agent_rotation_needs_many_agents_and_many_failures():
    assert fired(run(RuleEngine(), [make(i * 20, ip="1.9.9.8", user_agent="Same") for i in range(8)]), "ua_rotation") == []  # một UA
    assert fired(run(RuleEngine(), [make(i * 20, ip="1.9.9.7", user_agent=f"A{i}") for i in range(4)]), "ua_rotation") == []  # 4 lần sai
    hidden = run(RuleEngine(), [make(i * 20, ip="1.9.9.6") for i in range(8)])
    assert fired(hidden, "ua_rotation") == [] and "ua_rotation" in hidden[0].skipped  # không có UA thì bỏ qua


def test_regular_rhythm_flags_machine_like_timing_in_enforce_mode():
    """Milestone C+: shadow -> enforce SAU khi qua kiểm chứng hành vi (artifacts/behavior_verification/regular_rhythm.json) —
    thay đổi thiết kế có chủ ý; trước đó test này kiểm luật chỉ chạy shadow."""
    results = run(RuleEngine(), [make(i * 2.0, username=f"user{i}", ip="1.8.8.8") for i in range(12)])  # đúng 2 giây một lần
    assert fired(results, "regular_rhythm") == [9, 10, 11]  # từ khi đủ 10 mẫu
    found = hit(results[9], "regular_rhythm")
    assert found.mode == "enforce" and found.evidence["mean_interval_s"] == 2.0 and found.evidence["cv"] == 0.0
    assert any(h.rule_id == "regular_rhythm" for h in results[9].enforced)


def test_regular_rhythm_ignores_human_jitter_slow_cadence_and_short_histories():
    rng = random.Random(3)
    t, jittery = 0.0, []
    for i in range(20):
        t += rng.uniform(0.5, 20.0)
        jittery.append(make(t, username=f"user{i}", ip="1.8.8.9"))
    assert fired(run(RuleEngine(), jittery), "regular_rhythm") == []
    assert fired(run(RuleEngine(), [make(i * 60.0, username=f"user{i}", ip="1.8.8.10") for i in range(12)]), "regular_rhythm") == []  # đều nhưng chậm (60 giây)
    assert fired(run(RuleEngine(), [make(i * 2.0, username=f"user{i}", ip="1.8.8.11") for i in range(9)]), "regular_rhythm") == []  # mới 9 mẫu


# ------------------------------------------------------------------------------------------------ impossible_travel


def travel_pair(second_at, second_geo, first_success=True, second_success=True, first_geo=HANOI):
    first = make(0, success=first_success, latitude=first_geo[0] if first_geo else None, longitude=first_geo[1] if first_geo else None)
    second = make(second_at, success=second_success, latitude=second_geo[0] if second_geo else None, longitude=second_geo[1] if second_geo else None)
    return run(RuleEngine(), [first, second])


def test_impossible_travel_flags_a_jump_of_thousands_of_km_in_minutes():
    results = travel_pair(600, NEW_YORK)  # Hà Nội → New York trong 10 phút
    assert fired(results, "impossible_travel") == [1]
    found = hit(results[1], "impossible_travel")
    assert found.message.startswith("Cách ") and "km chỉ sau 10.0 phút" in found.message and found.message.endswith("ngưỡng 900).")
    assert found.evidence["previous_latitude"] == HANOI[0] and found.evidence["previous_longitude"] == HANOI[1] and found.evidence["speed_kmh"] > 900
    assert found.techniques == ("T1078",) and found.severity == "high"
    # Phase 3 (quyết định thiết kế có chủ ý, thay expectation cũ "so với lần thử trước bất kể kết quả"): chỉ tính
    # THÀNH CÔNG → THÀNH CÔNG — lần thử SAI không chứng minh chủ tài khoản đã ở nơi đó.
    assert fired(travel_pair(600, NEW_YORK, first_success=False, second_success=False), "impossible_travel") == []
    assert fired(travel_pair(600, NEW_YORK, first_success=True, second_success=False), "impossible_travel") == []  # thử SAI từ xa sau lần thành công
    assert fired(travel_pair(600, NEW_YORK, first_success=False, second_success=True), "impossible_travel") == []  # chưa có lần thành công trước đó để so


def test_impossible_travel_accepts_plausible_trips_and_missing_data():
    assert fired(travel_pair(600, (21.05, 105.83)), "impossible_travel") == []  # cách vài km
    assert fired(travel_pair(24 * 3600, NEW_YORK), "impossible_travel") == []  # ~13.000 km trong 24 giờ ≈ 540 km/h: máy bay dân dụng đi được
    assert fired(travel_pair(0, NEW_YORK), "impossible_travel") == []  # cùng thời điểm: không kết luận
    no_geo = travel_pair(600, None)
    assert fired(no_geo, "impossible_travel") == [] and "impossible_travel" in no_geo[1].skipped  # thiếu toạ độ: bỏ qua, không báo nhầm
    assert fired(travel_pair(600, NEW_YORK, first_geo=None), "impossible_travel") == []  # lần trước không có toạ độ
    first_only = travel_pair(600, NEW_YORK)[0]
    assert "impossible_travel" in first_only.skipped  # lần đầu: chưa có lịch sử


def test_impossible_travel_speed_limit_is_configurable():
    strict = RuleEngine(RuleConfig.from_dict({"rules": {"impossible_travel": {"params": {"max_speed_kmh": 5000.0}}}}))
    trip = [make(0, success=True, latitude=HANOI[0], longitude=HANOI[1]), make(3600, success=True, latitude=NEW_YORK[0], longitude=NEW_YORK[1])]  # ~13.000 km trong 1 giờ ≈ 13.000 km/h
    assert fired(run(strict, trip), "impossible_travel") == [1]
    loose = RuleEngine(RuleConfig.from_dict({"rules": {"impossible_travel": {"params": {"max_speed_kmh": 20_000.0}}}}))
    assert fired(run(loose, trip), "impossible_travel") == []
    with pytest.raises(Exception, match="lớn hơn mức tối đa"):
        RuleConfig.from_dict({"rules": {"impossible_travel": {"params": {"max_speed_kmh": 30_000.0}}}})  # cấu hình vô lý bị chặn ngay khi nạp


# ------------------------------------------------------------------------------------------------ multi_context_simultaneous, country_hop


def test_two_countries_within_minutes_is_flagged_on_the_second_login():
    results = run(RuleEngine(), [make(0, success=True, country="VN", ip="1.1.1.1"), make(300, success=True, country="US", ip="2.2.2.2")])
    assert fired(results, "multi_context_simultaneous") == [1]
    found = hit(results[1], "multi_context_simultaneous")
    assert found.evidence["countries"] == ["US", "VN"] and "2 quốc gia (US, VN)" in found.message and found.severity == "high"


def test_multi_context_needs_two_countries_inside_the_window_and_successful_logins():
    same = run(RuleEngine(), [make(0, success=True, country="VN", ip="1.1.1.1"), make(100, success=True, country="VN", ip="1.1.1.2")])
    assert fired(same, "multi_context_simultaneous") == []
    late = run(RuleEngine(), [make(0, success=True, country="VN"), make(700, success=True, country="US")])  # 11 phút: quá cửa sổ 10 phút
    assert fired(late, "multi_context_simultaneous") == []
    failed_abroad = run(RuleEngine(), [make(0, success=True, country="VN"), make(100, success=False, country="US")])
    assert fired(failed_abroad, "multi_context_simultaneous") == []  # lần ở nước ngoài thất bại: không phải phiên song song
    three = RuleEngine(RuleConfig.from_dict({"rules": {"multi_context_simultaneous": {"params": {"min_countries": 3}}}}))
    assert fired(run(three, [make(0, success=True, country="VN"), make(60, success=True, country="US")]), "multi_context_simultaneous") == []
    other_user = run(RuleEngine(), [make(0, success=True, country="VN"), make(60, success=True, country="US", username="bob")])
    assert fired(other_user, "multi_context_simultaneous") == []


def test_country_hop_counts_countries_touching_one_username_in_a_day():
    attempts = [make(0, country="VN"), make(3600, country="US"), make(7200, country="DE")]
    results = run(RuleEngine(), attempts)
    # Milestone B: enforce sau khi qua kiểm chứng (trước đó mặc định shadow)
    assert fired(results, "country_hop") == [2] and hit(results[2], "country_hop").mode == "enforce"
    assert fired(run(RuleEngine(), attempts[:2]), "country_hop") == []  # mới 2 nước
    slow = [make(0, country="VN"), make(3600, country="US"), make(25 * 3600, country="DE")]  # nước thứ ba sau 25 giờ: nước đầu đã ra khỏi cửa sổ
    assert fired(run(RuleEngine(), slow), "country_hop") == []
    assert fired(run(RuleEngine(), [make(i * 60, country="VN") for i in range(10)]), "country_hop") == []


def test_country_hop_ignores_successful_logins_by_default():
    # Milestone B: khách du lịch đăng nhập ĐÚNG ở 3 nước trong một ngày không phải "bị thử từ nhiều nước".
    travel = [make(0, success=True, country="VN"), make(7 * 3600, success=True, country="JP"), make(20 * 3600, success=True, country="FR")]
    assert fired(run(RuleEngine(), travel), "country_hop") == []
    mixed = [make(0, success=True, country="VN"), make(3600, country="US"), make(7200, country="DE")]  # chỉ 2 nước có lần SAI
    assert fired(run(RuleEngine(), mixed), "country_hop") == []
    legacy = RuleEngine(RuleConfig.from_dict({"rules": {"country_hop": {"params": {"failures_only": False}}}}))
    assert fired(run(legacy, mixed), "country_hop") == [2]  # hành vi cũ (mọi lần thử) vẫn bật được qua cấu hình


# ------------------------------------------------------------------------------------------------ dormant_account_login


DAY = 86_400


def dormant_run(idle_days, config=None, second=None, **first_kw):
    first = make(0, success=True, country="VN", user_agent="Browser-1", **first_kw)
    second = second or make(idle_days * DAY, success=True, country="US", user_agent="Browser-1")
    return run(RuleEngine(config), [first, second])


def test_a_dormant_account_returning_from_a_new_country_is_flagged():
    results = dormant_run(100)
    assert fired(results, "dormant_account_login") == [1]
    found = hit(results[1], "dormant_account_login")
    assert found.evidence["idle_days"] == 100.0 and found.evidence["new_country"] is True and found.evidence["new_device"] is False
    assert "ngủ đông 100 ngày" in found.message and "quốc gia mới US" in found.message and found.severity == "medium"


def test_dormancy_alone_is_not_enough_by_default_but_can_be_required_alone():
    familiar = make(100 * DAY, success=True, country="VN", user_agent="Browser-1")  # cùng nước, cùng thiết bị
    assert fired(dormant_run(100, second=familiar), "dormant_account_login") == []
    alone = RuleConfig.from_dict({"rules": {"dormant_account_login": {"params": {"require_change": False}}}})
    assert fired(dormant_run(100, config=alone, second=familiar), "dormant_account_login") == [1]
    new_device = make(100 * DAY, success=True, country="VN", user_agent="Browser-2")
    assert fired(dormant_run(100, second=new_device), "dormant_account_login") == [1]  # thiết bị mới cũng đủ


def test_recent_accounts_failures_and_first_logins_are_not_dormant():
    assert fired(dormant_run(30), "dormant_account_login") == []  # mới 30 ngày
    failed = make(100 * DAY, success=False, country="US", user_agent="Browser-1")
    assert fired(dormant_run(100, second=failed), "dormant_account_login") == []  # thất bại: chưa vào được
    first_ever = run(RuleEngine(), [make(0, success=True, country="US")])
    assert fired(first_ever, "dormant_account_login") == [] and "dormant_account_login" in first_ever[0].skipped
    only_failures = run(RuleEngine(), [make(0, success=False), make(200 * DAY, success=True, country="US")])
    assert fired(only_failures, "dormant_account_login") == []  # chưa từng có lần THÀNH CÔNG nào để "ngủ đông"


# ------------------------------------------------------------------------------------------------ rare_network_login


def engine_with_stats(total, per_asn, config=None):
    stats = MemoryGlobalStats()
    for asn, count in per_asn.items():
        for i in range(count):
            stats.update(make(0, success=True, username=f"seed{i}", asn=asn))
    assert stats.total_successes == total
    return RuleEngine(config, stats=stats)


def test_login_from_a_network_nobody_else_uses_is_flagged_in_shadow_mode():
    engine = engine_with_stats(30_000, {100: 29_990, 200: 10})
    never_seen = engine.evaluate(make(1, success=True, asn=300))
    assert fired([never_seen], "rare_network_login") == [0]
    found = hit(never_seen, "rare_network_login")
    assert found.mode == "shadow" and found.evidence["never_seen"] is True and found.evidence["asn_successes"] == 0 and "AS300" in found.message
    assert fired([engine.evaluate(make(2, success=True, asn=200))], "rare_network_login") == []  # 10/30.000 = 0,033% > ngưỡng 0,002%
    assert fired([engine.evaluate(make(3, success=True, asn=100))], "rare_network_login") == []


def test_rare_network_needs_enough_global_data_a_success_and_an_asn():
    small = engine_with_stats(5_000, {100: 5_000})  # dưới min_total: ASN nào cũng "hiếm" nên luật chưa có hiệu lực
    assert fired([small.evaluate(make(1, success=True, asn=999))], "rare_network_login") == []
    engine = engine_with_stats(30_000, {100: 30_000})
    assert fired([engine.evaluate(make(1, success=False, asn=999))], "rare_network_login") == []  # thất bại: chưa vào được tài khoản
    no_asn = engine.evaluate(make(2, success=True))
    assert fired([no_asn], "rare_network_login") == [] and "rare_network_login" in no_asn.skipped
    unknown_user = engine.evaluate(make(3, success=True, asn=999, exists=False))
    assert fired([unknown_user], "rare_network_login") == []


def test_rare_network_threshold_is_configurable():
    loose = RuleConfig.from_dict({"rules": {"rare_network_login": {"params": {"max_share": 0.001}}}})
    engine = engine_with_stats(30_000, {100: 29_990, 200: 10}, config=loose)
    assert fired([engine.evaluate(make(1, success=True, asn=200))], "rare_network_login") == [0]  # 0,033% ≤ 0,1%


# ------------------------------------------------------------------------------------------------ tor / datacenter / vpn / blocklist


def intel():
    return ThreatIntel(
        tor=frozenset({"185.220.101.1"}), datacenter=CidrSet(["34.64.0.0/10"]), vpn=CidrSet(["185.159.156.0/22"]),
        loaded={"tor": True, "datacenter": True, "vpn": True},
    )


def test_tor_exit_node_is_flagged_whatever_the_outcome():
    engine = RuleEngine(intel=intel())
    failed, ok = engine.evaluate(make(0, ip="185.220.101.1")), engine.evaluate(make(1, ip="185.220.101.1", success=True))
    assert fired([failed, ok], "tor_exit") == [0, 1]
    assert "thất bại" in hit(failed, "tor_exit").message and "thành công" in hit(ok, "tor_exit").message
    found = hit(ok, "tor_exit")
    assert found.techniques == ("T1090.003",) and found.mode == "enforce" and found.severity == "medium"
    assert fired([engine.evaluate(make(2, ip="185.220.101.2"))], "tor_exit") == []


def test_datacenter_and_vpn_ranges_are_flagged_in_shadow_mode():
    engine = RuleEngine(intel=intel())
    cloud = engine.evaluate(make(0, ip="34.100.1.1", success=True))
    assert fired([cloud], "datacenter_ip") == [0] and hit(cloud, "datacenter_ip").mode == "shadow" and hit(cloud, "datacenter_ip").techniques == ("T1090.002",)
    vpn = engine.evaluate(make(1, ip="185.159.157.200"))
    assert fired([vpn], "vpn_ip") == [0] and hit(vpn, "vpn_ip").mode == "shadow"
    home = engine.evaluate(make(2, ip="113.160.1.1", success=True))
    assert fired([home], "datacenter_ip") == [] and fired([home], "vpn_ip") == [] and fired([home], "tor_exit") == []


def test_reputation_rules_are_skipped_without_their_lists():
    result = RuleEngine().evaluate(make(0, ip="185.220.101.1"))  # engine mặc định: chưa nạp danh sách nào
    assert fired([result], "tor_exit") == [] and "Tor" in result.skipped["tor_exit"] and "datacenter" in result.skipped["datacenter_ip"] and "VPN" in result.skipped["vpn_ip"]
    only_tor = RuleEngine(intel=ThreatIntel(tor=frozenset({"1.1.1.1"}), loaded={"tor": True, "datacenter": False, "vpn": False})).evaluate(make(0, ip="1.1.1.1"))
    assert fired([only_tor], "tor_exit") == [0] and "tor_exit" not in only_tor.skipped and "datacenter_ip" in only_tor.skipped


def test_blocklist_hit_covers_ip_network_asn_and_username_and_respects_expiry():
    engine = RuleEngine()
    engine.blocklist.add("ip", "6.6.6.6", "IP đã dò mật khẩu")
    engine.blocklist.add("cidr", "7.7.0.0/16", "dải proxy")
    engine.blocklist.add("asn", "AS64666", "nhà mạng chỉ chứa botnet")
    engine.blocklist.add("username", "admin", "tài khoản bị nhắm")
    engine.blocklist.add("ip", "8.8.8.8", "chặn tạm", ttl=3600, now=T0)
    kinds = {}
    for name, attempt_ in {
        "ip": make(0, ip="6.6.6.6"), "cidr": make(1, ip="7.7.200.1"), "asn": make(2, ip="9.9.9.9", asn=64666), "username": make(3, ip="9.9.9.10", username="Admin"),
        "temp": make(4, ip="8.8.8.8"), "clean": make(5, ip="9.9.9.11"), "expired": make(3700, ip="8.8.8.8"),
    }.items():
        result = engine.evaluate(attempt_)
        kinds[name] = hit(result, "blocklist_hit").evidence["kind"] if fired([result], "blocklist_hit") else None
    assert kinds == {"ip": "ip", "cidr": "cidr", "asn": "asn", "username": "username", "temp": "ip", "clean": None, "expired": None}
    blocked = engine.evaluate(make(10, ip="6.6.6.6"))
    found = hit(blocked, "blocklist_hit")
    assert found.severity == "high" and found.mode == "enforce" and found.techniques == () and "IP đã dò mật khẩu" in found.message


def test_user_agent_rotation_counts_canonical_families_not_version_strings():
    # Milestone B: Chrome tự cập nhật phiên bản không phải "đổi User-Agent".
    from app.utils.device import parse_user_agent

    def chrome(v):
        ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36"
        p = parse_user_agent(ua)
        return dict(user_agent=ua, browser=p.browser, os=p.os, device_type=p.device_type)

    versions = [make(i * 20, username=f"u{i % 2}", ip="1.9.9.5", **chrome(118 + i)) for i in range(10)]  # 10 lần sai, 10 chuỗi UA, MỘT họ
    assert fired(run(RuleEngine(), versions), "ua_rotation") == []
    raw = RuleEngine(RuleConfig.from_dict({"rules": {"ua_rotation": {"params": {"canonical_agents": False}}}}))
    assert fired(run(raw, versions), "ua_rotation") != []  # đếm chuỗi thô (hành vi trước Milestone B) thì khớp


def test_user_agent_rotation_ignores_shared_ip_dominated_by_successful_logins():
    # NAT dùng chung: 9 người, trình duyệt khác nhau, mỗi người gõ sai 1 lần rồi đăng nhập đúng.
    attempts = []
    for i in range(9):
        attempts += [make(i * 30, username=f"nv{i}", ip="1.9.9.4", user_agent=f"Agent-{i}"), make(i * 30 + 5, success=True, username=f"nv{i}", ip="1.9.9.4", user_agent=f"Agent-{i}")]
    assert fired(run(RuleEngine(), attempts), "ua_rotation") == []
