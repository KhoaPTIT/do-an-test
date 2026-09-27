"""MR9 — bộ replay: số đo theo luật và theo nhãn, luật bị bỏ qua/lỗi, thứ tự thời gian, giới hạn, báo cáo, bộ chuyển đổi bảng login_events."""

import json
from datetime import datetime, timedelta, timezone

from app.detection.engine import LoginAttempt, RuleConfig, RuleEngine
from app.detection.engine.registry import RuleSpec, rule
from app.detection.engine.replay import _canonical_command, attempt_from_event, db_attempts, replay, to_markdown
from app.models import LoginEvent, User

T0 = 1_700_000_000.0
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
ATTACK = {"is_attack_ip": True, "is_ato": False}
ATO = {"is_attack_ip": False, "is_ato": True}
CLEAN = {"is_attack_ip": False, "is_ato": False}


def make(t, username="alice", success=False, ip="10.0.0.1", labels=None, **kw):
    kw.setdefault("user_agent", UA)
    return LoginAttempt(ts=T0 + t, username=username, success=success, ip=ip, user_key=f"k-{username}", labels=labels or {}, **kw)


def scenario(attack_labels=ATTACK):
    """Kẻ nhồi thông tin (12 tên khác nhau trong 22 giây), người dùng hợp lệ, một người gõ nhầm và một vụ chiếm tài khoản."""
    events = [make(i * 2, username=f"victim{i}", ip="6.6.6.6", labels=attack_labels) for i in range(12)]
    events += [make(100 + i * 60, username="alice", success=True, ip="10.0.0.5", labels=CLEAN) for i in range(4)]
    events += [make(400, username="bob", ip="10.0.0.6", labels=CLEAN), make(410, username="bob", success=True, ip="10.0.0.6", labels=CLEAN)]
    events.append(make(500, username="carol", success=True, ip="7.7.7.7", labels=ATO))
    return events  # 19 lần thử, 6 thành công; 12 mang nhãn tấn công, 1 mang nhãn ATO, 6 không nhãn (5 thành công)


# ------------------------------------------------------------------------------------------------ số đo theo luật và nhãn


def test_tallies_split_the_hits_of_each_rule_by_label():
    report = replay(scenario())
    assert (report.events, report.successes) == (19, 6)
    assert dict(report.labels) == {"is_attack_ip": 12, "is_ato": 1} and report.label_ips == {"is_attack_ip": 1, "is_ato": 1}
    assert (report.unlabelled, report.unlabelled_success) == (6, 5)

    stuffing = report.rules["credential_stuffing"]  # lần sai thứ 10, 11, 12 của cùng một IP với 10+ tên khác nhau
    assert stuffing.tally.hits == 3 and dict(stuffing.tally.by_label) == {"is_attack_ip": 3} and stuffing.tally.unlabelled == 0
    assert {name: len(ips) for name, ips in stuffing.tally.ips_by_label.items()} == {"is_attack_ip": 1}
    assert stuffing.tally.success_hits == 0 and report.per_10k(stuffing.tally.unlabelled) == 0.0
    assert dict(stuffing.tally.by_scope) == {"ip": 3} and dict(stuffing.tally.unlabelled_by_scope) == {} and stuffing.tally.unlabelled_ips == set()

    rhythm = report.rules["regular_rhythm"]  # cách đều 2 giây: khớp ở chế độ shadow
    assert rhythm.mode == "shadow" and rhythm.tally.hits == 3
    assert report.any_enforced.hits == 3 and report.any_rule.hits == 3 and report.any_enforced.unlabelled == 0


def test_hits_on_unlabelled_rows_are_counted_as_false_alerts_and_normalised_per_10k_legit_logins():
    typo_storm = [make(600 + i, username="dave", ip="10.9.9.9", labels=CLEAN) for i in range(5)]  # 5 lần sai liền của một người hợp lệ
    report = replay(scenario() + typo_storm)
    brute = report.rules["brute_force"]
    assert brute.tally.hits == 1 and brute.tally.unlabelled == 1 and brute.tally.unlabelled_success == 0 and brute.tally.success_hits == 0
    assert report.unlabelled_success == 5 and report.per_10k(brute.tally.unlabelled) == 1 / 5 * 10_000
    sample = brute.tally.samples["unlabelled"][0]
    assert sample["username"] == "dave" and sample["ip"] == "10.9.9.9" and sample["success"] is False and "Dò mật khẩu 'dave'" in sample["message"]
    assert brute.tally.samples["labelled"] == []
    assert brute.tally.unlabelled_ips == {"10.9.9.9"} and dict(brute.tally.by_scope) == {}  # `brute_force` không có phạm vi; số nguồn báo nhầm = 1 IP
    assert report.any_enforced.unlabelled_ips == {"10.9.9.9"}


def test_replaying_with_different_labels_gives_identical_hits_because_the_engine_never_sees_them():
    attack, clean = replay(scenario(ATTACK)), replay(scenario(CLEAN))
    assert {rid: r.tally.hits for rid, r in attack.rules.items()} == {rid: r.tally.hits for rid, r in clean.rules.items()}
    assert attack.any_enforced.hits == clean.any_enforced.hits == 3
    assert attack.rules["credential_stuffing"].tally.unlabelled == 0 and clean.rules["credential_stuffing"].tally.unlabelled == 3  # chỉ cách CHIA khác nhau


def test_examples_come_from_different_ips_not_from_one_burst():
    events = [make(i * 2, username=f"v{i}", ip=f"6.6.6.{i % 3}", labels=ATTACK) for i in range(60)]
    report = replay(events, RuleEngine(RuleConfig.from_dict({"rules": {"credential_stuffing": {"params": {"min_fails": 3, "min_users": 3}}}})))
    ips = [s["ip"] for s in report.rules["credential_stuffing"].tally.samples["labelled"]]
    assert 1 < len(ips) <= 3 and len(set(ips)) == len(ips)


# ------------------------------------------------------------------------------------------------ bỏ qua, lỗi, chế độ


def test_evaluated_and_skipped_counts_explain_which_rules_could_run():
    report = replay(scenario())
    n = report.events
    travel = report.rules["impossible_travel"]
    assert travel.evaluated == 0 and travel.skipped == n and any("toạ độ" in reason for reason in travel.skip_reasons)
    tor = report.rules["tor_exit"]
    assert tor.evaluated == 0 and any("Tor" in reason for reason in tor.skip_reasons)  # chưa nạp danh sách
    brute = report.rules["brute_force"]
    assert (brute.evaluated, brute.skipped, brute.errors) == (n, 0, 0)


def test_shadow_rules_count_in_any_rule_but_not_in_any_enforced_and_off_rules_are_listed():
    config = RuleConfig.from_dict({"rules": {"scripted_client": {"mode": "shadow"}, "bot_user_agent": {"mode": "off"}}})
    report = replay([make(0, user_agent="curl/8.4.0", device_type="bot")], RuleEngine(config))
    assert report.any_rule.hits == 1 and report.any_enforced.hits == 0
    assert "bot_user_agent" not in report.rules and report.off_rules == ["bot_user_agent"] and report.rules["scripted_client"].mode == "shadow"
    assert report.config == config.to_dict()


def test_a_failing_rule_is_counted_and_shown_in_the_report():
    registry: dict[str, RuleSpec] = {}
    rule(id="hong", title="hỏng", category="Tự động hoá", severity="low", description="luôn lỗi", registry=registry)(lambda ctx: 1 / 0)
    report = replay([make(0), make(1)], RuleEngine(registry=registry))
    broken = report.rules["hong"]
    assert broken.errors == 2 and broken.evaluated == 0 and "ZeroDivisionError" in broken.first_error
    text = to_markdown(report, title="T")
    assert "## 4. Luật bị bỏ qua hoặc lỗi" in text and "| `hong` | 0 | — | ZeroDivisionError: division by zero (2 lần) |" in text


# ------------------------------------------------------------------------------------------------ thứ tự, giới hạn, tiến độ, bộ nhớ


def test_events_that_go_back_in_time_are_counted():
    report = replay([make(0), make(10), make(5), make(20)])
    assert report.events == 4 and report.out_of_order == 1
    assert replay([make(0), make(1), make(1), make(2)]).out_of_order == 0  # trùng mốc không phải đi ngược


def test_limit_stops_early_and_progress_is_reported_periodically():
    calls = []
    report = replay((make(i) for i in range(50)), limit=10, progress=lambda done, ts, elapsed: calls.append((done, ts)), progress_every=4)
    assert report.events == 10 and [done for done, _ in calls] == [4, 8] and calls[0][1] == T0 + 3
    assert report.first_ts == T0 and report.last_ts == T0 + 9 and abs(report.days - 9 / 86_400) < 1e-9


def test_report_records_memory_and_speed_diagnostics():
    report = replay(scenario())
    assert report.memory["accounts_in_history"] == 12 + 3  # 12 nạn nhân + alice, bob, carol
    assert report.memory["window_keys_at_end"] > 0 and report.events_per_second > 0 and report.latency.percentile(0.5) > 0
    assert set(report.latency.to_dict()) == {"mean_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms"}


# ------------------------------------------------------------------------------------------------ báo cáo


def test_report_serialises_to_json_and_renders_markdown(tmp_path):
    report = replay(scenario())
    data = report.to_dict()
    json.dumps(data, ensure_ascii=False)
    assert data["events"] == 19 and data["rules"]["credential_stuffing"]["by_label"] == {"is_attack_ip": 3} and data["label_ips"]["is_attack_ip"] == 1
    assert data["rules"]["credential_stuffing"]["ips_by_label"] == {"is_attack_ip": 1} and data["any_enforced"]["hits"] == 3

    text = to_markdown(report, title="Báo cáo thử", caveats={"credential_stuffing": "lưu ý riêng X"}, notes=["ghi chú chung Y"], regenerate="python -m demo")
    for expected in (
        "# Báo cáo thử", "`python -m demo`", "## 1. Dữ liệu và cách chạy", "## 2. Số lần khớp và báo nhầm", "## 3. Phát hiện theo nhãn", "`is_attack_ip`: IP",
        "## 5. Lưu ý riêng của nguồn dữ liệu", "lưu ý riêng X", "ghi chú chung Y", "| `credential_stuffing` | enforce | 19 | 0 | 3 |", "bất kỳ luật `enforce` nào",
        "## 6. Ví dụ", "Luật có nhiều phạm vi", "| `credential_stuffing` | ip | 3 | 0 | 0.0% |", "IP không nhãn bị khớp",
    ):
        assert expected in text, expected
    assert "## 3." not in to_markdown(replay([make(0)]), title="T") and "## 5." not in to_markdown(replay([make(0)]), title="T")  # không nhãn / không lưu ý: bỏ mục

    out = tmp_path / "deep" / "dir" / "report.json"
    report.save_json(out)
    assert json.loads(out.read_text(encoding="utf-8"))["events"] == 19


# ------------------------------------------------------------------------------------------------ bảng login_events


def _event(user_id, name, second, base, success=False, ip="1.2.3.4", synthetic=False, **kw):
    return LoginEvent(user_id=user_id, attempted_username=name, success=success, ip_address=ip, user_agent=kw.pop("user_agent", UA), created_at=base + timedelta(seconds=second), is_synthetic=synthetic, **kw)


def test_db_adapter_replays_login_events_in_time_order_with_the_synthetic_flag_as_label(db_session):
    user = User(username="alice", password_hash="x")
    db_session.add(user)
    db_session.commit()
    base = datetime(2026, 9, 27, 10, 0, 0)  # SQLite trả về mốc thời gian không múi giờ; adapter coi là UTC như hệ thống ghi
    geo = {"country": "VN", "city": "Hanoi", "latitude": 21.03, "longitude": 105.85}
    events = [_event(user.id, "alice", 10 * i, base, synthetic=i % 2 == 0, **geo) for i in (4, 0, 2, 1, 3)]  # chèn lộn xộn
    events.append(_event(None, "ghost", 100, base, ip="5.6.7.8", user_agent=None))
    db_session.add_all(events)
    db_session.commit()

    attempts = list(db_attempts(db_session))
    assert [a.ts for a in attempts] == [base.replace(tzinfo=timezone.utc).timestamp() + s for s in (0, 10, 20, 30, 40, 100)]
    first, ghost = attempts[0], attempts[-1]
    assert (first.username, first.user_key, first.user_exists, first.country, first.has_geo, first.asn) == ("alice", str(user.id), True, "VN", True, None)
    assert dict(first.labels) == {"is_synthetic": True} and dict(attempts[1].labels) == {"is_synthetic": False}
    assert (ghost.username, ghost.user_key, ghost.user_agent, ghost.device_type, ghost.has_geo) == ("ghost", None, None, "unknown", False)

    report = replay(db_attempts(db_session), source="db")
    assert report.events == 6 and report.out_of_order == 0 and report.labels["is_synthetic"] == 3
    assert report.rules["brute_force"].tally.hits == 1  # lần sai thứ 5 của alice trong 40 giây
    assert len(list(db_attempts(db_session, start=base + timedelta(seconds=25)))) == 3  # đầu mốc gồm cả
    assert len(list(db_attempts(db_session, end=base + timedelta(seconds=20)))) == 2  # cuối mốc không gồm


def test_attempt_from_event_treats_naive_timestamps_as_utc_and_keeps_aware_ones():
    naive = _event(3, "bob", 0, datetime(2026, 1, 2, 3, 4, 5))
    aware = _event(3, "bob", 0, datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=7))))
    assert attempt_from_event(naive).ts == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc).timestamp()
    assert attempt_from_event(aware).ts == datetime(2026, 1, 1, 20, 4, 5, tzinfo=timezone.utc).timestamp()


def test_the_regenerate_command_keeps_data_and_rule_options_but_not_output_paths():
    argv = ["rba", "--start", "2020-02-03", "--end", "2020-08-01", "--out", "C:/tmp/a.md", "--json=b.json", "--progress", "0", "--config", "rules.json"]
    assert _canonical_command(argv) == "python -m app.detection.engine.replay rba --start 2020-02-03 --end 2020-08-01 --config rules.json --out <tệp.md>"
