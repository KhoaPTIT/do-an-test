"""MR9 — bộ chuyển đổi RBA cho replay rule engine: đọc đúng cột, sắp thứ tự, xử lý tên không tồn tại, lọc khoảng thời gian, dòng lệnh."""

import json
from datetime import datetime, timezone

import pandas as pd
import pytest

from app.detection.engine import replay as replay_module
from app.detection.engine.replay import replay
from ml.rba import rule_replay
from ml.rba.etl import FULL_PARQUET
from ml.rba.features import RBA_CATCHALL_USER_ID

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
COLUMNS = ["row_id", "ts", "user_id", "ip", "country", "asn", "ua", "browser", "os", "device_type", "success", "is_attack_ip", "is_ato"]


def row(row_id, ts, user_id=7, ip="1.1.1.1", country="NO", asn=29695, ua=UA, browser="Chrome 120", os="Linux", device="desktop", success=True, attack=False, ato=False):
    return (row_id, ts, user_id, ip, country, asn, ua, browser, os, device, success, attack, ato)


def write(tmp_path, rows):
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["ts"] = pd.to_datetime(df["ts"]).astype("datetime64[us]")
    df["asn"] = df["asn"].astype("Int32")
    path = tmp_path / "rba_tiny.parquet"
    df.to_parquet(path, index=False)
    return path


def utc(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


@pytest.fixture()
def tiny(tmp_path):
    rows = [  # cố ý xếp lộn thứ tự: adapter phải sắp theo (thời gian, row_id)
        row(2, "2020-03-01 12:00:02.500"),
        row(0, "2020-03-01 12:00:00.000"),
        row(1, "2020-03-01 12:00:01.250", user_id=RBA_CATCHALL_USER_ID, ip="6.6.6.6", country="US", asn=None, ua=None, browser=None, os=None, device=None, success=False, attack=True),
        row(4, "2020-03-01 12:00:05.000", user_id=8, ip="7.7.7.7", success=True, ato=True),
        row(3, "2020-03-01 12:00:05.000", user_id=9, ip="8.8.8.8", success=False),  # trùng thời gian với row 4: xếp theo row_id
    ]
    return write(tmp_path, rows)


def test_rows_come_back_in_time_order_with_exact_timestamps_and_types(tiny):
    attempts = list(rule_replay.rba_attempts(tiny, sort=True))
    assert [a.username for a in attempts] == ["7", "?1", "7", "9", "8"]  # 0, 1, 2, 3, 4
    assert [a.ts for a in attempts][:3] == [utc("2020-03-01 12:00:00"), utc("2020-03-01 12:00:01.250"), utc("2020-03-01 12:00:02.500")]
    first = attempts[0]
    assert (first.user_key, first.asn, first.country, first.browser, first.os, first.device_type, first.success, first.ip) == ("7", 29695, "NO", "Chrome 120", "Linux", "desktop", True, "1.1.1.1")
    assert first.user_agent == UA and isinstance(first.asn, int) and not first.has_geo  # RBA không có toạ độ


def test_the_catch_all_user_becomes_an_unknown_account_with_a_unique_name_per_attempt(tiny):
    ghost = list(rule_replay.rba_attempts(tiny, sort=True))[1]
    assert ghost.user_key is None and not ghost.user_exists and ghost.username == "?1"  # tên riêng theo row_id: không gộp mọi tên không tồn tại làm một
    assert ghost.asn is None and ghost.device_type is None and ghost.user_agent is None and ghost.success is False


def test_labels_are_attached_but_only_in_the_labels_field(tiny):
    attempts = list(rule_replay.rba_attempts(tiny, sort=True))
    assert [dict(a.labels) for a in attempts] == [
        {"is_attack_ip": False, "is_ato": False}, {"is_attack_ip": True, "is_ato": False}, {"is_attack_ip": False, "is_ato": False},
        {"is_attack_ip": False, "is_ato": False}, {"is_attack_ip": False, "is_ato": True},
    ]
    assert not any(hasattr(a, name) for a in attempts for name in ("is_attack_ip", "is_ato"))  # không lộ ra ngoài `labels`


def test_time_range_is_half_open_and_limit_applies_after_sorting(tiny):
    assert [a.username for a in rule_replay.rba_attempts(tiny, sort=True, start="2020-03-01 12:00:01")] == ["?1", "7", "9", "8"]
    assert [a.username for a in rule_replay.rba_attempts(tiny, sort=True, end="2020-03-01 12:00:02.500")] == ["7", "?1"]  # mốc cuối không gồm
    assert [a.username for a in rule_replay.rba_attempts(tiny, sort=True, start="2020-03-01", end="2020-03-02", limit=2)] == ["7", "?1"]
    assert list(rule_replay.rba_attempts(tiny, sort=True, start="2021-01-01")) == []


def test_batches_smaller_than_the_result_give_the_same_stream(tiny):
    assert [a.ts for a in rule_replay.rba_attempts(tiny, batch_rows=2, sort=True)] == [a.ts for a in rule_replay.rba_attempts(tiny, sort=True)]


def test_without_sort_the_file_order_is_trusted_and_the_replay_reports_a_disordered_file(tiny):
    attempts = list(rule_replay.rba_attempts(tiny))  # thứ tự vật lý: row 2, 0, 1, 4, 3
    assert [a.username for a in attempts] == ["7", "7", "?1", "8", "9"]
    assert replay(rule_replay.rba_attempts(tiny), source="tiny").out_of_order == 2 and replay(rule_replay.rba_attempts(tiny, sort=True)).out_of_order == 0


def test_missing_parquet_gives_a_helpful_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="ml.rba.etl"):
        list(rule_replay.rba_attempts(tmp_path / "khong_co.parquet"))


def test_an_enumerating_attack_ip_is_caught_because_unknown_names_are_kept_distinct(tmp_path):
    """RBA gộp mọi tên không tồn tại vào một user_id; nếu adapter giữ nguyên thì `username_enumeration` không bao giờ thấy 8 tên khác nhau."""
    rows = [row(i, f"2020-03-01 12:00:{i:02d}", user_id=RBA_CATCHALL_USER_ID, ip="6.6.6.6", success=False, attack=True) for i in range(10)]
    rows += [row(100 + i, f"2020-03-01 12:01:{i:02d}", user_id=5, ip="10.0.0.2", success=i == 3) for i in range(4)]  # người dùng thật, một lần gõ nhầm
    report = replay(rule_replay.rba_attempts(write(tmp_path, rows)), source="tiny")
    enumeration = report.rules["username_enumeration"]
    assert enumeration.tally.hits == 3 and dict(enumeration.tally.by_label) == {"is_attack_ip": 3} and enumeration.tally.unlabelled == 0  # lần thứ 8, 9, 10
    assert report.rules["brute_force"].tally.hits == 0  # tên riêng từng lần: không chạm ngưỡng theo tên
    assert report.labels["is_attack_ip"] == 10 and report.label_ips["is_attack_ip"] == 1 and report.out_of_order == 0


def test_unknown_names_can_share_one_name_per_ip_as_the_opposite_bound(tmp_path):
    rows = [row(i, f"2020-03-01 12:00:{i:02d}", user_id=RBA_CATCHALL_USER_ID, ip="6.6.6.6", success=False, attack=True) for i in range(10)]
    rows += [row(20 + i, f"2020-03-01 12:00:{20 + i:02d}", user_id=RBA_CATCHALL_USER_ID, ip="7.7.7.7", success=False) for i in range(3)]
    path = write(tmp_path, rows)
    per_ip = list(rule_replay.rba_attempts(path, unknown_names="ip"))
    assert {a.username for a in per_ip} == {"?6.6.6.6", "?7.7.7.7"} and all(a.user_key is None for a in per_ip)
    assert len({a.username for a in rule_replay.rba_attempts(path)}) == 13  # mặc định: mỗi lần một tên

    shared = replay(iter(per_ip), source="tiny")
    assert shared.rules["username_enumeration"].tally.hits == 0  # chỉ một tên giả mỗi IP: không thể "dò nhiều tên"
    assert shared.rules["brute_force"].tally.hits == 6  # nhưng 10 lần sai cùng một tên giả trong 10 giây: lần thứ 5..10
    per_attempt = replay(rule_replay.rba_attempts(path), source="tiny")
    assert per_attempt.rules["username_enumeration"].tally.hits == 3 and per_attempt.rules["brute_force"].tally.hits == 0


def test_an_unknown_naming_mode_is_rejected():
    with pytest.raises(ValueError, match="unknown_names"):
        list(rule_replay.rba_attempts(unknown_names="khac"))


def test_caveats_and_notes_follow_the_naming_mode():
    attempt, per_ip = rule_replay.rba_caveats("attempt"), rule_replay.rba_caveats("ip")
    assert set(attempt) == set(per_ip) and attempt["username_enumeration"] != per_ip["username_enumeration"] and "THỔI PHỒNG" in attempt["credential_stuffing"]
    assert "cận TRÊN" in rule_replay.rba_notes("attempt")[1] and "cận DƯỚI" in rule_replay.rba_notes("ip")[1]
    assert rule_replay.RBA_CAVEATS == attempt and rule_replay.RBA_NOTES == rule_replay.rba_notes("attempt")


def test_the_command_line_writes_markdown_and_json_with_the_dataset_caveats(tiny, tmp_path, capsys):
    out, data = tmp_path / "reports" / "r.md", tmp_path / "reports" / "r.json"
    code = replay_module.main(["rba", "--parquet", str(tiny), "--out", str(out), "--json", str(data), "--progress", "0", "--limit", "4"])
    assert code == 0 and "đã ghi" in capsys.readouterr().out
    text = out.read_text(encoding="utf-8")
    assert "# Replay rule engine v2 trên RBA" in text and "RBA không có toạ độ" in text and "TỔNG HỢP" in text and "--limit 4" in text
    payload = json.loads(data.read_text(encoding="utf-8"))
    assert payload["events"] == 4 and payload["labels"]["is_attack_ip"] == 1 and payload["rules"]["impossible_travel"]["skipped"] == 4

    replay_module.main(["rba", "--parquet", str(tiny), "--out", str(out), "--progress", "0", "--unknown-names", "ip"])
    assert "cận DƯỚI" in out.read_text(encoding="utf-8") and "--unknown-names ip" in out.read_text(encoding="utf-8")


def test_every_caveat_names_a_registered_rule():
    from app.detection.engine import REGISTRY

    assert set(rule_replay.RBA_CAVEATS) <= set(REGISTRY)
    assert all(text.strip().endswith(".") for text in rule_replay.RBA_CAVEATS.values())


@pytest.mark.skipif(not FULL_PARQUET.is_file(), reason="chưa có rba_full.parquet (chạy python -m ml.rba.etl)")
def test_a_slice_of_the_real_dataset_replays_in_order_and_impossible_travel_cannot_run():
    report = replay(rule_replay.rba_attempts(start="2020-03-01", end="2020-03-01 06:00:00", limit=30_000), source="rba")
    assert 5_000 < report.events <= 30_000 and report.out_of_order == 0
    assert report.labels["is_attack_ip"] > 0 and report.unlabelled > 0
    assert report.rules["impossible_travel"].evaluated == 0 and report.rules["tor_exit"].evaluated == 0  # không toạ độ; chưa nạp danh sách
    assert report.any_enforced.by_label["is_attack_ip"] > 0 and report.events_per_second > 300
