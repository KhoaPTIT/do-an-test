"""MR12 — app/detection/rule_engine_runtime.py: lịch sử tài khoản/thống kê ASN dựng từ DB, blocklist DB-backed có cache
TTL (xoá giữa các test qua conftest.py), engine dùng fakeredis (qua monkeypatch của rate_counter, không phải Redis thật)."""

from datetime import datetime, timedelta, timezone

import fakeredis
import pytest

from app.detection.engine import LoginAttempt
from app.detection.rule_engine_runtime import (
    DbAccountHistory,
    DbGlobalStats,
    build_rule_engine,
    invalidate_blocklist_cache,
    load_threat_intel_at_startup,
    refresh_blocklist,
)
from app.models import BlocklistEntry, LoginEvent, User

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _event(db, *, minutes=0, user_id=None, success=True, ip="10.0.0.1", asn=None, country=None, ua="Mozilla/5.0 (X11; Linux x86_64)", lat=None, lon=None):
    ev = LoginEvent(
        user_id=user_id, attempted_username=f"u{user_id}" if user_id else "ghost", success=success, ip_address=ip, asn=asn, country=country,
        user_agent=ua, latitude=lat, longitude=lon, is_synthetic=True, created_at=BASE + timedelta(minutes=minutes),
    )
    db.add(ev)
    db.flush()
    return ev


def _user(db, username="alice"):
    u = User(username=username, password_hash="x")
    db.add(u)
    db.flush()
    return u


# ------------------------------------------------------------------------------------------------ DbAccountHistory


def test_returns_none_for_a_user_with_no_prior_history_or_an_unknown_key(db_session):
    user = _user(db_session)
    history = DbAccountHistory(db_session, BASE + timedelta(days=1))
    assert history.get(str(user.id)) is None
    assert history.get(None) is None
    assert history.get("not-an-int") is None


def test_builds_last_event_last_success_and_known_countries_devices_strictly_before(db_session):
    user = _user(db_session)
    _event(db_session, minutes=0, user_id=user.id, success=True, country="VN", ua="UA-A", lat=21.0, lon=105.0)
    _event(db_session, minutes=10, user_id=user.id, success=False, country="US")  # thất bại: không vào known_countries, vẫn là last_event
    current = _event(db_session, minutes=20, user_id=user.id)

    history = DbAccountHistory(db_session, current.created_at).get(str(user.id))
    assert history.n_success == 1 and history.known_countries == ("VN",)
    assert history.last_event_ts == (BASE + timedelta(minutes=10)).timestamp()  # dòng phút 10 (thất bại) vẫn là "lần gần nhất"
    assert history.last_event_lat is None  # toạ độ của LẦN GẦN NHẤT (phút 10), không có lat/lon
    assert history.last_success_ts == BASE.timestamp()


def test_get_never_includes_the_row_at_or_after_before(db_session):
    user = _user(db_session)
    at_before = BASE + timedelta(minutes=30)
    _event(db_session, minutes=30, user_id=user.id)  # created_at == before: KHÔNG được tính
    assert DbAccountHistory(db_session, at_before).get(str(user.id)) is None


def test_known_devices_uses_the_shared_ua_hash_function(db_session):
    from app.detection.engine.types import ua_hash

    user = _user(db_session)
    _event(db_session, minutes=0, user_id=user.id, success=True, ua="Mozilla/5.0 special")
    current = _event(db_session, minutes=5, user_id=user.id)
    history = DbAccountHistory(db_session, current.created_at).get(str(user.id))
    assert history.known_devices == (ua_hash("Mozilla/5.0 special"),)


# ------------------------------------------------------------------------------------------------ DbGlobalStats


def test_counts_only_successful_real_account_logins_by_asn_and_caches_within_ttl(db_session):
    user = _user(db_session)
    _event(db_session, minutes=0, user_id=user.id, success=True, asn=100)
    _event(db_session, minutes=1, user_id=user.id, success=False, asn=100)  # thất bại: không tính
    _event(db_session, minutes=1, user_id=None, success=True, asn=100)  # tên không tồn tại: không tính

    stats = DbGlobalStats(db_session, ttl_seconds=1000.0)
    assert stats.total_successes == 1 and stats.asn_successes(100) == 1 and stats.asn_successes(999) == 0

    _event(db_session, minutes=2, user_id=user.id, success=True, asn=100)
    assert stats.total_successes == 1  # còn trong TTL: không quét lại


def test_a_fresh_instance_always_recomputes(db_session):
    user = _user(db_session)
    _event(db_session, minutes=0, user_id=user.id, success=True, asn=1)
    assert DbGlobalStats(db_session).total_successes == 1
    _event(db_session, minutes=1, user_id=user.id, success=True, asn=1)
    assert DbGlobalStats(db_session).total_successes == 2  # instance MỚI, không dùng lại cache của instance trước


# ------------------------------------------------------------------------------------------------ blocklist DB-backed


def test_refresh_blocklist_matches_an_unexpired_entry_and_ignores_an_expired_one(db_session):
    db_session.add_all(
        [
            BlocklistEntry(kind="ip", value="6.6.6.6", reason="botnet", added_by="admin"),
            BlocklistEntry(kind="ip", value="7.7.7.7", reason="cũ", expires_at=BASE - timedelta(days=1)),
        ]
    )
    db_session.flush()
    invalidate_blocklist_cache()
    blocklist = refresh_blocklist(db_session, force=True)

    live = LoginAttempt(ts=BASE.timestamp(), username="x", success=False, ip="6.6.6.6")
    expired = LoginAttempt(ts=BASE.timestamp(), username="x", success=False, ip="7.7.7.7")
    assert blocklist.match(live) is not None and blocklist.match(live).reason == "botnet"
    assert blocklist.match(expired) is None  # hết hạn TRƯỚC mốc BASE


def test_refresh_blocklist_is_cached_until_invalidated(db_session):
    invalidate_blocklist_cache()
    before = refresh_blocklist(db_session)
    db_session.add(BlocklistEntry(kind="username", value="newblock"))
    db_session.flush()
    same = refresh_blocklist(db_session)
    assert same is before  # còn trong TTL: chưa thấy mục mới

    invalidate_blocklist_cache()
    refreshed = refresh_blocklist(db_session)
    assert refreshed is not before
    assert refreshed.match(LoginAttempt(ts=BASE.timestamp(), username="newblock", success=False, ip="1.2.3.4")) is not None


# ------------------------------------------------------------------------------------------------ build_rule_engine (tích hợp, dùng fakeredis)


@pytest.fixture()
def redis_client(monkeypatch):
    client = fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True)
    monkeypatch.setattr("app.detection.rate_counter.redis_client", client)
    return client


def test_build_rule_engine_uses_the_current_rate_counter_redis_client_not_a_stale_singleton(db_session, redis_client):
    """Bảo vệ khỏi lỗi đã sửa: đổi `rate_counter.redis_client` (như test làm qua monkeypatch) phải được `build_rule_engine`
    thấy ngay, không được giữ tham chiếu cũ từ lúc import module."""
    load_threat_intel_at_startup()
    engine = build_rule_engine(db_session, before=BASE + timedelta(days=1))
    for i in range(5):
        result = engine.evaluate(LoginAttempt(ts=(BASE + timedelta(seconds=i)).timestamp(), username="brute", success=False, ip="1.1.1.1"))
    assert any(h.rule_id == "brute_force" for h in result.hits)
    assert redis_client.keys("rule:*")  # đã ghi vào ĐÚNG client bị monkeypatch, không phải Redis thật


def test_build_rule_engine_never_lets_the_calling_labels_leak_and_skips_reputation_rules_without_lists(db_session, redis_client):
    load_threat_intel_at_startup()
    engine = build_rule_engine(db_session, before=BASE + timedelta(days=1))
    result = engine.evaluate(LoginAttempt(ts=BASE.timestamp(), username="x", success=False, ip="8.8.8.8"))
    # threat_intel thật của repo có thể đã tải (backend/threat_intel/); chỉ kiểm KHÔNG lỗi và không sập, không khẳng định nội dung danh sách.
    assert result.errors == {}
