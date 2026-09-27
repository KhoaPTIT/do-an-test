"""MR12 — app/detection/rba_live_features.py: dựng HistorySummary từ DB (SQLite test), đúng quy ước "chỉ tính TRƯỚC sự
kiện" của ml/rba/features.py, cache đếm toàn cục có TTL, không bao giờ raise ra ngoài `compute_rba_features`."""

from datetime import datetime, timedelta, timezone

import pytest

from app.detection.rba_live_features import GlobalCountsCache, build_features_and_summary, build_history_summary, compute_rba_features, event_record_for, to_us
from app.models import LoginEvent, User
from ml.rba.features import FEATURE_NAMES

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _mk(db, *, minutes=0, user_id=None, ip="10.0.0.1", asn=None, success=True, country=None, ua="Mozilla/5.0", browser=None, os=None, device="desktop"):
    ev = LoginEvent(
        user_id=user_id, attempted_username=f"u{user_id}" if user_id else "ghost", success=success, ip_address=ip, asn=asn, country=country,
        user_agent=ua, browser_name=browser, os_name=os, device_type=device, is_synthetic=True, created_at=BASE + timedelta(minutes=minutes),
    )
    db.add(ev)
    db.flush()
    return ev


def _user(db, username="alice"):
    u = User(username=username, password_hash="x")
    db.add(u)
    db.flush()
    return u


def test_event_record_for_carries_every_field_and_a_matching_ts_us(db_session):
    ev = _mk(db_session, minutes=5, user_id=None, ip="1.2.3.4", asn=64500, success=False, country="VN", ua="Mozilla/5.0 test", browser="Chrome", os="Windows", device="mobile")
    rec = event_record_for(ev)
    assert (rec.ip, rec.asn, rec.country, rec.ua, rec.browser, rec.os, rec.device_type, rec.success, rec.user_id) == ("1.2.3.4", 64500, "VN", "Mozilla/5.0 test", "Chrome", "Windows", "mobile", False, None)
    assert rec.ts_us == to_us(BASE + timedelta(minutes=5))


def test_user_events_only_include_the_same_user_strictly_before(db_session):
    user = _user(db_session)
    other = _user(db_session, "bob")
    _mk(db_session, minutes=0, user_id=user.id)
    _mk(db_session, minutes=1, user_id=other.id)  # người khác: không được tính
    current = _mk(db_session, minutes=2, user_id=user.id)

    summary = build_history_summary(db_session, event_record_for(current))
    assert summary.user_events is not None and len(summary.user_events) == 1  # chỉ dòng phút 0, không phải của bob, không phải chính nó
    assert summary.user_events[0].ts_us == to_us(BASE)


def test_unknown_username_has_no_user_history_but_still_has_ip_and_global_history(db_session):
    _mk(db_session, minutes=0, user_id=None, ip="9.9.9.9")
    current = _mk(db_session, minutes=1, user_id=None, ip="9.9.9.9")
    summary = build_history_summary(db_session, event_record_for(current))
    assert summary.user_events is None and len(summary.ip_events) == 1


def test_ip_events_respect_the_24h_window_and_ip_prior_attempts_all_does_not(db_session):
    old = _mk(db_session, minutes=0, ip="5.5.5.5")  # sẽ ở ngoài cửa sổ 24h của dòng cuối
    _mk(db_session, minutes=120, ip="5.5.5.5")  # cách mốc cuối 23h — rõ ràng còn trong cửa sổ (tránh đúng biên 24h)
    current_ts = BASE + timedelta(hours=25)
    current = LoginEvent(user_id=None, attempted_username="x", success=True, ip_address="5.5.5.5", user_agent="ua", is_synthetic=True, created_at=current_ts)
    db_session.add(current)
    db_session.flush()

    summary = build_history_summary(db_session, event_record_for(current))
    assert len(summary.ip_events) == 1  # chỉ dòng phút 120 còn trong 24h; dòng đầu (phút 0, cách 25h) đã ngoài cửa sổ
    assert summary.ip_prior_attempts_all == 2  # nhưng "mọi thời điểm" vẫn đếm cả hai
    assert old.id  # tránh cảnh báo biến không dùng


def test_asn_events_are_empty_without_an_asn_and_scoped_to_24h_when_present(db_session):
    _mk(db_session, minutes=0, asn=64500)
    with_asn = LoginEvent(user_id=None, attempted_username="x", success=True, ip_address="1.1.1.1", asn=64500, user_agent="ua", is_synthetic=True, created_at=BASE + timedelta(minutes=30))
    without_asn = LoginEvent(user_id=None, attempted_username="y", success=True, ip_address="1.1.1.2", asn=None, user_agent="ua", is_synthetic=True, created_at=BASE + timedelta(minutes=30))
    db_session.add_all([with_asn, without_asn])
    db_session.flush()

    assert len(build_history_summary(db_session, event_record_for(with_asn)).asn_events) == 1
    assert build_history_summary(db_session, event_record_for(without_asn)).asn_events == []


def test_global_counts_only_include_successful_real_account_logins_strictly_before(db_session):
    user = _user(db_session)
    _mk(db_session, minutes=0, user_id=user.id, success=True, country="VN")
    _mk(db_session, minutes=1, user_id=user.id, success=False, country="US")  # thất bại: không tính
    _mk(db_session, minutes=1, user_id=None, success=True, country="JP")  # tên không tồn tại: không tính
    current = _mk(db_session, minutes=2, user_id=user.id, success=True, country="VN")

    cache = GlobalCountsCache()
    summary = build_history_summary(db_session, event_record_for(current), cache=cache)
    assert summary.global_counts.total == 1  # chỉ dòng phút 0 (thành công, tài khoản thật)


def test_global_counts_cache_is_reused_within_the_ttl_and_refreshed_after(db_session):
    user = _user(db_session)
    _mk(db_session, minutes=0, user_id=user.id, success=True)
    cache = GlobalCountsCache(ttl_seconds=1000.0)
    before = BASE + timedelta(minutes=5)
    first = cache.get(db_session, before)
    _mk(db_session, minutes=1, user_id=user.id, success=True)  # thêm một dòng thành công mới, VẪN TRƯỚC `before`
    assert cache.get(db_session, before) is first  # cùng mốc, còn trong TTL: KHÔNG quét lại, vẫn thấy 1
    assert first.total == 1

    cache.invalidate()
    refreshed = cache.get(db_session, before)
    assert refreshed is not first and refreshed.total == 2  # sau invalidate: quét lại, thấy cả hai

    later = cache.get(db_session, before + timedelta(seconds=1))
    assert later is refreshed  # mốc cache (before) vẫn <= mốc mới hỏi và trong TTL: an toàn để dùng lại

    earlier = cache.get(db_session, before - timedelta(seconds=1))
    assert earlier is not refreshed  # mốc cache SAU mốc đang hỏi: không an toàn (có thể thừa), phải tính lại


def test_compute_rba_features_returns_all_50_names_and_is_consistent_with_the_pure_spec(db_session):
    user = _user(db_session)
    _mk(db_session, minutes=0, user_id=user.id, success=True, country="VN", ua="Mozilla/5.0 A")
    current = _mk(db_session, minutes=10, user_id=user.id, success=True, country="VN", ua="Mozilla/5.0 A")

    features = compute_rba_features(db_session, event_record_for(current))
    assert features is not None and set(features) == set(FEATURE_NAMES)
    assert features["new_country"] == 0.0  # đã thấy VN ở lần thành công trước
    assert features["u_n_success"] == 1.0  # 1 lần thành công TRƯỚC đó (không tính chính nó)


def test_compute_rba_features_returns_none_instead_of_raising_on_error(db_session, monkeypatch):
    import app.detection.rba_live_features as mod

    def boom(*args, **kwargs):
        raise RuntimeError("lỗi giả lập")

    monkeypatch.setattr(mod, "build_history_summary", boom)
    current = _mk(db_session, minutes=0)
    assert compute_rba_features(db_session, event_record_for(current)) is None


def test_build_features_and_summary_returns_both_and_matches_the_separate_calls(db_session):
    """MR13: `app/detection/alert_intelligence.py` cần TÁI DÙNG `HistorySummary` đã dựng (không truy vấn DB lần hai) để
    tính novelty — kết quả hai phần phải khớp CHÍNH XÁC với gọi `build_history_summary`/`compute_rba_features` riêng."""
    user = _user(db_session)
    _mk(db_session, minutes=0, user_id=user.id, success=True, country="VN", ua="Mozilla/5.0 A")
    current_a = _mk(db_session, minutes=10, user_id=user.id, success=True, country="VN", ua="Mozilla/5.0 A")
    current_b = _mk(db_session, minutes=10, user_id=user.id, success=True, country="VN", ua="Mozilla/5.0 A")

    features, summary = build_features_and_summary(db_session, event_record_for(current_a))
    assert features == compute_rba_features(db_session, event_record_for(current_b))
    assert summary is not None and summary.user_events is not None and len(summary.user_events) == 1


def test_build_features_and_summary_returns_none_none_instead_of_raising_on_error(db_session, monkeypatch):
    import app.detection.rba_live_features as mod

    def boom(*args, **kwargs):
        raise RuntimeError("lỗi giả lập")

    monkeypatch.setattr(mod, "build_history_summary", boom)
    current = _mk(db_session, minutes=0)
    assert build_features_and_summary(db_session, event_record_for(current)) == (None, None)
