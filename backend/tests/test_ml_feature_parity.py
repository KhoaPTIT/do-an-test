"""BẮT BUỘC (Phase 4.1B): cùng lịch sử + cùng sự kiện ⇒ trích đặc trưng OFFLINE (`ml.features.extract_offline`, dùng để
dựng dataset) và RUNTIME (`app.detection.ml_runtime.runtime_features`, dùng ở /login) cho CÙNG vector.

Kèm hồi quy cho lỗi tìm được ở audit Phase 4.0: sự kiện hiện tại đã `flush` vào DB trước khi trích đặc trưng nên bản cũ lấy
nhầm chính nó làm "lần thành công trước" (`minutes_since_last_login` luôn = 0)."""

import math
import random
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.detection.ml_runtime import runtime_features
from app.models import LoginEvent, User
from ml.features import FEATURE_NAMES, RawLogin, extract_offline

T = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)
UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    None,
)
PLACES = (("VN", "Hanoi", 21.03, 105.85), ("VN", "Ho Chi Minh City", 10.82, 106.63), ("JP", "Tokyo", 35.68, 139.65), (None, None, None, None))


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _insert(db, user_id, raw: RawLogin) -> LoginEvent:
    row = LoginEvent(
        user_id=user_id, attempted_username=raw.username, success=raw.success, ip_address="192.0.2.10", user_agent=raw.user_agent,
        country=raw.country, city=raw.city, latitude=raw.latitude, longitude=raw.longitude, created_at=raw.ts,
    )
    db.add(row)
    db.flush()  # như pipeline.py: sự kiện được ghi TRƯỚC khi trích đặc trưng
    return row


def _random_history(rng, username, n=40):
    events, t = [], T - timedelta(days=30)
    for k in range(n):
        t += timedelta(minutes=rng.choice((3, 40, 300, 900, 1500, 2800)))
        place = rng.choice(PLACES[:2]) if rng.random() < 0.85 else rng.choice(PLACES)
        events.append(RawLogin(k + 1, username, t, rng.random() > 0.15, *place, rng.choice(UAS)))
    return events


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_offline_and_runtime_features_are_identical_for_every_event(db, seed):
    rng = random.Random(seed)
    user = User(username=f"u{seed}", password_hash="x")
    db.add(user)
    db.flush()
    events = _random_history(rng, user.username)
    offline = dict(extract_offline(events))
    assert len(offline) > 10  # đủ sự kiện thuộc phạm vi để so

    runtime = {}
    for raw in events:  # phát lại theo thời gian: mỗi sự kiện được ghi rồi chấm ngay, như luồng /login
        row = _insert(db, user.id, raw)
        in_scope, features = runtime_features(db, row)
        if in_scope:
            runtime[raw.event_id] = features
    assert runtime.keys() == offline.keys()
    for event_id, features in offline.items():
        for name in FEATURE_NAMES:
            assert runtime[event_id][name] == pytest.approx(features[name], abs=1e-9), (event_id, name)


def test_regression_previous_login_is_not_the_current_event(db):
    """Lần thành công trước lúc T, lần hiện tại lúc T + 300 phút ⇒ ≈ 300 phút (bản cũ trả 0)."""
    user = User(username="alice", password_hash="x")
    db.add(user)
    db.flush()
    for d in range(12, 0, -1):  # hồ sơ trưởng thành
        _insert(db, user.id, RawLogin(0, "alice", T - timedelta(days=d), True, "VN", "Hanoi", 21.03, 105.85, UAS[0]))
    _insert(db, user.id, RawLogin(0, "alice", T, True, "VN", "Hanoi", 21.03, 105.85, UAS[0]))
    current = _insert(db, user.id, RawLogin(0, "alice", T + timedelta(minutes=300), True, "VN", "Hanoi", 21.03, 105.85, UAS[0]))
    in_scope, features = runtime_features(db, current)
    assert in_scope
    assert math.expm1(features["log_minutes_since_last_success"]) == pytest.approx(300.0)
    assert features["logins_last_24h"] == 1.0


def test_failed_logins_and_unknown_accounts_are_out_of_scope(db):
    """Train chỉ trên lần thành công ⇒ runtime chỉ chấm lần thành công; lần thất bại để 20 detector luật xử lý."""
    user = User(username="bob", password_hash="x")
    db.add(user)
    db.flush()
    for d in range(12, 0, -1):
        _insert(db, user.id, RawLogin(0, "bob", T - timedelta(days=d), True, "VN", "Hanoi", 21.03, 105.85, UAS[0]))
    failed = _insert(db, user.id, RawLogin(0, "bob", T, False, "JP", "Tokyo", 35.68, 139.65, UAS[3]))
    assert runtime_features(db, failed) == (False, None)
    ghost = _insert(db, None, RawLogin(0, "ghost", T, True, "VN", "Hanoi", 21.03, 105.85, UAS[0]))
    assert runtime_features(db, ghost) == (False, None)


def test_immature_profile_is_out_of_scope(db):
    user = User(username="newbie", password_hash="x")
    db.add(user)
    db.flush()
    for d in range(5, 0, -1):
        _insert(db, user.id, RawLogin(0, "newbie", T - timedelta(days=d), True, "VN", "Hanoi", 21.03, 105.85, UAS[0]))
    current = _insert(db, user.id, RawLogin(0, "newbie", T, True, "VN", "Hanoi", 21.03, 105.85, UAS[0]))
    assert runtime_features(db, current) == (False, None)
