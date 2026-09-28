"""Kiểm tra nhiệm vụ 7.1 — trích xuất đặc trưng ML, đặc biệt là chống rò rỉ
dữ liệu tương lai (data leakage) qua UserHistoryState."""

from datetime import datetime, timedelta, timezone

import pytest

from ml.features import UserHistoryState, compute_features, update_state


def test_first_login_has_neutral_defaults():
    state = UserHistoryState()
    now = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)

    features = compute_features(
        state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85,
        device_fingerprint="fp1", created_at=now,
    )

    assert features["hour_deviation_from_avg"] == 0.0  # chưa có baseline
    # Lần đăng nhập ĐẦU TIÊN: đúng nghĩa đen là "chưa từng thấy" vị trí/thiết
    # bị này -> is_new=1.0 (khác baseline.py tầng 2 vốn coi None là "không lạ"
    # để tránh false positive rule cứng; ở đây để nguyên giá trị thô, ML tự
    # học ý nghĩa của is_new=1 kết hợp với "chưa có lịch sử gì" qua các đặc
    # trưng khác — đây chính là điểm khác biệt triết lý tầng 2 vs tầng 3).
    assert features["is_new_location"] == 1.0
    assert features["is_new_device"] == 1.0
    assert features["distance_km_from_home"] == 0.0  # chưa có home_location


def test_new_location_and_device_detected_after_history_built():
    state = UserHistoryState()
    now = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)

    f1 = compute_features(state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85, device_fingerprint="fp1", created_at=now)
    update_state(state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85, device_fingerprint="fp1", created_at=now)

    later = now + timedelta(days=1)
    f2 = compute_features(state, country="US", city="New York", latitude=40.71, longitude=-74.01, device_fingerprint="fp2", created_at=later)

    assert f2["is_new_location"] == 1.0
    assert f2["is_new_device"] == 1.0
    assert f2["distance_km_from_home"] > 10000  # Hà Nội -> New York rất xa


def test_known_location_and_device_not_flagged_as_new():
    state = UserHistoryState()
    now = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    update_state(state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85, device_fingerprint="fp1", created_at=now)

    later = now + timedelta(days=1)
    features = compute_features(state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85, device_fingerprint="fp1", created_at=later)

    assert features["is_new_location"] == 0.0
    assert features["is_new_device"] == 0.0


def test_minutes_since_last_login_and_velocity_window():
    state = UserHistoryState()
    t0 = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    update_state(state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85, device_fingerprint="fp1", created_at=t0)

    t1 = t0 + timedelta(minutes=5)
    f1 = compute_features(state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85, device_fingerprint="fp1", created_at=t1)
    assert abs(f1["minutes_since_last_login"] - 5.0) < 0.01
    assert f1["logins_last_24h"] == 1.0  # chỉ tính lần TRƯỚC (t0), chưa gồm t1


def test_hour_deviation_uses_circular_distance():
    state = UserHistoryState()
    # 3 lần đăng nhập lúc 23h -> baseline avg_hour ~ 23h
    base_day = datetime(2026, 1, 1, 23, 0, tzinfo=timezone.utc)
    for i in range(3):
        ts = base_day + timedelta(days=i)
        update_state(state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85, device_fingerprint="fp1", created_at=ts)

    # Đăng nhập lúc 1h sáng -> chỉ cách 2h thật sự (không phải 22h)
    near = datetime(2026, 1, 5, 1, 0, tzinfo=timezone.utc)
    features = compute_features(state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85, device_fingerprint="fp1", created_at=near)
    assert features["hour_deviation_from_avg"] < 3.0


def test_compute_features_does_not_mutate_state():
    """compute_features() KHÔNG được tự ý cập nhật state — phải gọi update_state()
    riêng, nếu không sẽ tính sai cho batch xử lý nhiều lần đăng nhập liên tiếp."""
    state = UserHistoryState()
    now = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)

    compute_features(state, country="VN", city="Hanoi", latitude=21.03, longitude=105.85, device_fingerprint="fp1", created_at=now)

    assert state.known_locations == set()
    assert state.known_devices == set()
    assert state.login_hours == []
    assert state.recent_timestamps == []


def test_compute_realtime_features_tolerates_a_previous_event_read_back_naive_from_sqlite(db_session):
    """Bug thật tự phát hiện ở MR18 (ml/attack_scenarios.py — mọi kịch bản có baseline lịch sử TRƯỚC khi tấn công):
    `previous_event.created_at` đọc lại từ SQLite mất tzinfo (naive) trong khi `created_at` (tham số, vừa dựng trong
    Python cho lần đăng nhập ĐANG chấm) vẫn aware — trừ hai loại datetime khác nhau raise TypeError thay vì tính được
    `minutes_since_last_login`. CÙNG lớp bug đã gặp (và sửa bằng ensure_utc()) ở is_impossible_travel
    (app/detection/rules.py, MR13) và alert_intelligence_sim.py/pipeline.py (nhiều nơi khác) — lần này ở
    compute_realtime_features (tầng 3, ml/features.py), một hàm KHÔNG được test này chạm tới trước MR18 vì luôn có
    baseline history nào đó."""
    from ml.features import compute_realtime_features
    from app.models import LoginEvent, User

    user = User(username="alice_realtime", password_hash="x")
    db_session.add(user)
    db_session.flush()
    aware_previous = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    db_session.add(LoginEvent(user_id=user.id, attempted_username="alice_realtime", success=True, ip_address="1.2.3.4", is_synthetic=True, created_at=aware_previous))
    db_session.commit()

    now = datetime(2026, 1, 1, 10, 30, tzinfo=timezone.utc)  # 90 phút sau, vẫn aware — KHÔNG raise, KHÔNG lệch vì mất tzinfo
    features = compute_realtime_features(
        db_session, user_id=user.id, baseline=None, country="VN", city="Hanoi", latitude=21.03, longitude=105.85,
        device_fingerprint="fp1", created_at=now,
    )

    assert features["minutes_since_last_login"] == pytest.approx(90.0)
