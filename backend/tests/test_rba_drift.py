"""MR12 — PSI (Population Stability Index): công thức, NaN, đặc trưng gần hằng số, báo cáo, cờ mẫu quá nhỏ."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import drift


def test_identical_distributions_give_a_psi_near_zero():
    rng = np.random.default_rng(0)
    values = rng.normal(0, 1, 4000)
    assert drift.population_stability_index(values[:2000], values[2000:]) < 0.02


def test_a_large_shift_gives_a_large_psi():
    rng = np.random.default_rng(1)
    reference = rng.normal(0, 1, 3000)
    shifted = rng.normal(4, 1, 1000)  # lệch hẳn ra ngoài phạm vi đã thấy ở tham chiếu
    assert drift.population_stability_index(reference, shifted) > 1.0


def test_psi_is_symmetric_in_magnitude_but_not_in_sign_convention():
    """PSI thật ra không đối xứng tuyệt đối (khoảng chia theo tham chiếu), nhưng đổi vai trò hai phân phối lệch tương đương vẫn phải cho số LỚN cả hai chiều."""
    rng = np.random.default_rng(2)
    a, b = rng.normal(0, 1, 3000), rng.normal(3, 1, 3000)
    assert drift.population_stability_index(a, b) > 0.5 and drift.population_stability_index(b, a) > 0.5


def test_nan_rows_are_dropped_from_both_sides_before_binning():
    rng = np.random.default_rng(3)
    clean = rng.normal(0, 1, 2000)
    with_nans = np.concatenate([clean, np.full(500, np.nan)])
    assert drift.population_stability_index(with_nans, clean) == pytest.approx(drift.population_stability_index(clean, clean), abs=1e-9)


def test_all_nan_on_either_side_gives_nan_not_a_crash():
    values = np.random.default_rng(4).normal(0, 1, 100)
    assert np.isnan(drift.population_stability_index(np.full(50, np.nan), values))
    assert np.isnan(drift.population_stability_index(values, np.full(50, np.nan)))


def test_a_near_constant_reference_feature_does_not_crash_and_flags_any_new_value():
    reference = np.zeros(1000)
    assert drift.population_stability_index(reference, np.zeros(200)) == 0.0
    assert np.isnan(drift.population_stability_index(reference, np.concatenate([np.zeros(190), np.ones(10)])))


@pytest.mark.parametrize("psi,expected", [(0.02, "ổn định"), (0.15, "trôi vừa"), (0.4, "trôi đáng kể"), (float("nan"), "không đủ dữ liệu")])
def test_verdict_thresholds(psi, expected):
    assert drift.verdict(psi) == expected


def test_psi_report_sorts_by_drift_descending_and_flags_low_confidence_current_samples():
    rng = np.random.default_rng(5)
    reference = pd.DataFrame({"stable": rng.normal(0, 1, 2000), "drifted": rng.normal(0, 1, 2000), "missing_in_current": rng.normal(0, 1, 2000)})
    current = pd.DataFrame({"stable": rng.normal(0, 1, 20), "drifted": rng.normal(5, 1, 20), "missing_in_current": np.full(20, np.nan)})
    rows = drift.psi_report(reference, current, feature_names=["stable", "drifted", "missing_in_current"])
    assert [r.feature for r in rows[:1]] == ["drifted"]  # trôi nhiều nhất lên đầu
    assert all(r.low_confidence for r in rows)  # 20 < MIN_CURRENT_ROWS (30)
    missing_row = next(r for r in rows if r.feature == "missing_in_current")
    assert np.isnan(missing_row.psi) and missing_row.n_current == 0 and missing_row.verdict == "không đủ dữ liệu"


def test_render_lists_every_feature_with_its_verdict_and_flags_low_confidence():
    rows = [
        drift.FeatureDrift("a", 0.02, "ổn định", 100, 50, False),
        drift.FeatureDrift("b", 0.4, "trôi đáng kể", 100, 5, True),
        drift.FeatureDrift("c", float("nan"), "không đủ dữ liệu", 100, 0, True),
    ]
    text = drift.render(rows)
    for expected in ("a", "0.020", "ổn định", "b", "0.400", "trôi đáng kể", "mẫu hiện tại quá ít", "c", "—", "không đủ dữ liệu"):
        assert expected in text, expected


# ------------------------------------------------------------------------------------ MR17: current_frame(db=, limit=)


def _make_user_and_events(db_session, *, count, ip="1.2.3.4"):
    from datetime import datetime, timedelta, timezone

    from app.models import LoginEvent, User
    from app.security import hash_password

    user = User(username="alice", password_hash=hash_password("x"))
    db_session.add(user)
    db_session.flush()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(count):
        db_session.add(LoginEvent(
            user_id=user.id, attempted_username="alice", success=True, ip_address=ip, is_synthetic=False, created_at=base + timedelta(minutes=i),
        ))
    db_session.commit()
    return user


def test_current_frame_uses_the_injected_session_not_the_real_configured_one(db_session, monkeypatch):
    """Bug thật tự phát hiện khi dựng MR17 (GET /model-health): current_frame() TỰ mở app.database.SessionLocal bên
    trong khi không truyền `db` — một endpoint/test đã monkeypatch SessionLocal Ở NƠI KHÁC (app.detection.pipeline,
    app.main, như conftest.py làm) vẫn bị current_frame() lặng lẽ đọc nhầm DB THẬT. Kiểm bằng cách CHẶN HẲN
    app.database.SessionLocal — nếu hàm cố mở nó, test này tự sập thay vì âm thầm đọc nhầm DB."""
    from ml.rba.drift import current_frame

    def _boom():
        raise AssertionError("current_frame() không được tự mở app.database.SessionLocal khi đã có `db` truyền vào")

    monkeypatch.setattr("app.database.SessionLocal", _boom)
    _make_user_and_events(db_session, count=3)

    result = current_frame(db=db_session)

    assert len(result) == 3  # đọc đúng DB được truyền vào (db_session, SQLite in-memory của test), không lỗi


def test_current_frame_limit_keeps_the_most_recent_rows_not_the_oldest(db_session):
    """10 lần đăng nhập liên tiếp của CÙNG tài khoản -> u_n_success (số lần thành công TRƯỚC ĐÓ) tăng dần đều 0..9.
    `limit=3` phải giữ lại 3 dòng CUỐI (u_n_success cao) chứ không phải 3 dòng ĐẦU (u_n_success thấp) — kiểm GIÁN TIẾP
    qua đặc trưng vì DataFrame trả về không có cột created_at để so trực tiếp."""
    from ml.rba.drift import current_frame

    _make_user_and_events(db_session, count=10)

    result = current_frame(db=db_session, limit=3)

    assert len(result) == 3
    assert result["u_n_success"].min() >= 7  # dòng thứ 8,9,10 (0-based 7,8,9) có ÍT NHẤT 7 lần thành công trước đó
