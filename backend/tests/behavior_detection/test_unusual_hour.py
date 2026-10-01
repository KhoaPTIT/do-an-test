"""unusual_hour — tài khoản trưởng thành đăng nhập THÀNH CÔNG vào một giờ NGOÀI mọi khung giờ mà chính nó đã từng đăng
nhập thành công. Hồ sơ = histogram 24 ô (giờ UTC) làm mượt vòng tròn bằng nhân tam giác bán kính `smoothing_hours` (mặc định
2 ô); hồ sơ quá phân tán (khung quen > `max_coverage` của ngày) → NOT_APPLICABLE. Không giờ nào "luôn nguy hiểm".

Milestone C.1 thay detector 3σ quanh giờ trung tâm (Milestone C). Các test giả định riêng của 3σ đã được cập nhật có ghi lý
do: hồ sơ hai cụm nay ĐƯỢC chấm (giờ ngoài cả hai cụm là bất thường), biên là bán kính làm mượt thay cho "4 giờ tối thiểu"."""

from datetime import timedelta

import pytest

from app.detection.engine.profile import assess_hour, hour_ranges, smoothed_hour_probabilities
from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, T0
from verification.harness import CHROME_UA, SAFARI_UA

RULE = "unusual_hour"
MIDNIGHT = T0 - timedelta(hours=9)  # T0 = 09:00 UTC
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def _profile(env, name, hours, days=20, ua=CHROME_UA):
    env.add_user(name)
    for d in range(days, 0, -1):
        for h in hours[d % len(hours)] if isinstance(hours[0], (list, tuple)) else [hours[d % len(hours)]]:
            env.add_history(name, ip=HOME_IP, ts=MIDNIGHT - timedelta(days=d) + timedelta(hours=h), user_agent=ua)


def _login_at(env, name, hour, success=True, day=0, ua=CHROME_UA):
    env.login(name, success=success, ip=HOME_IP, ts=MIDNIGHT + timedelta(days=day, hours=hour), user_agent=ua)


def _history(env, name, at):
    from app.detection.rule_engine_runtime import DbAccountHistory

    db = env.session_factory()
    try:
        return DbAccountHistory(db, at).get(str(env.user_id(name)))
    finally:
        db.close()


# ------------------------------------------------------------------------------------------------ A. 08–18h → 03h

def test_positive_office_hours_profile_then_3am(env):
    _profile(env, "alice", [8, 10, 12, 14, 16, 18, 9, 11, 13, 15, 17])  # 08:00–18:00
    _login_at(env, "alice", 3.0)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type == "behavior_anomaly" and a.severity == "low"
    exp = a.explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "unusual_hour" and exp["action"] == "allow"
    ev = exp["evidence"]
    assert ev["current_hour"] == 3.0 and ev["hour_probability"] == 0.0
    assert ev["usual_hour_ranges"] == ["06:00-21:00"]  # 08–18h ± bán kính làm mượt 2 giờ
    assert ev["reason"] == "outside_established_login_windows" and ev["profile_method"].startswith("circular_histogram_24h")
    assert ev["successful_login_count"] == 20 and ev["profile_age_days"] >= 19 and ev["timezone"] == "UTC"


# ------------------------------------------------------------------------------------------------ B. ca đêm 22–02h, nửa đêm (C.1 §5)

@pytest.mark.parametrize("hour", [0.5, 23.0, 1.75, 22.25])
def test_negative_night_shift_22_to_02_logging_in_during_the_shift(env, hour):
    _profile(env, "owl", [22, 23, 0, 1, 2, 23.5, 0.5])
    _login_at(env, "owl", hour)
    assert env.detector_alerts(RULE) == []


@pytest.mark.parametrize("hour", [23.5, 0.25, 0.75, 23.0])
def test_negative_cluster_across_midnight_23_30_00_15_00_45(env, hour):
    _profile(env, "alice", [23.5, 0.25, 0.75])
    _login_at(env, "alice", hour)
    assert env.detector_alerts(RULE) == []


def test_unit_bins_23_and_00_are_neighbours_in_the_smoothing():
    counts = [0] * 24
    counts[23] = 5
    probabilities = smoothed_hour_probabilities(tuple(counts), 2)
    assert probabilities[0] > 0 and probabilities[1] > 0 and probabilities[2] == 0  # 23h làm mượt sang 0h, 1h
    assert probabilities[21] > 0 and probabilities[20] == 0
    assert abs(sum(probabilities) - 1.0) < 1e-9
    assert hour_ranges(probabilities) == ("21:00-02:00",)  # một dải qua nửa đêm, không bị cắt đôi


@pytest.mark.parametrize("hour", [23.75, 0.25, 1.5, 22.5])
def test_negative_profile_around_midnight_is_circular(env, hour):
    _profile(env, "alice", [23.0, 23.5, 0.0, 0.5, 1.0])
    _login_at(env, "alice", hour)
    assert env.detector_alerts(RULE) == []


def test_positive_around_midnight_profile_then_noon(env):
    _profile(env, "alice", [23.0, 23.5, 0.0, 0.5, 1.0])
    _login_at(env, "alice", 12.0)
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    ev = alerts[0].explanation["evidence"]
    assert ev["usual_hour_ranges"] == ["21:00-04:00"] and ev["nearest_usual_hours_away"] >= 10.5


# ------------------------------------------------------------------------------------------------ C. nhiều khung giờ (C.1 §4)

@pytest.mark.parametrize("hour", [8.25, 13.5, 19.0])
def test_negative_three_modes_08_13_19_are_all_usual(env, hour):
    _profile(env, "alice", [8, 13, 19, 8.5, 13.25, 18.75], days=24)
    _login_at(env, "alice", hour)
    assert env.detector_alerts(RULE) == []


def test_positive_three_modes_then_3am(env):
    _profile(env, "alice", [8, 13, 19, 8.5, 13.25, 18.75], days=24)
    _login_at(env, "alice", 3.0)
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    # ba cụm 08h, 13h, 18–19h cách nhau ≤ 5 giờ nên khung quen (± 2 giờ) liền thành một dải; 03h vẫn nằm ngoài
    assert alerts[0].explanation["evidence"]["usual_hour_ranges"] == ["06:00-22:00"]


def test_positive_bimodal_morning_evening_profile_then_2pm(env):
    """Thay đổi thiết kế có chủ ý (C.1): detector 3σ bỏ qua hồ sơ hai cụm (R ≈ 0, "không có giờ quen"); histogram coi CẢ HAI
    cụm là khung quen — 08h và 20h bình thường, 14h (cách cả hai cụm 6 giờ) là bất thường."""
    _profile(env, "alice", [8, 20])
    _login_at(env, "alice", 8.25)
    _login_at(env, "alice", 20.25, day=1)
    assert env.detector_alerts(RULE) == []
    _login_at(env, "alice", 14.0, day=2)
    assert len(env.detector_alerts(RULE)) == 1


# ------------------------------------------------------------------------------------------------ D. hồ sơ gần như 24/7 (C.1 §6)

def test_negative_round_the_clock_profile_is_not_applicable(env):
    _profile(env, "ops", [[h, (h + 8) % 24, (h + 16) % 24] for h in range(8)], days=24)  # mọi giờ trong ngày đều có lần thành công
    _login_at(env, "ops", 3.5)
    assert env.detector_alerts(RULE) == []
    hour = assess_hour(_history(env, "ops", MIDNIGHT), MIDNIGHT.timestamp() + 3.5 * 3600, smoothing_hours=PARAMS["smoothing_hours"], max_coverage=PARAMS["max_coverage"])
    assert hour.status == "NOT_APPLICABLE" and hour.coverage > PARAMS["max_coverage"]


def test_boundary_coverage_above_the_limit_is_not_applicable_even_with_a_gap(env):
    # 04h–19h đều có lần thành công → khung quen 02h–22h (20/24 ≈ 0,83 > 0,75): còn khoảng trống 22h–02h nhưng hồ sơ quá phân tán
    _profile(env, "wide", list(range(4, 20)), days=32)
    _login_at(env, "wide", 0.0)
    assert env.detector_alerts(RULE) == []
    hour = assess_hour(_history(env, "wide", MIDNIGHT), MIDNIGHT.timestamp(), smoothing_hours=PARAMS["smoothing_hours"], max_coverage=PARAMS["max_coverage"])
    assert hour.status == "NOT_APPLICABLE" and hour.hour_probability == 0.0


# ------------------------------------------------------------------------------------------------ E. chưa trưởng thành

def test_negative_new_account_is_not_evaluated(env):
    _profile(env, "newbie", [9, 10], days=5)
    _login_at(env, "newbie", 21.0)
    assert env.detector_alerts(RULE) == []


def test_negative_too_few_successes_even_over_many_days(env):
    env.add_user("rare")
    for d in range(30, 3, -3):  # 9 lần thành công trong 27 ngày: tuổi đủ, số lần chưa đủ
        env.add_history("rare", ip=HOME_IP, ts=MIDNIGHT - timedelta(days=d) + timedelta(hours=9))
    _login_at(env, "rare", 21.0)
    assert env.detector_alerts(RULE) == []


def test_negative_many_successes_but_profile_younger_than_7_days(env):
    _profile(env, "young", [[9, 10, 11]], days=6)  # 18 lần trong 6 ngày
    _login_at(env, "young", 21.0)
    assert env.detector_alerts(RULE) == []


# ------------------------------------------------------------------------------------------------ F. chống đầu độc hồ sơ (C.1 §7)

def test_negative_failed_login_at_an_odd_hour(env):
    _profile(env, "alice", [9, 10, 11])
    _login_at(env, "alice", 22.0, success=False)
    assert env.detector_alerts(RULE) == []


def test_profile_poisoning_failed_logins_at_3am_do_not_enter_the_hour_histogram(env):
    _profile(env, "alice", [9, 10, 11])
    for k in range(10):
        _login_at(env, "alice", 3.0 + k * 0.05, success=False)
    history = _history(env, "alice", MIDNIGHT + timedelta(days=1))
    assert history.hour_counts[3] == 0 and sum(history.hour_counts) == 20
    assert history.hour_counts[9] + history.hour_counts[10] + history.hour_counts[11] == 20
    _login_at(env, "alice", 3.0, day=1)  # 10 lần thử SAI lúc 03h không biến 03h thành giờ quen
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and alerts[0].explanation["evidence"]["successful_login_count"] == 20


# ------------------------------------------------------------------------------------------------ G. múi giờ

def test_limitation_hours_are_utc_for_both_profile_and_login(env):
    """Hệ thống không có múi giờ / DST của người dùng: hồ sơ và lần đăng nhập cùng tính theo UTC (ghi trong evidence). Không
    giả lập logic múi giờ không có dữ liệu hỗ trợ — xem LIMITATIONS trong báo cáo Milestone C.1."""
    _profile(env, "alice", [9, 10, 11])
    _login_at(env, "alice", 22.0)
    assert env.detector_alerts(RULE)[0].explanation["evidence"]["timezone"] == "UTC"


# ------------------------------------------------------------------------------------------------ biên & lệch nhỏ

def test_negative_one_hour_off(env):
    _profile(env, "alice", [9, 9.5, 10, 10.5])
    _login_at(env, "alice", 11.5)
    assert env.detector_alerts(RULE) == []


def test_boundary_smoothing_radius(env):
    """Biên = bán kính làm mượt: hồ sơ toàn 10:xx (ô 10) → ô 8–12 thuộc khung quen; 12:55 (ô 12) bình thường, 13:05 (ô 13) bất thường."""
    _profile(env, "a", [10.0])
    _profile(env, "b", [10.0])
    _login_at(env, "a", 12 + 55 / 60)
    _login_at(env, "b", 13 + 5 / 60)
    assert [x.user_id for x in env.detector_alerts(RULE)] == [env.user_id("b")]


def test_negative_hour_seen_only_in_the_tail_of_a_skewed_profile(env):
    """Nhóm báo nhầm lớn nhất của 3σ (WIDE_NORMAL_WINDOW, fp_analysis.json): lần đầu trong ngày quanh 18h, các lần sau muộn dần
    tới 01h. 01h đã có trong lịch sử của chính người dùng nên là giờ quen dù cách giờ trung tâm > 3σ."""
    _profile(env, "alice", [[18, 19.5], [18.25], [17.75, 20, 23], [18.5, 21], [18, 1.0]], days=30)
    _login_at(env, "alice", 1.25)
    assert env.detector_alerts(RULE) == []


# ------------------------------------------------------------------------------------------------ quy kết

def test_attribution_hour_and_device_keep_both_reasons(env):
    _profile(env, "alice", [9, 10, 11], ua=CHROME_UA)
    _login_at(env, "alice", 22.0, ua=SAFARI_UA)
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == [RULE]
    assert "unusual_device" in alerts[0].explanation["secondary_signals"]
