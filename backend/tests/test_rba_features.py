"""MR3 — đặc tả đặc trưng v2: ngữ nghĩa từng nhóm, tính tay trên các ca nhỏ."""

import math

import pytest

from ml.rba import features as F
from ml.rba.features import EventRecord, W_1H, W_24H


def ev(t, user=1, ip="1.1.1.1", asn=100, country="NO", ua="ua1", browser="Chrome 90.0", os="Windows 10", device="desktop", success=True):
    return EventRecord(t, user, ip, asn, country, ua, browser, os, device, success)


def feats(event, prior):
    return F.compute_features_spec(event, prior)


def test_feature_names_are_unique_and_cover_every_group():
    assert len(F.FEATURE_NAMES) == len(set(F.FEATURE_NAMES)) == 50
    assert sum(len(v) for v in F.FEATURE_GROUPS.values()) == len(F.FEATURE_NAMES)


def test_strip_version():
    assert F.strip_version("Chrome Mobile 46.0.2490") == "Chrome Mobile"
    assert F.strip_version("Android 2.3.3.2672") == "Android"
    assert F.strip_version("Googlebot") == "Googlebot"
    assert F.strip_version("∅") == "∅"


def test_unknown_account_has_no_user_features_but_keeps_rarity_and_infra():
    f = feats(ev(10 * W_1H, user=None, success=False), [ev(9 * W_1H, user=None, ip="1.1.1.1", success=False)])
    assert math.isnan(f["u_n_attempts"]) and math.isnan(f["new_country"]) and math.isnan(f["llr_sum"])
    assert not math.isnan(f["rare_country"])
    assert f["ip_attempts_24h"] == 1 and f["ip_unknown_attempts_24h"] == 1
    assert f["cur_success"] == 0.0


def test_brand_new_user_is_all_new_with_zero_llr():
    f = feats(ev(1000, user=7), [])
    assert f["u_n_attempts"] == 0 and f["u_n_success"] == 0 and f["u_fail_streak"] == 0
    assert all(f[f"new_{a}"] == 1.0 for a in F.NOVELTY_ATTRS)
    assert f["llr_sum"] == pytest.approx(0.0)  # chưa có lịch sử: p_user = p_global -> không có thông tin
    assert math.isnan(f["u_age_days"]) and math.isnan(f["u_secs_since_last"])


def test_novelty_is_measured_against_successful_history_only():
    prior = [
        ev(100, country="NO", success=True),
        ev(200, country="US", success=False),  # đăng nhập thất bại từ US không làm US thành "quen"
        ev(300, browser="Firefox 80.0", success=True),
    ]
    f = feats(ev(1000, country="US", browser="Firefox 81.0", asn=100), prior)
    assert f["new_country"] == 1.0  # US chỉ xuất hiện ở lần thất bại
    assert f["new_browser"] == 1.0  # Firefox 81.0 chưa từng thành công (chỉ có 80.0)
    assert f["new_browser_family"] == 0.0  # nhưng họ Firefox đã quen
    assert f["new_asn"] == 0.0 and f["new_ip"] == 0.0


def test_llr_is_positive_for_unseen_values_and_negative_for_habitual_ones():
    prior = [ev(i * 100, user=1, country="NO") for i in range(1, 6)]
    prior += [ev(i * 100 + 50, user=2, country="US") for i in range(1, 6)]  # người khác, để global có cả US
    habitual = feats(ev(10_000, user=1, country="NO"), prior)
    unseen = feats(ev(10_000, user=1, country="US"), prior)
    assert habitual["llr_country"] < 0 < unseen["llr_country"]
    assert unseen["rare_country"] == pytest.approx(habitual["rare_country"])  # NO và US đều xuất hiện 5 lần toàn cục


def test_llr_matches_hand_computation():
    prior = [ev(100, user=1, country="NO"), ev(200, user=1, country="NO"), ev(300, user=2, country="US")]
    f = feats(ev(1000, user=1, country="US"), prior)
    p_g = (1 + 1.0) / (3 + 1.0)  # US: 1 lần trong 3 lần thành công toàn cục
    p_u = (0 + 1.0 * p_g) / (2 + 1.0)  # user 1: 0 lần US trong 2 lần thành công
    assert f["llr_country"] == pytest.approx(math.log(p_g) - math.log(p_u))
    assert f["rare_country"] == pytest.approx(-math.log(p_g))


def test_fail_streak_counts_failures_since_last_success():
    prior = [ev(100, success=True), ev(200, success=False), ev(300, success=False)]
    assert feats(ev(400), prior)["u_fail_streak"] == 2
    assert feats(ev(400), prior + [ev(350, success=True)])["u_fail_streak"] == 0
    assert feats(ev(400), [ev(100, success=False), ev(200, success=False)])["u_fail_streak"] == 2


def test_time_windows_are_open_at_the_old_end_and_strictly_before_now():
    t = 30 * W_24H
    prior = [
        ev(t - W_1H, user=1),  # đúng 1h trước: ngoài cửa sổ 1h (mở ở đầu cũ)
        ev(t - W_1H + 1, user=1),  # trong cửa sổ
        ev(t, user=1),  # cùng micro-giây: không tính là "trước đó"
    ]
    f = feats(ev(t, user=1), prior)
    assert f["u_attempts_1h"] == 1
    assert f["u_attempts_24h"] == 2
    assert f["u_n_attempts"] == 2


def test_infra_features_count_only_recent_events_from_the_same_ip_and_asn():
    t = 10 * W_24H
    prior = [
        ev(t - 100, user=1, ip="9.9.9.9", asn=7, success=False, ua="a"),
        ev(t - 200, user=2, ip="9.9.9.9", asn=7, success=False, ua="b"),
        ev(t - 300, user=None, ip="9.9.9.9", asn=7, success=False, ua="b"),
        ev(t - 400, user=3, ip="8.8.8.8", asn=7, success=True, ua="c"),  # cùng ASN, khác IP
        ev(t - 2 * W_24H, user=4, ip="9.9.9.9", asn=7, success=True),  # quá cũ cho cửa sổ 24h
    ]
    f = feats(ev(t, user=5, ip="9.9.9.9", asn=7), prior)
    assert f["ip_attempts_24h"] == 3 and f["ip_attempts_1h"] == 3
    assert f["ip_fail_ratio_24h"] == 1.0
    assert f["ip_distinct_users_24h"] == 2 and f["ip_unknown_attempts_24h"] == 1
    assert f["ip_distinct_ua_24h"] == 2
    assert f["ip_prior_attempts_all"] == 4
    assert f["asn_attempts_24h"] == 4 and f["asn_distinct_ips_24h"] == 2 and f["asn_distinct_users_24h"] == 3
    assert f["asn_fail_ratio_24h"] == pytest.approx(0.75)
    assert f["asn_unknown_share_24h"] == pytest.approx(0.25)


def test_missing_asn_gives_nan_asn_features_and_ratio_is_nan_without_traffic():
    f = feats(ev(1000, asn=None, ip="7.7.7.7"), [])
    assert math.isnan(f["asn_attempts_24h"])
    assert f["ip_attempts_24h"] == 0 and math.isnan(f["ip_fail_ratio_24h"])


def test_device_code_and_missing_values():
    assert feats(ev(1000, device="bot"), [])["cur_device_code"] == 3
    assert feats(ev(1000, device=None), [])["cur_device_code"] == F.DEVICE_CODE_MISSING
    assert feats(ev(1000, device="fridge"), [])["cur_device_code"] == F.DEVICE_CODE_MISSING
