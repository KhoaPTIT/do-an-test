"""MR7 — phân tích lỗi: ATO bị bỏ sót/bắt được, kiểu báo nhầm, giới hạn với Targeted theo khoảng cách thời gian."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import ensemble as En
from ml.rba import errors as Er
from ml.rba import eval_tasks, splits, train
from ml.rba.features import FEATURE_NAMES


def make_world(seed=0, n=18000):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({name: rng.gamma(2.0, 1.0, n) for name in FEATURE_NAMES})
    for name in ("country", "asn", "ip", "ua", "browser", "os", "device", "browser_family", "os_family"):
        df[f"new_{name}"] = (rng.random(n) < 0.04).astype(float)
    df["cur_success"] = (rng.random(n) < 0.85).astype(float)
    df["cur_device_code"] = rng.integers(0, 6, n).astype(float)
    df["u_n_success"] = rng.integers(0, 12, n).astype(float)
    df["u_secs_since_last_success"] = np.exp(rng.uniform(0, np.log(100 * 86400), n))
    df["row_id"] = np.arange(n)
    df["user_id"] = rng.integers(0, 4000, n)
    df["ip"] = [f"ip-{i % 3000}" for i in range(n)]
    df["ts"] = pd.Timestamp("2020-03-01") + pd.to_timedelta(rng.integers(0, 260 * 24 * 3600, n), unit="s")
    df["partition"] = splits.assign_time_split(df["ts"])
    df["is_attack_ip"] = False
    df["is_ato"] = False
    df["in_warmup"] = False
    df["weight"] = 1.0
    return df


def build(seed=0):
    df = make_world(seed)
    legit_test = df[(df["partition"] == "test") & (df["cur_success"] == 1)].index.to_numpy()
    rng = np.random.default_rng(seed + 1)

    # kiểu báo nhầm được cài sẵn: 2% đăng nhập hợp lệ ở test có quốc gia mới và nhà mạng cực hiếm (chỉ ở test, để ngưỡng chọn trên val không bị kéo)
    planted = rng.choice(legit_test, int(0.02 * len(legit_test)), replace=False)
    df.loc[planted, "new_country"] = 1.0
    df.loc[planted, "u_n_success"] = df.loc[planted, "u_n_success"].clip(lower=3)
    df.loc[planted, "rare_asn"] += 14.0
    rest = np.setdiff1d(legit_test, planted)

    # 60 ca ATO trong giai đoạn "tương lai": 25 lộ ở độ hiếm ASN (bat_thuong), 15 ở độ hiếm quốc gia (chiem_tai_khoan), 20 không lộ gì
    picks = rng.choice(rest, 60, replace=False)
    df.loc[picks, ["is_ato", "partition"]] = [True, "ato"]
    df.loc[picks[:25], "rare_asn"] += 15.0
    df.loc[picks[:25], "u_n_success"] = 8.0
    df.loc[picks[25:40], "rare_country"] += 15.0
    df.loc[picks[25:40], "u_n_success"] = 5.0
    df.loc[picks[40:], "u_n_success"] = 0.0  # tài khoản mới, IP bị gắn nhãn tấn công, không lộ gì
    df.loc[picks[40:], "is_attack_ip"] = True
    return eval_tasks.add_population_weights(df)


def make_hybrid(df):
    def column(name):
        return lambda frame: frame[name].to_numpy(dtype=float)

    return train.build_hybrid(
        df,
        [
            ("ip_tan_cong", column("ip_distinct_users_24h"), None),
            ("chiem_tai_khoan", column("rare_country"), En.gate_success_with_history),
            ("bat_thuong", column("rare_asn"), En.gate_success),
        ],
    )


@pytest.fixture(scope="module")
def world():
    df = build()
    hybrid = make_hybrid(df)
    return df, hybrid, Er.thresholds(hybrid, df, with_history=False), Er.thresholds(hybrid, df, with_history=True)


def test_buckets_are_half_open_and_treat_missing_as_infinite():
    labels = Er._bucket(np.array([0, 1, 4, 5, 200, np.nan]), Er.HISTORY_BUCKETS)
    assert list(labels) == ["chưa có lịch sử", "mỏng (1–4)", "mỏng (1–4)", "dày (≥ 5)", "dày (≥ 5)", "dày (≥ 5)"]
    gaps = Er._bucket(np.array([0, 59, 60, 3599, 3600, 40 * 86400, np.nan]), Er.GAP_BUCKETS)
    assert list(gaps) == ["< 1 phút", "< 1 phút", "1–10 phút", "10 phút–1 giờ", "1–24 giờ", "> 30 ngày", "> 30 ngày"]


def test_thresholds_give_the_requested_false_alert_rate_on_validation(world):
    df, hybrid, tau_all, tau_history = world
    for tau, with_history in ((tau_all, False), (tau_history, True)):
        frame = Er.analysis._val_legit_success_task(df, with_history=with_history).frame
        score = Er._score_from_tails(Er._hybrid_parts(hybrid, frame)[1])
        w = frame["pop_weight"].to_numpy()
        for target, value in tau.items():
            assert w[score > value].sum() / w.sum() == pytest.approx(target, abs=target * 0.5 + 0.002)
    assert tau_all[0.001] > tau_all[0.01]  # FPR nhỏ hơn -> ngưỡng cao hơn


def test_ato_cases_report_which_component_caught_each_case_and_who_was_missed(world):
    df, hybrid, tau_all, _ = world
    cases = Er.ato_case_table(df, hybrid, tau_all)
    assert len(cases) == 60 and cases["ts"].is_monotonic_increasing
    caught = cases[cases["bat_0.01"]]
    assert set(caught["thanh_phan_bao"]) <= {"bat_thuong", "chiem_tai_khoan"}
    assert (caught["thanh_phan_bao"] == "bat_thuong").sum() >= 20 and (caught["thanh_phan_bao"] == "chiem_tai_khoan").sum() >= 12
    missed = cases[~cases["bat_0.01"]]
    assert len(missed) >= 15 and missed["ip_bi_gan_nhan"].mean() > 0.8 and (missed["lich_su"] == "chưa có lịch sử").mean() > 0.8
    assert cases["bat_0.001"].sum() <= cases["bat_0.01"].sum()  # ngưỡng chặt hơn không thể bắt nhiều hơn

    segments = {r["lat_cat"]: r for r in Er.ato_segments(cases)}
    assert segments["tất cả (60 ca)"]["n"] == 60 and segments["tất cả (60 ca)"]["bat_duoc"] == len(caught)
    cold, dense = segments["lịch sử: chưa có lịch sử"], segments["lịch sử: dày (≥ 5)"]
    assert cold["recall"] < 0.1 and dense["recall"] > 0.6  # tài khoản mới không bắt được; tài khoản dày bắt được
    assert segments["IP bị gắn nhãn tấn công"]["recall"] < 0.1 and segments["IP không gắn nhãn"]["recall"] > 0.6
    assert sum(segments["tất cả (60 ca)"]["theo_thanh_phan"].values()) == segments["tất cả (60 ca)"]["bat_duoc"]
    profile = Er.ato_profile(cases)
    assert profile.loc["rare_asn", "bắt được"] > profile.loc["rare_asn", "bỏ sót"] and profile.loc["số ca"].sum() == 60
    text = Er.profile_markdown(profile)
    assert "| `rare_asn` |" in text and "| `số ca` |" in text and "bắt được" in text and "bỏ sót" in text


def test_false_alert_archetypes_share_sums_and_show_the_planted_pattern(world):
    df, hybrid, tau_all, _ = world
    result = Er.false_alert_archetypes(df, hybrid, tau_all[0.01])
    rows = {r["kieu"]: r for r in result["kieu"]}
    assert sum(r["ty_le_dang_nhap"] for r in rows.values()) == pytest.approx(1.0)
    assert sum(r["ty_le_trong_bao_nham"] for r in rows.values()) == pytest.approx(1.0)
    planted = rows["quoc_gia_hoac_mang_moi"]
    assert planted["ty_le_trong_bao_nham"] > 0.5 and planted["gap_may_lan"] > 3  # kiểu cài sẵn chiếm phần lớn báo nhầm, gấp nhiều lần mức chung
    assert planted["theo_thanh_phan"]["bat_thuong"] > 0.8  # do đúng thành phần độ hiếm nhà mạng
    examples = result["vi_du"]["quoc_gia_hoac_mang_moi"]
    assert 0 < len(examples) <= 3 and examples[0]["diem"] >= examples[-1]["diem"]
    assert all(e["diem"] > tau_all[0.01] for e in examples)  # ví dụ luôn là ca THẬT SỰ bị báo (điểm trên ngưỡng)
    assert all(e["thanh_phan_bao"] in ("bat_thuong", "chiem_tai_khoan") for e in examples)  # hoà ở mức sàn xác suất thì lấy thành phần đứng trước
    assert result["fpr_thuc_te"] > 0.01  # cài sẵn 2% ở test nên báo nhầm thực tế vượt mục tiêu


def test_archetype_priority_is_first_match_and_covers_every_row():
    frame = make_world(seed=3, n=500)
    frame["u_n_success"] = 0.0
    frame["new_country"] = 1.0  # vừa "chưa có lịch sử" vừa "quốc gia mới": kiểu đứng trước thắng
    assert set(Er.assign_archetype(frame)) == {"moi_tai_khoan"}
    frame["u_n_success"] = 5.0
    assert set(Er.assign_archetype(frame)) == {"quoc_gia_hoac_mang_moi"}
    frame["new_country"], frame["new_asn"] = 0.0, 0.0
    frame["ip_distinct_users_24h"], frame["ip_fail_ratio_24h"] = 0.0, 0.0
    frame["new_ua"], frame["new_ip"] = 0.0, 0.0
    assert set(Er.assign_archetype(frame)) == {"khac"}


def test_targeted_limits_show_detection_only_when_the_ip_change_is_close_to_the_last_login(world):
    df, hybrid, _, tau_history = world
    rng = np.random.default_rng(9)
    pool = df[(df["partition"] == "test") & (df["cur_success"] == 1) & (df["u_n_success"] >= 1)].sample(1800, random_state=2).copy()
    pool["row_id"] = 10**9 + np.arange(len(pool))
    pool["attacker_type"] = ["naive", "vpn", "targeted"] * 600
    pool["partition"] = "attacker"
    pool["is_attack_ip"] = False
    short = pool["u_secs_since_last_success"] < 3600
    pool.loc[(pool["attacker_type"] == "targeted") & short, "ip_distinct_users_24h"] += 15.0  # Targeted chỉ lộ khi IP mới xuất hiện sát lần trước
    pool.loc[pool["attacker_type"] == "naive", "rare_country"] += 15.0  # Naive lộ ở mọi khoảng cách

    result = Er.targeted_limits(df, hybrid, pool, tau_history)
    by_gap = {r["lat_cat"]: r for r in result["kieu"]["targeted"]["khoang_cach"]}
    near = [by_gap[k] for k in ("< 1 phút", "1–10 phút", "10 phút–1 giờ") if k in by_gap]
    far = [by_gap[k] for k in ("7–30 ngày", "> 30 ngày") if k in by_gap]
    assert near and far
    assert all(r["recall_0.01"] > 0.8 for r in near) and all(r["recall_0.01"] < 0.2 for r in far)
    naive = result["kieu"]["naive"]["khoang_cach"]
    assert all(r["recall_0.01"] > 0.8 for r in naive)
    for kind in result["kieu"].values():
        for rows in kind.values():
            for r in rows:
                assert r["recall_0.001"] <= r["recall_0.01"] + 1e-9 and 0 <= r["bao_nham_0.01"] <= 1
    assert {r["lat_cat"] for r in result["kieu"]["targeted"]["lich_su"]} <= {"mỏng (1–4)", "dày (≥ 5)"}


def test_markdown_renderers_contain_labels_and_numbers(world):
    df, hybrid, tau_all, tau_history = world
    cases = Er.ato_case_table(df, hybrid, tau_all)
    text = Er.segments_markdown(Er.ato_segments(cases))
    assert "tất cả (60 ca)" in text and "Do `bat_thuong`" in text and "%" in text
    archetypes = Er.archetypes_markdown(Er.false_alert_archetypes(df, hybrid, tau_all[0.01]))
    assert "Quốc gia hoặc nhà mạng mới" in archetypes and "×" in archetypes
    pool = df[(df["partition"] == "test") & (df["cur_success"] == 1) & (df["u_n_success"] >= 1)].sample(300, random_state=4).copy()
    pool["row_id"] = 10**9 + np.arange(len(pool))
    pool["attacker_type"] = "targeted"
    limits = Er.limits_markdown(Er.targeted_limits(df, hybrid, pool, tau_history))
    assert "Bắt được @FPR 1.0%" in limits and "Bắt được @FPR 0.1%" in limits


def test_single_feature_rules_recover_the_planted_signal_and_report_by_history(world):
    df, _, _, _ = world
    result = Er.single_feature_rules(df)
    rows = {(r["bai"], r["luat"]): r for r in result["rows"]}
    asn = rows[("ato/future", "rare_asn")]
    assert asn["so_ca"] == 60 and asn["roc_auc"] > 0.65 and asn["recall@fpr=0.01"] > 0.3  # 25 trong 60 ca lộ ở độ hiếm nhà mạng (AUC ≈ 25/60 + 0,5·35/60)
    assert rows[("ato/future", "rare_ip")]["roc_auc"] < 0.65  # đặc trưng không mang tín hiệu thì gần ngẫu nhiên
    assert result["rare_asn_trung_vi_ato_future"] > 0 and result["rare_asn_phan_vi_hop_le"]["0.99"] > result["rare_asn_phan_vi_hop_le"]["0.5"]
    assert set(asn["theo_lich_su"]) == {"chưa có lịch sử thành công", "mỏng (1–4)", "dày (≥5)"}
    text = Er.single_rules_markdown(result)
    assert "`rare_asn + rare_country`" in text and "Chưa có lịch sử" in text and "ato/all" in text


def test_legit_new_ip_rate_follows_the_gap_and_shares_sum_to_one():
    df = make_world(seed=5, n=20000)
    df["new_ip"] = (np.random.default_rng(1).random(len(df)) < np.clip(np.log10(df["u_secs_since_last_success"]) / 8, 0, 1)).astype(float)  # IP mới hiếm khi vừa đăng nhập, nhiều khi cách lâu
    df["u_n_success"] = 3.0
    rows = Er.legit_new_ip_by_gap(eval_tasks.add_population_weights(df))
    assert [r["lat_cat"] for r in rows] == [g[0] for g in Er.GAP_BUCKETS if g[0] in {r["lat_cat"] for r in rows}]
    assert sum(r["ty_le_dang_nhap"] for r in rows) == pytest.approx(1.0)
    rates = [r["ty_le_ip_moi"] for r in rows]
    assert rates == sorted(rates) and rates[-1] > rates[0] + 0.3  # cách càng lâu càng hay đổi IP
    assert "% dùng IP mới" in Er.new_ip_markdown(rows) and rows[0]["lat_cat"] in Er.new_ip_markdown(rows)
