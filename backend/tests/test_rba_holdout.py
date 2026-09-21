"""MR7 — giấu từng họ tấn công khỏi huấn luyện: định nghĩa họ, không rò rỉ, và số đo phản ánh đúng "chưa thấy"."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import eval_tasks, models, splits, train
from ml.rba import holdout as H
from ml.rba.features import FEATURE_NAMES, RBA_CATCHALL_USER_ID

TEST_FAMILIES = (H.FAMILY_BY_KEY["it_luot"], H.FAMILY_BY_KEY["rai_rong"])


def make_world(n=14000, seed=0):
    """Hai họ tấn công với tín hiệu RIÊNG: `it_luot` chỉ lộ ở `rare_asn`, `rai_rong` chỉ lộ ở `ip_distinct_users_24h`."""
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({name: rng.gamma(2.0, 1.0, n) for name in FEATURE_NAMES})
    for name in [f"new_{a}" for a in ("country", "asn", "ip", "ua", "browser", "os", "device", "browser_family", "os_family")] + ["cur_success"]:
        df[name] = (rng.random(n) < 0.6).astype(float)
    df["cur_device_code"] = rng.integers(0, 6, n).astype(float)
    df["u_n_success"] = rng.integers(0, 12, n).astype(float)
    df["row_id"] = np.arange(n)
    df["user_id"] = rng.integers(0, 2000, n)
    df["ts"] = pd.Timestamp("2020-03-01") + pd.to_timedelta(rng.integers(0, 260 * 24 * 3600, n), unit="s")
    df["partition"] = splits.assign_time_split(df["ts"])
    df["is_attack_ip"] = rng.random(n) < 0.10
    df["is_ato"] = False
    df["in_warmup"] = False
    df["weight"] = np.where(df["is_attack_ip"], 4.0, 1.0)

    df["ip"] = [f"legit-{i % 3000}" for i in range(n)]
    attack = df["is_attack_ip"].to_numpy()
    kind = rng.integers(0, 2, n)  # 0: chậm và ít, 1: rải rộng
    slow_ip = [f"slow-{i}" for i in range(80)]
    wide_ip = [f"wide-{i}" for i in range(80)]
    df.loc[attack, "ip"] = [slow_ip[rng.integers(0, 80)] if k == 0 else wide_ip[rng.integers(0, 80)] for k in kind[attack]]
    df.loc[attack & (kind == 0), "rare_asn"] += 6.0
    df.loc[attack & (kind == 1), "ip_distinct_users_24h"] += 10.0

    df["asn"] = rng.choice([100, 200, 300], n)
    df["country"] = rng.choice(["NO", "US", "PL"], n)
    df["device_type"] = rng.choice(["mobile", "desktop"], n)
    stats = pd.DataFrame(
        {
            "ip": slow_ip + wide_ip,
            "attempts": [rng.integers(1, 11) for _ in slow_ip] + [rng.integers(60, 400) for _ in wide_ip],
            "successes": rng.integers(0, 5, 160),
            "users": [rng.integers(0, 4) for _ in slow_ip] + [rng.integers(35, 200) for _ in wide_ip],
        }
    )

    donors = df[df["partition"].isin(["train", "val"]) & ~df["is_attack_ip"] & (df["cur_success"] == 1)].sample(1500, random_state=1).copy()
    donors["row_id"] = 10**9 + np.arange(len(donors))
    donors["period"] = np.where(donors["partition"] == "train", "train", "val")
    donors["attacker_type"] = rng.choice(["naive", "vpn", "targeted"], len(donors))
    donors["partition"] = "attacker"
    donors["is_attack_ip"] = False
    donors["pop_weight"] = 1.0
    donors.loc[donors["attacker_type"] == "naive", "rare_country"] += 6.0  # mỗi kiểu chỉ lộ ở MỘT đặc trưng
    donors.loc[donors["attacker_type"] == "vpn", "llr_ip"] += 9.0
    donors.loc[donors["attacker_type"] == "targeted", "u_fail_streak"] += 9.0
    return eval_tasks.add_population_weights(df), donors, stats


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    out = tmp_path_factory.mktemp("mr7")
    saved = (models.ARTIFACT_DIR, dict(models.DEFAULT_GBM_PARAMS))
    models.ARTIFACT_DIR = out
    models.DEFAULT_GBM_PARAMS.update({"min_data_in_leaf": 20, "num_leaves": 15, "num_threads": 2})
    try:
        df, attackers, stats = make_world()
        train.train_all(df, attackers, quick=True)  # sinh hybrid.joblib, knn_distance.joblib... vào thư mục tạm
        yield H.add_family_columns(df, stats), attackers, stats
    finally:
        models.ARTIFACT_DIR, models.DEFAULT_GBM_PARAMS = saved[0], saved[1]


def test_family_rules_use_ip_statistics_and_attributes_and_only_mark_attack_rows(world):
    df, _, stats = world
    lookup = stats.set_index("ip")
    attack = df[df["is_attack_ip"]]
    assert not df.loc[~df["is_attack_ip"], [f"fam_{f.key}" for f in H.FAMILIES]].to_numpy().any()  # dòng hợp lệ không thuộc họ nào
    assert (attack["fam_it_luot"] == (lookup.loc[attack["ip"], "attempts"].to_numpy() <= 10)).all()
    assert (attack["fam_rai_rong"] == (lookup.loc[attack["ip"], "users"].to_numpy() > 30)).all()
    assert (attack["fam_ngoai_my"] == (attack["country"] != "US")).all()
    assert (attack["fam_may_tinh"] == attack["device_type"].isin(["desktop", "tablet"])).all()
    tail = attack[["fam_mang_duoi_0", "fam_mang_duoi_1", "fam_mang_duoi_2"]].to_numpy().sum(axis=1)
    assert (tail == 1).all()  # mọi ASN (khác mạng chiếm ưu thế) rơi đúng một nhóm đuôi
    assert attack["fam_it_luot"].any() and attack["fam_rai_rong"].any() and not (attack["fam_it_luot"] & attack["fam_rai_rong"]).any()


def test_training_sets_without_a_family_drop_exactly_its_rows_from_train_and_val(world):
    df, _, _ = world
    train_full, val_full = models.attack_ip_sets(df)
    train_set, val_set = H.attack_ip_sets_without(df, "it_luot")
    for full, cut in ((train_full, train_set), (val_full, val_set)):
        frame_full, y_full, _ = full
        frame_cut, y_cut, w_cut = cut
        removed = frame_full["fam_it_luot"].to_numpy()
        assert removed.sum() > 0
        assert len(frame_cut) == len(frame_full) - removed.sum() and len(y_cut) == len(w_cut) == len(frame_cut)
        assert not frame_cut["fam_it_luot"].any()  # không còn dòng nào của họ
        assert y_cut.sum() == y_full.sum() - y_full[removed].sum()  # chỉ mất dương tính của họ đó
        assert set(frame_cut["row_id"]) == set(frame_full.loc[~removed, "row_id"])  # âm tính và họ khác giữ nguyên


@pytest.fixture(scope="module")
def experiments(world):
    """Chạy hai loạt thí nghiệm một lần cho mọi test bên dưới (n_boot và số vòng nhỏ để nhanh)."""
    df, attackers, _ = world
    attack_ip = H.run_attack_ip_holdout(df, families=TEST_FAMILIES, n_boot=20, rounds=80, log=lambda m: None)
    sim = H.run_sim_holdout(df, attackers, attackers.assign(row_id=attackers["row_id"] + 7), n_boot=20, rounds=80, log=lambda m: None)
    return attack_ip, sim


def test_hidden_family_is_missed_while_the_same_model_family_seen_is_caught(experiments):
    result, _ = experiments
    by_key = {f["key"]: f for f in result["families"]}
    assert set(by_key) == {"it_luot", "rai_rong"}
    for key, fam in by_key.items():
        seen = fam["results"]["gbm_attack_ip (đã thấy họ)"]["recall@fpr=0.01"]["value"]
        unseen = fam["results"]["gbm_attack_ip (chưa thấy họ)"]["recall@fpr=0.01"]["value"]
        assert seen > 0.4, (key, seen)  # tín hiệu riêng của họ đủ để mô hình đã thấy bắt được
        assert unseen < seen - 0.2, (key, seen, unseen)  # giấu họ thì mô hình chỉ còn tín hiệu của họ kia, không bắt được
        assert fam["train_rows_removed"] > 0 and 0 < fam["train_share_removed"] < 1
        assert fam["test_rows"] > 20 and fam["test_ips"] > 5
        for scorer, entry in fam["results"].items():  # cấu trúc số đo và khoảng tin cậy hợp lệ
            for metric in H.METRIC_KEYS:
                value, (lo, hi) = entry[metric]["value"], entry[metric]["ci95"]
                assert 0.0 <= value <= 1.0 and lo <= hi, (scorer, metric)
    assert {"tier2_current", "freeman_all", "isolation_forest", "knn_distance", "rules_tuned (không có họ)",
            "hybrid (đã thấy họ)", "hybrid (chưa thấy họ)"} <= set(by_key["it_luot"]["results"])
    hidden_hybrid = by_key["it_luot"]["results"]["hybrid (chưa thấy họ)"]["recall@fpr=0.01"]["value"]
    seen_hybrid = by_key["it_luot"]["results"]["hybrid (đã thấy họ)"]["recall@fpr=0.01"]["value"]
    assert hidden_hybrid <= seen_hybrid + 1e-9  # giấu họ không thể làm hybrid bắt được NHIỀU hơn (Isolation Forest vẫn đứng đó)


def test_hidden_attacker_style_is_missed_by_the_supervised_model_only_for_that_style(experiments):
    _, result = experiments
    by_variant = {v["variant"]: v for v in result["variants"]}
    assert set(by_variant) == set(H.SIM_VARIANTS)
    for variant, dropped in H.SIM_VARIANTS.items():
        entry = by_variant[variant]
        assert entry["dropped"] == list(dropped) and set(entry["trained_on"]) == set(H.SIM_TYPES) - set(dropped)
        for kind in H.SIM_TYPES:
            assert entry["per_type"][kind]["seen_in_training"] == (kind not in dropped)
    only_vpn_hidden = by_variant["khong_vpn"]["per_type"]
    seen_naive = only_vpn_hidden["naive"]["results"]["gbm_attacker_sim (mô hình này)"]["recall@fpr=0.01"]["value"]
    hidden_vpn = only_vpn_hidden["vpn"]["results"]["gbm_attacker_sim (chưa thấy kiểu)"]["recall@fpr=0.01"]["value"]
    full_vpn = only_vpn_hidden["vpn"]["results"]["gbm_attacker_sim (đã thấy kiểu)"]["recall@fpr=0.01"]["value"]
    assert seen_naive > 0.4 and full_vpn > 0.4  # kiểu còn được học và mô hình đầy đủ đều bắt được
    assert hidden_vpn < full_vpn - 0.2  # giấu VPN thì mất khả năng bắt VPN (tín hiệu của VPN là riêng)


def test_markdown_tables_list_every_family_variant_and_scorer(experiments):
    attack_ip, sim = experiments
    text = H.attack_ip_markdown(attack_ip)
    assert "Chậm và ít" in text and "Rải rộng" in text and "`gbm_attack_ip (chưa thấy họ)`" in text and "%" in text
    text = H.sim_markdown(sim)
    assert "**targeted** (chưa thấy)" in text and "vpn + targeted" in text and "`hybrid (chưa thấy kiểu)`" in text


def test_attack_ip_statistics_count_attempts_successes_and_real_accounts_only(tmp_path):
    full = pd.DataFrame(
        {
            "ip": ["a", "a", "a", "a", "b", "b", "c", "a"],
            "user_id": [1, 1, 2, RBA_CATCHALL_USER_ID, 3, 3, 4, 5],
            "success": [True, False, False, False, True, True, True, True],
            "is_attack_ip": [True, True, True, True, True, True, False, True],
            "is_ato": [False, False, False, False, False, False, False, True],  # ATO không tính
        }
    )
    path = tmp_path / "full.parquet"
    full.to_parquet(path)
    stats = H.build_attack_ip_stats(path, out_path=None).set_index("ip")
    assert set(stats.index) == {"a", "b"}  # IP không phải tấn công bị bỏ
    assert dict(stats.loc["a"]) == {"attempts": 4, "successes": 1, "users": 2}  # "thùng chứa" và dòng ATO không tính
    assert dict(stats.loc["b"]) == {"attempts": 2, "successes": 2, "users": 1}


def test_feature_variants_remove_the_signal_that_lives_in_the_dropped_group(world):
    from ml.rba.features import FEATURE_GROUPS

    df, _, _ = world
    variants = {"bỏ độ hiếm": H._without_groups("rarity"), "chỉ độ hiếm": list(FEATURE_GROUPS["rarity"])}
    result = H.run_attack_ip_variant_holdout(df, variants=variants, families=TEST_FAMILIES, n_boot=10, rounds=60, log=lambda m: None)
    by_key = {f["key"]: f["results"] for f in result["families"]}
    recall = lambda key, name: by_key[key][name]["recall@fpr=0.01"]["value"]
    assert result["variants"] == {"bỏ độ hiếm": len(H._without_groups("rarity")), "chỉ độ hiếm": len(FEATURE_GROUPS["rarity"])}
    assert recall("it_luot", "chỉ độ hiếm (đã thấy họ)") > 0.4 and recall("it_luot", "bỏ độ hiếm (đã thấy họ)") < 0.2  # tín hiệu it_luot nằm ở độ hiếm
    assert recall("rai_rong", "bỏ độ hiếm (đã thấy họ)") > 0.4 and recall("rai_rong", "chỉ độ hiếm (đã thấy họ)") < 0.2  # còn rai_rong nằm ở hạ tầng IP
    assert recall("it_luot", "chỉ độ hiếm (chưa thấy họ)") < 0.2 and recall("rai_rong", "bỏ độ hiếm (chưa thấy họ)") < 0.2  # giấu họ thì mất cả ở biến thể
    assert set(H._without_groups("rarity")) | set(FEATURE_GROUPS["rarity"]) == set(FEATURE_NAMES)
    text = H.variants_markdown(result)
    assert "bỏ độ hiếm (" in text and "chỉ độ hiếm (" in text and "→" in text and "Chậm và ít" in text
