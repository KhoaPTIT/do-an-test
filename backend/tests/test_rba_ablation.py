"""MR7 — ablation theo nhóm đặc trưng: cấu hình đúng, và phép đo tìm ra đúng nhóm mang tín hiệu."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import ablation as Ab
from ml.rba import eval_tasks, splits
from ml.rba.features import FEATURE_GROUPS, FEATURE_NAMES


def make_world(n=9000, seed=0, n_ato=60):
    """Dòng tấn công và ATO chỉ khác đăng nhập thường ở nhóm `rarity` (rare_asn, rare_country)."""
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({name: rng.gamma(2.0, 1.0, n) for name in FEATURE_NAMES})
    for name in [f"new_{a}" for a in ("country", "asn", "ip", "ua", "browser", "os", "device", "browser_family", "os_family")] + ["cur_success"]:
        df[name] = (rng.random(n) < 0.7).astype(float)
    df["cur_device_code"] = rng.integers(0, 6, n).astype(float)
    df["u_n_success"] = rng.integers(0, 12, n).astype(float)
    df["row_id"] = np.arange(n)
    df["user_id"] = rng.integers(0, 3000, n)
    df["ip"] = [f"ip-{i % 2500}" for i in range(n)]
    df["ts"] = pd.Timestamp("2020-03-01") + pd.to_timedelta(rng.integers(0, 260 * 24 * 3600, n), unit="s")
    df["partition"] = splits.assign_time_split(df["ts"])
    df["is_attack_ip"] = rng.random(n) < 0.10
    df["is_ato"] = False
    df["in_warmup"] = False
    df["weight"] = 1.0
    for column in ("rare_asn", "rare_country"):
        df.loc[df["is_attack_ip"], column] += 8.0

    future = df[(df["partition"] == "test") & ~df["is_attack_ip"] & (df["cur_success"] == 1)].sample(n_ato, random_state=1).index
    df.loc[future, ["is_ato", "partition"]] = [True, "ato"]
    for column in ("rare_asn", "rare_country"):
        df.loc[future, column] += 20.0
    return eval_tasks.add_population_weights(df)


@pytest.fixture(scope="module")
def world():
    return make_world()


def test_feature_configs_drop_or_keep_exactly_one_group_and_the_top_features():
    configs = Ab.feature_configs(["rare_asn", "u_fail_streak", "llr_ip"])
    assert len(configs) == 1 + 2 * len(FEATURE_GROUPS) + 2 and configs["tat_ca"] == list(FEATURE_NAMES)
    for group, members in FEATURE_GROUPS.items():
        assert set(configs[f"chi:{group}"]) == set(members) and len(configs[f"chi:{group}"]) == len(members)
        assert set(configs[f"bo:{group}"]) == set(FEATURE_NAMES) - set(members)
        assert len(configs[f"bo:{group}"]) + len(members) == len(FEATURE_NAMES)
    assert configs["bo_top1"] == [f for f in FEATURE_NAMES if f != "rare_asn"]
    assert set(FEATURE_NAMES) - set(configs["bo_top3"]) == {"rare_asn", "u_fail_streak", "llr_ip"}
    assert list(Ab.feature_configs()) == [k for k in configs if k not in ("bo_top1", "bo_top3")]  # không có top thì không có hai cấu hình đó
    for features in configs.values():  # thứ tự đặc trưng luôn theo FEATURE_NAMES
        assert features == [f for f in FEATURE_NAMES if f in features]


def test_gbm_ablation_finds_the_group_that_carries_the_attack_signal(world):
    result = Ab.run_gbm_ablation("attack_ip", world, None, None, n_boot=10, rounds=60, log=lambda m: None)
    rows = {r["config"]: r for r in result["rows"]}
    recall = lambda name: rows[name]["results"]["attack_ip/test"]["recall@fpr=0.01"]["value"]
    assert len(rows) == 1 + 2 * len(FEATURE_GROUPS) + 2 and result["top_features"][0] in ("rare_asn", "rare_country")
    assert recall("tat_ca") > 0.8 and recall("chi:rarity") > 0.8  # tín hiệu nằm ở nhóm độ hiếm và một mình nó đủ
    assert recall("bo:rarity") < 0.2 and recall("chi:cur") < 0.2 and recall("chi:history") < 0.2  # bỏ nó hoặc chỉ dùng nhóm khác thì mất
    assert recall("bo:infra_ip") > 0.8 and recall("bo:cur") > 0.8  # bỏ nhóm không liên quan không đổi
    assert recall("bo_top1") > 0.8  # còn đặc trưng thứ hai cùng nhóm nên không phụ thuộc MỘT đặc trưng
    assert recall("bo_top3") < recall("tat_ca")  # nhưng bỏ cả ba đặc trưng đầu (đủ cả hai của nhóm) thì mất
    assert rows["tat_ca"]["removed"] == [] and set(rows["bo:rarity"]["removed"]) == set(FEATURE_GROUPS["rarity"]) and rows["chi:rarity"]["removed"] is None


def test_isolation_forest_ablation_shows_which_group_makes_it_catch_the_takeovers(world):
    result = Ab.run_if_ablation(world, n_boot=20, log=lambda m: None)
    rows = {r["config"]: r for r in result["rows"]}
    auc = lambda name: rows[name]["results"]["ato/future"]["roc_auc"]["value"]
    assert set(rows) == set(Ab.feature_configs()) and result["tasks"] == ["ato/future", "ato/all"]
    assert auc("chi:rarity") > 0.95  # ATO khác thường ở đúng nhóm độ hiếm
    assert auc("bo:rarity") < 0.7  # bỏ nhóm ấy thì Isolation Forest không còn thấy gì
    assert auc("chi:rarity") > auc("tat_ca") > auc("bo:rarity") - 0.05  # thêm nhiều chiều không liên quan làm loãng tín hiệu


def test_ablation_markdown_reports_changes_against_the_control_row(world):
    result = Ab.run_gbm_ablation("attack_ip", world, None, None, n_boot=10, rounds=40, log=lambda m: None)
    text = Ab.ablation_markdown(result)
    assert "tất cả (đối chứng)" in text and "bỏ nhóm `rarity`" in text and "chỉ nhóm `rarity`" in text
    assert "bỏ đặc trưng quan trọng nhất" in text and "(+0.0)" in text  # đối chứng so với chính nó
    assert "0.0" in Ab.ablation_markdown(result, "roc_auc") and "(" in Ab.ablation_markdown(result, "roc_auc")


def test_extra_configs_select_the_intended_groups_and_only_configs_runs_just_those(world):
    cfg = Ab.EXTRA_SIM_CONFIGS
    assert set(cfg["chi_quan_he_voi_lich_su"]) == set().union(*(FEATURE_GROUPS[g] for g in ("novelty", "freeman", "rhythm", "history")))
    assert set(cfg["bo:rarity+infra_asn"]) == set(FEATURE_NAMES) - set(FEATURE_GROUPS["rarity"]) - set(FEATURE_GROUPS["infra_asn"])
    assert set(cfg["bo:rarity+infra_asn+infra_ip"]) == set(cfg["bo:rarity+infra_asn"]) - set(FEATURE_GROUPS["infra_ip"])
    result = Ab.run_gbm_ablation("attack_ip", world, None, None, n_boot=10, rounds=40, log=lambda m: None, only_configs={"bo:rarity+infra_asn": cfg["bo:rarity+infra_asn"]})
    assert [r["config"] for r in result["rows"]] == ["tat_ca", "bo:rarity+infra_asn"]
    assert "bỏ nhóm `rarity` + `infra_asn`" in Ab.ablation_markdown(result)
    assert "chỉ các nhóm quan hệ với lịch sử" in Ab.config_label("chi_quan_he_voi_lich_su")
