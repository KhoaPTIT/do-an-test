"""MR10 — báo cáo tinh chỉnh: chọn bậc chỉ trên train, các bộ luật gộp, ngân sách đơn điệu, định dạng tài liệu và hồ sơ cấu hình."""

import json

import numpy as np
import pandas as pd
import pytest

from app.detection.engine import REGISTRY, RuleConfig
from ml.rba import rule_tuning as RT
from ml.rba import rule_tuning_report as RP
from ml.rba.rule_tuning import LADDERS


def synthetic_frame(n: int = 6_000, seed: int = 0) -> pd.DataFrame:
    """Khung như `load_frame`: dòng bình thường được luật khớp thưa và ở bậc thấp, dòng tấn công khớp nhiều hơn và ở bậc cao hơn; thêm 12 ca ATO (8 quá khứ, 4 tương lai)."""
    rng = np.random.default_rng(seed)
    partition = rng.choice(["train", "val", "test", "late"], size=n, p=[0.5, 0.15, 0.2, 0.15])
    attack = rng.random(n) < 0.08
    df = pd.DataFrame({
        "partition": partition, "is_attack_ip": attack, "is_ato": False, "cur_success": (rng.random(n) < 0.6).astype(int), "pop_weight": rng.choice([1.0, 4.0, 10.0], n),
        "ip": rng.integers(0, 300, n).astype(str), "in_warmup": False, "ts": pd.Timestamp("2020-05-01"), "user_id": rng.integers(0, 900, n),
    })
    ato = pd.DataFrame({
        "partition": "ato", "is_attack_ip": False, "is_ato": True, "cur_success": 1, "pop_weight": 1.0, "ip": [f"ato{i}" for i in range(12)], "in_warmup": False,
        "ts": [pd.Timestamp("2020-03-01")] * 8 + [pd.Timestamp("2020-10-01")] * 4, "user_id": np.arange(10_000, 10_012),
    })
    df = pd.concat([df, ato], ignore_index=True)
    is_attack = df["is_attack_ip"].to_numpy() | df["is_ato"].to_numpy()
    for ladder in LADDERS:
        level = np.zeros(len(df), dtype=np.uint8)
        alive = rng.random(len(df)) < np.where(is_attack, 0.7, 0.35)  # xác suất khớp ở bậc lỏng nhất
        level[alive] = 1
        for rung in range(2, len(ladder.rungs) + 1):  # mỗi bậc chặt hơn giữ lại 55% (dòng tấn công 80%): các lần khớp lồng nhau
            alive &= rng.random(len(df)) < np.where(is_attack, 0.8, 0.55)
            level[alive] = rung
        df[ladder.column] = level
    return df


@pytest.fixture(scope="module")
def frame():
    return synthetic_frame()


@pytest.fixture(scope="module")
def payload(frame):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(RP, "CI_BOOT", 20)
        return RP.build_payload(frame)


def test_every_ladder_gets_a_row_per_rung_and_partition(payload):
    assert set(payload["ladders"]) == {l.name for l in LADDERS}
    for ladder in LADDERS:
        entry = payload["ladders"][ladder.name]
        assert len(entry["rungs"]) == len(ladder.rungs)
        for row in entry["rungs"]:
            assert set(RT.PARTITIONS) <= set(row) and set(row["ato"]) == {"past", "future", "all"} and row["train"]["fa10k"] >= 0
        fa = [row["train"]["fa10k"] for row in entry["rungs"]]
        assert all(a >= b - 1e-9 for a, b in zip(fa, fa[1:])), f"{ladder.name}: bậc chặt hơn không được báo nhầm nhiều hơn"  # lồng nhau -> đơn điệu


def _independent_fa(frame, part, column, rung):
    rows = frame[(frame["partition"] == part) & ~frame["in_warmup"]]
    w, attack, success = rows["pop_weight"].to_numpy(), rows["is_attack_ip"].to_numpy(), rows["cur_success"].to_numpy() == 1
    return w[(rows[column].to_numpy() >= rung) & ~attack].sum() / w[~attack & success].sum() * 10_000


def test_both_procedures_are_recomputed_independently(frame, payload):
    for ladder in LADDERS:
        only = next((r for r in range(1, len(ladder.rungs) + 1) if _independent_fa(frame, "train", ladder.column, r) <= RT.PRIMARY_BUDGET), None)
        both = next((r for r in range(1, len(ladder.rungs) + 1) if max(_independent_fa(frame, p, ladder.column, r) for p in ("train", "val")) <= RT.PRIMARY_BUDGET), None)
        selected = payload["ladders"][ladder.name]["selected"]
        assert selected["train_only"][str(RT.PRIMARY_BUDGET)] == only and selected["train_val"][str(RT.PRIMARY_BUDGET)] == both, ladder.name
        assert both is None or only is None or both >= only  # thêm điều kiện không bao giờ làm bậc LỎNG hơn


def test_selection_never_looks_at_test_late_or_ato_and_the_original_procedure_not_even_at_val(frame):
    """Xoá cờ ở phân vùng khác không được làm đổi bậc chọn: quy trình đặt trước chỉ dùng train, quy trình sửa chỉ dùng train và val; test, late và ATO không bao giờ."""
    subset = LADDERS[:3]

    def payload_with(zeroed):
        tampered = frame.copy()
        mask = tampered["partition"].isin(zeroed).to_numpy()
        for ladder in subset:
            tampered.loc[mask, ladder.column] = 0
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(RP, "CI_BOOT", 5)
            return RP.build_payload(tampered, ladders=subset)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(RP, "CI_BOOT", 5)
        baseline = RP.build_payload(frame, ladders=subset)
    beyond_selection, without_val = payload_with(["test", "late", "ato"]), payload_with(["val", "test", "late", "ato"])
    for ladder in subset:
        b = baseline["ladders"][ladder.name]["selected"]
        assert beyond_selection["ladders"][ladder.name]["selected"] == b  # cả hai quy trình bất biến khi test/late/ATO bị xoá
        assert without_val["ladders"][ladder.name]["selected"]["train_only"] == b["train_only"]  # quy trình đặt trước bất biến cả khi val bị xoá


def test_a_stricter_budget_never_selects_a_looser_rung(payload):
    for name, entry in payload["ladders"].items():
        for procedure in ("train_only", "train_val"):
            picked = [entry["selected"][procedure][str(b)] for b in payload["budgets"]]  # ngân sách 2, 5, 10: tăng dần
            as_number = [len(entry["rungs"]) + 1 if p is None else p for p in picked]  # không chọn được = chặt hơn mọi bậc
            assert as_number[0] >= as_number[1] >= as_number[2], (name, procedure)


def test_the_rule_sets_are_unions_of_their_member_ladders(frame, payload):
    parts = {name: RT.Part(frame, name) for name in RT.PARTITIONS}
    shadow_by_default = {rule_id for rule_id, spec in REGISTRY.items() if spec.default_mode == "shadow"}  # đọc registry (country_hop thành enforce ở Milestone B)
    for key in ("default_enforce", "train_only_enforce", "tuned_enforce", "tuned_all"):
        members = payload["sets"][key]["members"]
        flagged = RP.union_flags(frame, members, parts["test"].index)
        assert payload["sets"][key]["test"] == parts["test"].metrics(flagged)
    default = payload["sets"]["default_enforce"]["members"]
    assert set(default) == {l.name for l in LADDERS if l.rule_id not in shadow_by_default}  # chỉ luật mặc định enforce
    assert all(default[l.name] == l.default_rung for l in LADDERS if l.name in default)
    assert set(payload["sets"]["tuned_enforce"]["members"]) <= set(payload["sets"]["tuned_all"]["members"])
    for key in ("train_only_enforce", "tuned_enforce"):
        assert set(payload["sets"][key]["members"]) <= {l.name for l in LADDERS if l.rule_id not in shadow_by_default}
    assert not set(payload["sets"]["tuned_all"]["members"]) & set(RT.PROFILE_EXCLUDED)  # bậc thang bị loại không vào hồ sơ
    chosen_train_only = {n for n, e in payload["ladders"].items() if e["selected"]["train_only"][str(RT.PRIMARY_BUDGET)] is not None}
    assert set(payload["transfer"]["held"]) | set(payload["transfer"]["failed"]) == chosen_train_only and not set(payload["transfer"]["held"]) & set(payload["transfer"]["failed"])


def test_a_rule_without_any_usable_rung_becomes_shadow_in_the_profile(payload):
    profile = payload["profile"]
    RuleConfig.from_dict(profile)  # hồ sơ phải nạp được
    for entry in payload["ladders"].values():
        siblings = [(l.name, payload["ladders"][l.name]) for l in LADDERS if l.rule_id == entry["rule_id"]]
        usable = [n for n, s in siblings if s["selected"]["train_val"][str(RT.PRIMARY_BUDGET)] is not None and n not in RT.PROFILE_EXCLUDED]
        if not usable:
            assert profile["rules"][entry["rule_id"]] == {"mode": "shadow"}


def test_the_document_reports_defaults_selection_sets_and_limits(payload):
    text = RP.render(payload)
    for expected in (
        "# Tinh chỉnh ngưỡng luật trên train RBA (MR10)", "## 1. Cách làm, quy trình sửa", "## 2. Kết quả theo từng luật", "## 3. Bộ luật gộp", "## 4. Bậc thang bị loại khỏi hồ sơ",
        "## 5. Chi tiết từng bậc thang", "## 6. Luật không đánh giá được", "## 7. Giới hạn", "`brute_force`", "`credential_stuffing/asn`", "`dormant_account_login`", "◀", "hồ sơ (enforce)",
        "chỉ train (enforce)", "ATO quá khứ", "username_enumeration", "Cỡ mẫu", "Quy trình sửa", "Quy trình đặt trước", "Chuyển giao của quy trình đặt trước",
    ):
        assert expected in text, expected
    assert "✔" in text or all(entry["selected"]["train_only"][str(RT.PRIMARY_BUDGET)] is None for entry in payload["ladders"].values())


def test_run_writes_the_document_profile_and_json(tmp_path, frame, monkeypatch):
    monkeypatch.setattr(RT, "load_frame", lambda path, ladders=LADDERS: frame)
    monkeypatch.setattr(RP, "CI_BOOT", 10)
    doc, data, profile = tmp_path / "doc.md", tmp_path / "x" / "tuning.json", tmp_path / "profiles" / "p.json"
    assert RP.run(tmp_path / "levels.parquet", doc, data, profile) == 0
    assert doc.read_text(encoding="utf-8").startswith("# Tinh chỉnh ngưỡng luật")
    assert json.loads(data.read_text(encoding="utf-8"))["budget"] == RT.PRIMARY_BUDGET
    assert RuleConfig.from_file(profile) is not None and profile.read_text(encoding="utf-8").endswith("\n")
