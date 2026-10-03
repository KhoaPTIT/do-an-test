"""MR10 — tinh chỉnh ngưỡng luật: bậc thang hợp lệ, lồng nhau, trùng quyết định của engine ở bậc mặc định; thu thập, chọn bậc, hồ sơ cấu hình."""

import random

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from app.detection.engine import REGISTRY, LoginAttempt, RuleConfig, RuleEngine
from ml.rba import rule_tuning as RT
from ml.rba.rule_tuning import LADDERS, Ladder

T0 = 1_700_000_000.0
ATTACKERS = [(f"66.66.{i}.1", 64500 + i % 2) for i in range(4)]
LEGIT = [(f"10.0.{i}.1", 64510 + i % 4) for i in range(25)]
COUNTRIES = ["VN", "US", "DE", "JP"]
AGENTS = [f"Mozilla/5.0 (X11; Linux) Agent/{i}" for i in range(12)]


def traffic(seed: int = 1, n: int = 40_000) -> list[LoginAttempt]:
    """Lưu lượng tổng hợp đủ đa dạng để MỌI bậc thang có lúc khớp: kẻ nhồi thông tin (nhiều tên, xoay UA), tên không tồn tại, người dùng hợp lệ đổi quốc gia/thiết bị,
    khoảng lặng 100 ngày (tài khoản ngủ đông) và vài nhà mạng hiếm."""
    rng = random.Random(seed)
    users = [f"u{i}" for i in range(80)]
    events, t = [], T0
    for i in range(n):
        t += rng.expovariate(1 / 2.0)
        if i % 9_000 == 8_999:
            t += 100 * 86_400
        r = rng.random()
        if r < 0.30:  # kẻ tấn công
            (ip, asn), user, success = rng.choice(ATTACKERS), rng.choice(users), rng.random() < 0.02
            agent, country, device = rng.choice(AGENTS), rng.choice(COUNTRIES), "desktop"
        elif r < 0.40:  # tên không tồn tại
            (ip, asn), user, success = rng.choice(ATTACKERS + LEGIT), None, False
            agent, country, device = rng.choice(AGENTS), rng.choice(COUNTRIES), "desktop"
        else:  # người dùng hợp lệ
            (ip, asn), user, success = rng.choice(LEGIT), rng.choice(users[:40]), rng.random() < 0.85
            if rng.random() < 0.02:
                asn = 70_000 + rng.randrange(50)  # nhà mạng hiếm
            agent, country = rng.choice(AGENTS[:4]), rng.choice(COUNTRIES)
            device = "bot" if rng.random() < 0.01 else "desktop"
            if rng.random() < 0.005:
                agent = "curl/8.4.0"
        events.append(
            LoginAttempt(
                ts=t, username=user or f"?{i}", success=success, ip=ip, user_key=user, asn=asn, country=country, user_agent=agent, device_type=device,
            )
        )
    return events


@pytest.fixture(scope="module")
def events():
    return traffic()


@pytest.fixture(scope="module")
def every_rung(events):
    """Với mỗi lần thử và MỌI bậc của mọi bậc thang: có khớp không (không dừng ở bậc đầu tiên không khớp), cùng với kết quả engine ở cấu hình mặc định."""
    ladder_engine, default_engine = RuleEngine(), RuleEngine()
    plan = [(l, ladder_engine.registry[l.rule_id], l.resolved()) for l in LADDERS]
    hits = {l.name: np.zeros((len(events), len(l.rungs)), dtype=bool) for l in LADDERS}
    engine_hits: dict[str, list[str | None]] = {l.rule_id: [None] * len(events) for l in LADDERS}
    for i, a in enumerate(events):
        with ladder_engine.probe(a) as probe:
            for ladder, spec, resolved in plan:
                for r, params in enumerate(resolved):
                    hits[ladder.name][i, r] = probe.run(spec, params) is not None
        for hit in default_engine.evaluate(a).hits:
            if hit.rule_id in engine_hits:
                engine_hits[hit.rule_id][i] = hit.evidence.get("scope", "-")
    return hits, engine_hits


# ------------------------------------------------------------------------------------------------ bậc thang


def test_ladders_are_valid_named_and_their_default_rung_is_the_registry_default():
    assert len({l.name for l in LADDERS}) == len(LADDERS) and len({l.column for l in LADDERS}) == len(LADDERS)
    for ladder in LADDERS:
        spec = REGISTRY[ladder.rule_id]
        declared = {p.name for p in spec.params}
        assert 1 <= len(ladder.rungs) <= 255, ladder.name
        assert len(ladder.resolved()) == len(ladder.rungs)  # mọi bậc qua kiểm tra khoảng hợp lệ của registry
        assert all(set(rung) <= declared for rung in ladder.rungs) and set(ladder.fixed) <= declared
        if ladder.default_rung is not None:
            defaults = spec.defaults()
            assert all(defaults[k] == v for k, v in ladder.rungs[ladder.default_rung - 1].items()), f"{ladder.name}: bậc mặc định không trùng mặc định của luật"
    assert set(RT.NOT_EVALUABLE) <= set(REGISTRY) and not set(RT.NOT_EVALUABLE) & {l.rule_id for l in LADDERS}


def test_a_ladder_becomes_stricter_along_every_tuned_parameter():
    """Bậc sau chặt hơn bậc trước ở MỌI tham số được quét (tăng, riêng max_share giảm) — điều kiện cần cho tính lồng nhau."""
    stricter_when_smaller = {"max_share", "window_s"}  # max_share nhỏ hơn = chặt hơn; cửa sổ ngắn hơn = chặt hơn (multi_context_simultaneous)
    for ladder in LADDERS:
        for previous, current in zip(ladder.rungs, ladder.rungs[1:]):
            for key in previous:
                a, b = previous[key], current[key]
                assert (b < a) if key in stricter_when_smaller else (b > a), f"{ladder.name}.{key}: {a} -> {b}"


def test_the_hits_of_a_stricter_rung_are_always_a_subset_of_the_looser_rung(every_rung):
    hits, _ = every_rung
    quiet = []
    for ladder in LADDERS:
        h = hits[ladder.name]
        assert not (h[:, 1:] & ~h[:, :-1]).any(), f"{ladder.name}: bậc chặt khớp nơi bậc lỏng không khớp"
        if not h[:, 0].any():
            quiet.append(ladder.name)
    assert len(quiet) <= 2, f"lưu lượng thử không kích hoạt {quiet}"  # bài kiểm tra không được rỗng: hầu hết bậc thang khớp ít nhất một lần
    assert sum(1 for l in LADDERS if hits[l.name][:, 0].sum() > hits[l.name][:, -1].sum()) >= 8  # và chặt hơn thật sự khớp ít hơn


def test_the_default_rung_reproduces_the_engine_decision(every_rung):
    hits, engine_hits = every_rung
    by_rule: dict[str, list[Ladder]] = {}
    for ladder in LADDERS:
        by_rule.setdefault(ladder.rule_id, []).append(ladder)
    for rule_id, group in by_rule.items():
        engine_fired = np.array([h is not None for h in engine_hits[rule_id]])
        ladder_fired = {l.name: hits[l.name][:, l.default_rung - 1] for l in group}
        union = np.any(list(ladder_fired.values()), axis=0)
        assert (union == engine_fired).all(), f"{rule_id}: hợp các bậc thang mặc định khác quyết định của engine"
        for ladder in group:
            if ladder.scope == "ip":  # IP được xét trước nên khớp phạm vi IP giống hệt nhau
                assert (ladder_fired[ladder.name] == np.array([h == "ip" for h in engine_hits[rule_id]])).all()
            elif ladder.scope == "asn":  # engine chỉ báo "asn" khi IP không khớp: tập của engine nằm trong bậc thang ASN
                assert not (np.array([h == "asn" for h in engine_hits[rule_id]]) & ~ladder_fired[ladder.name]).any()
        assert engine_fired.any() or rule_id in {"rare_network_login"}, f"{rule_id}: lưu lượng thử không kích hoạt luật ở mặc định"


# ------------------------------------------------------------------------------------------------ thu thập


def test_collect_levels_scores_only_sample_rows_yet_counts_every_row(events):
    events = events[:6_000]
    rows = list(enumerate(events))
    everything = RT.collect_levels(iter(rows), np.arange(len(events)))
    chosen = np.arange(0, len(events), 7)
    partial = RT.collect_levels(iter(rows), chosen)
    assert everything.shape == (len(LADDERS), len(events)) and partial.shape == (len(LADDERS), len(chosen))
    assert (partial == everything[:, chosen]).all()  # dòng ngoài mẫu vẫn được đếm: mức của dòng mẫu không đổi
    assert everything.max() > 0 and everything.dtype == np.uint8


def test_collect_levels_reports_progress_and_ignores_unknown_row_ids(events):
    calls = []
    rows = [(1_000 + i, a) for i, a in enumerate(events[:30])]
    levels = RT.collect_levels(iter(rows), np.array([5, 1_010, 1_020]), progress=lambda seen, ts, elapsed: calls.append(seen), progress_every=10)
    assert calls == [10, 20, 30] and levels.shape == (len(LADDERS), 3) and (levels[:, 0] == 0).all()  # row_id 5 không có trong luồng


def test_levels_round_trip_through_parquet_with_the_ladder_definitions(tmp_path):
    levels = np.arange(len(LADDERS) * 4, dtype=np.uint8).reshape(len(LADDERS), 4) % 5
    ids = np.array([10, 20, 30, 40])
    path = tmp_path / "levels.parquet"
    RT.save_levels(levels, ids, path=path)
    table = pq.read_table(path).to_pandas()
    assert list(table["row_id"]) == [10, 20, 30, 40] and table["L__credential_stuffing__ip"].dtype == np.uint8
    assert (table[[l.column for l in LADDERS]].to_numpy().T == levels).all()
    assert path.with_suffix(".ladders.json").read_text(encoding="utf-8").count('"rule_id"') == len(LADDERS)


# ------------------------------------------------------------------------------------------------ đo, chọn bậc, hồ sơ


def frame(levels: list[int], **extra) -> pd.DataFrame:
    """Khung nhỏ: 4 đăng nhập hợp lệ thành công, 2 thất bại hợp lệ, 2 dòng tấn công (train) + 2 tấn công và 2 bình thường (test), 1 ATO."""
    rows = [
        # partition, attack, ato, success, weight, ip, level
        ("train", False, False, 1, 1.0, "a", levels[0]), ("train", False, False, 1, 1.0, "b", levels[1]), ("train", False, False, 1, 2.0, "c", levels[2]), ("train", False, False, 1, 1.0, "d", levels[3]),
        ("train", False, False, 0, 1.0, "e", levels[4]), ("train", False, False, 0, 1.0, "f", levels[5]),
        ("train", True, False, 0, 2.0, "x", levels[6]), ("train", True, False, 0, 2.0, "y", levels[7]),
        ("test", True, False, 0, 1.0, "x", levels[8]), ("test", True, False, 0, 3.0, "z", levels[9]), ("test", False, False, 1, 1.0, "a", levels[10]), ("test", False, False, 1, 1.0, "b", levels[11]),
        ("ato", False, True, 1, 1.0, "q", levels[12]),
    ]
    df = pd.DataFrame(rows, columns=["partition", "is_attack_ip", "is_ato", "cur_success", "pop_weight", "ip", "L__x"])
    df["in_warmup"] = False
    df["ts"] = pd.Timestamp("2020-09-15")
    df["user_id"] = np.arange(len(df))
    for key, value in extra.items():
        df[key] = value
    return df


def test_part_measures_alerts_per_10k_legit_logins_and_weighted_recall():
    df = frame([1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
    train = RT.Part(df, "train")
    m = train.metrics(df["L__x"].to_numpy()[train.index] >= 1)
    # khớp trên dòng bình thường: a (1) + c (2) + e (1, thất bại) = 4; đăng nhập hợp lệ thành công: 1 + 1 + 2 + 1 = 5  ->  8.000 trên 10.000
    assert m["fa10k"] == pytest.approx(4 / 5 * 10_000) and m["fa10k_success"] == pytest.approx(3 / 5 * 10_000)
    assert m["recall"] == pytest.approx(2 / 4) and m["n_attack"] == 2  # tấn công: x (trọng số 2) khớp, y (2) không
    test = RT.Part(df, "test")
    assert test.metrics(df["L__x"].to_numpy()[test.index] >= 1)["recall"] == pytest.approx(1 / 4)  # x (1) khớp, z (3) không
    assert RT.AtoSet(df).counts(df["L__x"].to_numpy()[RT.AtoSet(df).index] >= 1)["all"] == (1, 1)


def test_part_confidence_intervals_bracket_the_point_estimate():
    rng = np.random.default_rng(3)
    n = 4_000
    df = pd.DataFrame({
        "partition": "train", "is_attack_ip": rng.random(n) < 0.1, "is_ato": False, "cur_success": (rng.random(n) < 0.6).astype(int), "pop_weight": 1.0,
        "ip": rng.integers(0, 300, n).astype(str), "in_warmup": False,
    })
    flagged = rng.random(n) < 0.2
    part = RT.Part(df, "train")
    point, ci = part.metrics(flagged), part.ci(flagged, n_boot=100)
    assert ci["fa10k"][0] < point["fa10k"] < ci["fa10k"][1] and ci["recall"][0] < point["recall"] < ci["recall"][1]


def test_the_selected_rung_is_the_loosest_one_within_the_budget_on_train_only():
    def row(rung, train_fa, test_fa=0.0):
        part = {"fa10k": train_fa, "fa10k_success": train_fa, "recall": 0.5, "n_attack": 1}
        return RT.RungRow(rung, f"r{rung}", {"train": part, "val": part, "test": {**part, "fa10k": test_fa}, "late": part}, {})

    rows = [row(1, 40.0, 1.0), row(2, 12.0, 0.0), row(3, 4.9, 999.0), row(4, 1.0), row(5, 0.0)]
    assert RT.select_rung(rows, 5.0) == 3  # bậc 3 lỏng nhất còn trong ngân sách; test (999) KHÔNG ảnh hưởng việc chọn
    assert RT.select_rung(rows, 2.0) == 4 and RT.select_rung(rows, 100.0) == 1
    assert RT.select_rung([row(1, 9.0), row(2, 8.0)], 5.0) is None  # ngay cả bậc chặt nhất vẫn vượt ngân sách


def test_the_revised_procedure_also_requires_the_budget_on_val():
    def row(rung, train_fa, val_fa):
        part = {"fa10k": 0.0, "fa10k_success": 0.0, "recall": 0.5, "n_attack": 1}
        return RT.RungRow(rung, f"r{rung}", {"train": {**part, "fa10k": train_fa}, "val": {**part, "fa10k": val_fa}, "test": part, "late": part}, {})

    rows = [row(1, 40.0, 40.0), row(2, 4.0, 200.0), row(3, 3.0, 4.5), row(4, 0.0, 0.0)]
    assert RT.select_rung(rows, 5.0) == 2  # chỉ train: bậc 2 đã đạt
    assert RT.select_rung(rows, 5.0, parts=("train", "val")) == 3  # train và val: bậc 2 vượt ngân sách ở val
    assert RT.select_rung(rows, 0.5, parts=("train", "val")) == 4 and RT.select_rung(rows[:3], 0.5, parts=("train", "val")) is None


def test_the_profile_merges_scopes_disables_unselected_ones_and_validates_as_a_rule_config():
    selection = {l.name: None for l in LADDERS}
    selection.update({"brute_force": 5, "credential_stuffing/ip": None, "credential_stuffing/asn": 3, "rare_network_login": 8})
    profile = RT.build_profile(selection, excluded={})
    rules = profile["rules"]
    assert rules["brute_force"] == {"params": {"threshold": 8}}
    assert rules["credential_stuffing"]["params"] == {"asn_min_fails": 40, "asn_min_users": 20, "min_fails": 100_000, "min_users": 100_000}  # phạm vi IP bị tắt
    # giữ chế độ mặc định của luật: enforce từ Milestone C+ (trước đó shadow nên hồ sơ ghi "mode": "shadow")
    assert rules["rare_network_login"] == {"params": {"max_share": 5e-6}}
    assert rules["password_spray_slow"] == {"mode": "shadow"} and rules["ua_rotation"] == {"mode": "shadow"}  # không chọn được -> shadow
    config = RuleConfig.from_dict(profile)  # phải nạp được
    assert config.mode_of(REGISTRY["ua_rotation"]) == "shadow" and config.resolved_params(REGISTRY["brute_force"]).threshold == 8

    both = dict(selection, **{"credential_stuffing/ip": 4, "credential_stuffing/asn": 3})
    assert RT.build_profile(both, excluded={})["rules"]["credential_stuffing"]["params"] == {"min_fails": 10, "min_users": 5, "asn_min_fails": 40, "asn_min_users": 20}


def test_excluded_ladders_never_reach_the_profile_even_when_a_rung_was_selected():
    assert set(RT.PROFILE_EXCLUDED) == {"credential_stuffing/asn", "dormant_account_login"} and set(RT.PROFILE_EXCLUDED) <= {l.name for l in LADDERS}
    selection = {l.name: None for l in LADDERS}
    selection.update({"credential_stuffing/ip": 4, "credential_stuffing/asn": 3, "dormant_account_login": 6})
    rules = RT.build_profile(selection)["rules"]  # loại mặc định
    assert rules["credential_stuffing"]["params"] == {"min_fails": 10, "min_users": 5, "asn_min_fails": 1_000_000, "asn_min_users": 1_000_000}  # phạm vi ASN bị tắt
    assert rules["dormant_account_login"] == {"mode": "shadow"}  # không còn bậc nào -> shadow, dù đã chọn được bậc 6
    assert all(reason.strip() for reason in RT.PROFILE_EXCLUDED.values())


def test_load_frame_joins_model_table_weights_ips_and_levels(tmp_path, monkeypatch):
    n = 6
    model = pd.DataFrame({
        "row_id": np.arange(100, 100 + n), "ts": pd.Timestamp("2020-05-01"), "user_id": np.arange(n), "stratum": ["heavy", "heavy", "light", "single", "heavy", "heavy"],
        "forced": [False] * 5 + [True], "partition": ["train"] * 4 + ["test", "ato"], "weight": [1.0, 1.0, 1.0, 1.0, 1.0, 1.0], "is_attack_ip": False, "is_ato": [False] * 5 + [True],
        "in_warmup": False, "cur_success": 1, "u_n_success": 0, "extra_feature": 1.0,
    })
    sample = pd.DataFrame({"row_id": np.arange(100, 100 + n), "ip": [f"1.1.1.{i}" for i in range(n)]})
    for name, table in (("model.parquet", model), ("sample.parquet", sample)):
        table.to_parquet(tmp_path / name, index=False)
    monkeypatch.setattr(RT, "MODEL_TABLE_PARQUET", tmp_path / "model.parquet")
    monkeypatch.setattr(RT, "SAMPLE_PARQUET", tmp_path / "sample.parquet")
    levels = np.tile(np.arange(n, dtype=np.uint8), (len(LADDERS), 1))
    RT.save_levels(levels, np.arange(100, 100 + n), path=tmp_path / "levels.parquet")

    loaded = RT.load_frame(tmp_path / "levels.parquet")
    assert len(loaded) == n and loaded["ip"].tolist() == sample["ip"].tolist() and loaded["L__brute_force"].tolist() == list(range(n))
    # trọng số dân số: weight / tỉ lệ lấy mẫu của tầng (heavy 25%, light 10%, single 5%); user ép lấy (forced) = 100%
    assert loaded["pop_weight"].tolist() == pytest.approx([4.0, 4.0, 10.0, 20.0, 4.0, 1.0])
    with pytest.raises(ValueError, match="collect"):
        RT.load_frame(tmp_path / "levels.parquet", ladders=[*LADDERS, Ladder("moi", "brute_force", ({"threshold": 3},))])


def test_the_command_line_collects_levels_from_a_tiny_rba_file(tmp_path, monkeypatch):
    from ml.rba import rule_replay

    rows = [
        (i, f"2020-03-01 12:00:{i:02d}", 7, "6.6.6.6", "NO", 29695, "Mozilla/5.0 (X)", "Chrome 1", "Linux", "desktop", False, True, False, False, False, False) for i in range(10)
    ]
    df = pd.DataFrame(rows, columns=["row_id", "ts", "user_id", "ip", "country", "asn", "ua", "browser", "os", "device_type", "success", "is_attack_ip", "is_ato", "is_private_ip", "is_fake_asn", "ua_parse_failed"])
    df["ts"] = pd.to_datetime(df["ts"]).astype("datetime64[us]")
    df["asn"] = df["asn"].astype("Int32")
    df.to_parquet(tmp_path / "rba.parquet", index=False)
    pq.write_table(pa.table({"row_id": pa.array(np.arange(10, dtype=np.int64))}), tmp_path / "model.parquet")
    monkeypatch.setattr(RT, "MODEL_TABLE_PARQUET", tmp_path / "model.parquet")
    monkeypatch.setattr(RT, "rba_rows", lambda **kw: rule_replay.rba_rows(tmp_path / "rba.parquet", **kw))
    out = tmp_path / "out" / "levels.parquet"
    assert RT.main(["collect", "--out", str(out)]) == 0
    table = pq.read_table(out).to_pandas()
    assert len(table) == 10
    # lần sai thứ 1..10 của cùng một tài khoản trong 10 giây; các ngưỡng của bậc thang là 3, 4, 5, 6, 8, 10 -> số bậc còn khớp
    assert table["L__brute_force"].tolist() == [0, 0, 1, 2, 3, 4, 4, 5, 5, 6]


@pytest.mark.skipif(not __import__("ml.rba.etl", fromlist=["FULL_PARQUET"]).FULL_PARQUET.is_file(), reason="chưa có rba_full.parquet (chạy python -m ml.rba.etl)")
def test_ladders_at_the_default_rung_match_the_engine_on_a_real_day_of_rba():
    """Trên MỘT NGÀY dữ liệu thật (mọi dòng là dòng mẫu, gồm cả lần thử vào tên không tồn tại): hợp các bậc thang mặc định của mỗi luật phải trùng đúng tập lần khớp của engine."""
    from ml.rba.rule_replay import rba_rows

    rows = list(rba_rows(start="2020-03-01", end="2020-03-02"))
    ids = np.array([row_id for row_id, _ in rows])
    levels = RT.collect_levels(iter(rows), ids)
    engine, fired = RuleEngine(), {}
    for i, (_, attempt) in enumerate(rows):
        for hit in engine.evaluate(attempt).hits:
            fired.setdefault(hit.rule_id, {})[i] = hit.evidence.get("scope", "-")
    assert len(rows) > 20_000 and fired
    by_rule: dict[str, list[tuple[int, Ladder]]] = {}
    for k, ladder in enumerate(LADDERS):
        by_rule.setdefault(ladder.rule_id, []).append((k, ladder))
    for rule_id, group in by_rule.items():
        engine_rows = set(fired.get(rule_id, {}))
        union = set()
        for k, ladder in group:
            hit_rows = set(np.flatnonzero(levels[k] >= ladder.default_rung).tolist())
            union |= hit_rows
            if ladder.scope == "ip":
                assert hit_rows == {i for i, scope in fired.get(rule_id, {}).items() if scope == "ip"}, ladder.name
            elif ladder.scope == "asn":
                assert {i for i, scope in fired.get(rule_id, {}).items() if scope == "asn"} <= hit_rows, ladder.name
        assert union == engine_rows, f"{rule_id}: bậc thang mặc định lệch engine trên dữ liệu thật"
