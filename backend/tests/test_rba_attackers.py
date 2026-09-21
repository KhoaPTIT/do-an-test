"""MR4 — mô phỏng kẻ tấn công: mỗi loại đúng "biết gì về nạn nhân", không để lại dấu vân tay, đặc trưng đúng pipeline MR3."""

import duckdb
import numpy as np
import pandas as pd
import pytest

from ml.rba import attackers as A
from ml.rba import features as F
from ml.rba import splits
from ml.rba.features import EventRecord

DAY_US = 24 * A.HOUR_US
N_USERS = 40


def make_events(seed=0):
    """~10.000 đăng nhập trải 20 ngày: mỗi user có quốc gia/ASN/thiết bị "nhà" riêng, đủ dày để luôn có người cho."""
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(20 * 24 * 20):
        u = int(rng.integers(1, N_USERS + 1))
        home = rng.random() < 0.9
        c = u % 5 if home else int(rng.integers(0, 5))
        rows.append(
            dict(
                row_id=i, t=int(i * (20 * DAY_US) / (20 * 24 * 20)) + int(rng.integers(0, 1000)), uid=u,
                ip=f"10.{c}.{u}.{int(rng.integers(0, 4))}" if home else f"77.{c}.{int(rng.integers(0, 50))}.1",
                asn=1000 + c * 10 + (u % 2), country=f"C{c}", ua=f"UA{u}", browser="Chrome 90.0", os="Windows 10",
                device_type="desktop", success=bool(rng.random() < 0.85),
            )
        )
    return pd.DataFrame(rows)


@pytest.fixture(scope="module")
def world():
    events = make_events()
    con = duckdb.connect()
    con.register("events_df", events)
    con.execute("CREATE TABLE events_src AS SELECT * FROM events_df")
    users = np.arange(1, N_USERS + 1)
    rng = np.random.default_rng(1)
    picked = rng.permutation(users)[:30]
    anchors = []  # đăng nhập gốc: một đăng nhập thật, thành công của nạn nhân trong ngày 10–15
    for uid in picked:
        pool = events[(events["uid"] == uid) & events["success"] & (events["t"] >= 10 * DAY_US) & (events["t"] < 15 * DAY_US)]
        anchors.append(pool.iloc[int(rng.integers(0, len(pool)))])
    anchors = pd.DataFrame(anchors)
    victims = pd.DataFrame(
        {
            "victim_id": np.arange(30),
            "attacker_type": [A.ATTACKER_TYPES[i % 3] for i in range(30)],
            "uid": picked.astype("int64"),
            "anchor_row_id": anchors["row_id"].to_numpy().astype("int64"),
            "anchor_us": anchors["t"].to_numpy().astype("int64"),
            "t_inj_us": anchors["t"].to_numpy().astype("int64"),
        }
    )
    injected = A.simulate_attackers(con, victims, "events_src")
    return events, victims, injected, con


def victim_profile(events, victim):
    """Hồ sơ của nạn nhân = thuộc tính của đăng nhập gốc (đăng nhập thật bị thay thế)."""
    anchor = events[events["row_id"] == victim.anchor_row_id].iloc[0]
    return {col: anchor[col] for col in ("country", "asn", "ua", "browser", "os", "device_type")}


def test_every_victim_gets_one_successful_login_at_the_planned_time(world):
    events, victims, injected, _ = world
    assert len(injected) == len(victims)
    assert injected["victim_id"].is_unique and injected["row_id"].is_unique
    assert (injected["row_id"] >= A.INJECT_ROW_ID_BASE).all()
    assert injected["success"].all()
    merged = injected.merge(victims, on="victim_id", suffixes=("", "_v"))
    assert (merged["t"] == merged["t_inj_us"]).all() and (merged["uid"] == merged["uid_v"]).all()
    assert set(injected["attacker_type"]) == set(A.ATTACKER_TYPES)


DONOR_COLUMNS = ("ip", "asn", "country", "ua", "browser", "os", "device_type")


def first_donor_after(events, row, extra=None):
    """Đăng nhập thật thành công ĐẦU TIÊN của người khác sau mốc chèn (tuỳ chọn: thoả thêm điều kiện) — tính lại bằng pandas."""
    pool = events[(events["t"] > row.t) & events["success"] & (events["uid"] != row.uid)]
    if extra is not None:
        pool = pool[extra(pool)]
    return pool.sort_values(["t", "row_id"]).iloc[0]


def test_every_attacker_borrows_the_ip_of_a_real_login_of_someone_else_right_after_the_planned_time(world):
    events, _, injected, _ = world
    assert not injected["ip"].str.startswith("sim-attacker-").any()  # không dùng IP bịa: IP hoàn toàn mới là dấu vân tay
    same_as_donor = {  # điều kiện thêm của từng loại lên người cho (naive: không có)
        "naive": None,
        "vpn": lambda r: (lambda p: p["country"] == r.country),  # cùng quốc gia với đăng nhập gốc
        "targeted": lambda r: (lambda p: p["asn"] == r.asn),  # cùng ASN với đăng nhập gốc
    }
    for row in injected.itertuples():
        make = same_as_donor[row.attacker_type]
        donor = first_donor_after(events, row, extra=None if make is None else make(row))
        assert donor["t"] - row.t <= 24 * A.HOUR_US
        assert donor["ip"] == row.ip and donor["asn"] == row.asn
        if row.attacker_type != "targeted":  # targeted có quốc gia của đăng nhập gốc, IP/ASN của người cho
            assert donor["country"] == row.country


def test_naive_attacker_copies_every_attribute_of_the_first_real_login_of_someone_else_after_the_planned_time(world):
    events, _, injected, _ = world
    assert (injected["attacker_type"] == "naive").any()
    for row in injected[injected["attacker_type"] == "naive"].itertuples():
        donor = first_donor_after(events, row)
        assert all(getattr(row, c) == donor[c] for c in DONOR_COLUMNS)


def test_vpn_attacker_uses_the_country_of_the_replaced_login_but_not_her_device(world):
    events, victims, injected, _ = world
    seen_other_ua = 0
    for row in injected[injected["attacker_type"] == "vpn"].itertuples():
        profile = victim_profile(events, victims.loc[victims.victim_id == row.victim_id].iloc[0])
        assert row.country == profile["country"]
        donor = first_donor_after(events, row, extra=lambda p: p["country"] == profile["country"])
        assert all(getattr(row, c) == donor[c] for c in DONOR_COLUMNS)
        seen_other_ua += row.ua != profile["ua"]
    assert seen_other_ua > 0  # kẻ tấn công VPN không biết thiết bị của nạn nhân


def test_targeted_attacker_is_a_perfect_mimic_of_the_replaced_login_except_for_the_ip(world):
    events, victims, injected, _ = world
    assert (injected["attacker_type"] == "targeted").any()
    for row in injected[injected["attacker_type"] == "targeted"].itertuples():
        victim = victims.loc[victims.victim_id == row.victim_id].iloc[0]
        profile = victim_profile(events, victim)
        # mọi thuộc tính hồ sơ đúng bằng đăng nhập gốc (không phải "hay gặp nhất"/"gần nhất": xem docstring attackers.py)
        assert (row.country, row.asn, row.ua, row.browser, row.os, row.device_type) == tuple(
            profile[c] for c in ("country", "asn", "ua", "browser", "os", "device_type")
        )


def test_simulation_is_deterministic(world):
    events, victims, injected, con = world
    pd.testing.assert_frame_equal(injected, A.simulate_attackers(con, victims, "events_src"))


def test_victim_without_any_donor_is_dropped(world):
    events, victims, _, con = world
    lonely = victims.iloc[[0]].copy()
    lonely["t_inj_us"] = 400 * DAY_US  # xa mọi sự kiện: không có người cho trong 24h sau mốc
    lonely["attacker_type"] = "naive"
    assert A.simulate_attackers(con, lonely, "events_src").empty


def test_victim_without_a_prior_success_is_dropped_without_error(world):
    events, victims, _, con = world
    early = victims.iloc[[0]].copy()
    early["t_inj_us"] = 5  # trước mọi sự kiện: nạn nhân chưa từng đăng nhập thành công
    assert A.simulate_attackers(con, early, "events_src").empty


def test_donors_are_limited_to_the_allowed_pool_and_to_the_period(world):
    events, victims, _, con = world
    victim = victims.iloc[[0]].assign(attacker_type="naive")
    free = A.simulate_attackers(con, victim, "events_src")
    assert len(free) == 1
    free = free.iloc[0]
    donor = first_donor_after(events, free)

    pool = events.loc[events["row_id"] != donor["row_id"], ["row_id"]]  # cấm đúng người cho vừa chọn
    limited = A.simulate_attackers(con, victim, "events_src", donor_rows=pool)
    assert len(limited) == 1 and limited.iloc[0]["t"] == free["t"]
    successors = events[(events["t"] > free["t"]) & events["success"] & (events["uid"] != free["uid"]) & (events["row_id"] != donor["row_id"])]
    next_donor = successors.sort_values(["t", "row_id"]).iloc[0]
    assert all(limited.iloc[0][c] == next_donor[c] for c in DONOR_COLUMNS)  # người cho kế tiếp thay thế

    boxed = victim.assign(period_end_us=int(free["t"]) + 1)  # người cho phải xảy ra trước khi hết giai đoạn
    assert A.simulate_attackers(con, boxed, "events_src").empty


def test_select_victims_uses_only_eligible_rows_balances_types_and_replaces_a_real_login():
    rng = np.random.default_rng(0)
    n = 3000
    users = rng.integers(0, 900, n)
    ts = pd.Timestamp("2020-09-01") + pd.to_timedelta(rng.integers(0, 80 * 24 * 3600, n), unit="s")
    table = pd.DataFrame(
        {
            "row_id": np.arange(n) + 700, "user_id": users, "ts": ts, "partition": "test", "in_warmup": False, "cur_success": 1.0,
            "is_attack_ip": rng.random(n) < 0.1, "is_ato": False, "u_n_success": rng.integers(0, 3, n).astype(float),
        }
    )
    table.loc[table["user_id"] < 5, "partition"] = "train"  # 5 user đầu không có đăng nhập ở giai đoạn test
    table.loc[table["user_id"].isin([10, 11]), "is_ato"] = True
    victims = A.select_victims(table, A.SimulationConfig(per_type=100, seed=3), exclude_users=[20, 21, 22])
    assert victims["anchor_row_id"].is_unique and len(victims) == 300  # mỗi nạn nhân một đăng nhập gốc khác nhau
    assert set(victims["attacker_type"]) == set(A.ATTACKER_TYPES)
    assert victims["attacker_type"].value_counts().nunique() == 1  # chia đều
    assert not (set(victims["uid"]) & (set(range(5)) | {20, 21, 22}))  # giai đoạn khác, user bị loại
    assert (victims["t_inj_us"] == victims["anchor_us"]).all()  # đăng nhập giả thay đăng nhập thật đúng thời điểm đó
    by_row = table.set_index("row_id")  # anchor_row_id trỏ đúng đăng nhập gốc (cùng user, cùng thời điểm) và đủ điều kiện
    anchors = by_row.loc[victims["anchor_row_id"]]
    assert (anchors["user_id"].to_numpy() == victims["uid"].to_numpy()).all()
    assert all(A._to_us(ts) == a for ts, a in zip(anchors["ts"], victims["anchor_us"]))
    assert (anchors["u_n_success"] >= 1).all() and not anchors["is_attack_ip"].any() and not anchors["is_ato"].any()
    assert (victims["t_inj_us"] < A._to_us(splits.TEST_END)).all()
    assert (victims["period_end_us"] == A._to_us(splits.TEST_END)).all()


def test_select_victims_follows_login_volume_so_the_positives_match_the_rows_used_as_negatives():
    """Chọn mỗi user một lần (hay loại user đã là nạn nhân ở bộ khác) làm user hoạt động nhiều bị đại diện thiếu ở phía dương
    tính nhưng vẫn có mặt ở phía âm tính (âm tính lấy theo dòng); mô hình học "thuộc tính của họ = hợp lệ" (audit: nhóm độ hiếm
    tách được 95% ở val). Chọn thuần theo dòng thì mọi user chiếm phần nạn nhân đúng bằng phần đăng nhập của họ."""
    start = pd.Timestamp("2020-09-05")
    heavy = [(10_000 + u, start + pd.Timedelta(minutes=10 * k)) for u in range(20) for k in range(200)]  # 20 user × 200 đăng nhập
    single = [(u, start + pd.Timedelta(minutes=7 * u)) for u in range(2000)]  # 2.000 user × 1 đăng nhập
    table = pd.DataFrame(heavy + single, columns=["user_id", "ts"]).assign(
        partition="test", in_warmup=False, cur_success=1.0, is_attack_ip=False, is_ato=False, u_n_success=5.0
    )
    table["row_id"] = np.arange(len(table))
    heavy_share = []
    for seed in (1, 2, 3):
        victims = A.select_victims(table, A.SimulationConfig(per_type=100, seed=seed))  # 300 nạn nhân trên 4.000 + 2.000 dòng
        assert len(victims) == 300 and victims["anchor_row_id"].is_unique
        heavy_share.append(float((victims["uid"] >= 10_000).mean()))
    assert all(0.55 < share < 0.78 for share in heavy_share), heavy_share  # user nhiều đăng nhập giữ 2/3 số dòng -> ~2/3 nạn nhân
    assert victims["uid"].duplicated().any()  # cùng một user có thể bị chọn nhiều lần


def test_attacker_features_use_the_mr3_pipeline_and_match_the_spec(world):
    events, victims, injected, con = world
    feats = A.compute_attacker_features(con, injected, "SELECT * FROM events_src", end_us=10**15, infra_chunk_rows=10**7)
    assert len(feats) == len(injected)
    assert (feats["cur_success"] == 1).all() and (feats["partition"] == "attacker").all()

    record = lambda r: EventRecord(int(r.t), None if pd.isna(r.uid) else int(r.uid), r.ip, None if pd.isna(r.asn) else int(r.asn), r.country, r.ua, r.browser, r.os, r.device_type, bool(r.success))
    prior = [record(r) for r in events.itertuples()]
    for row in injected.head(6).itertuples():
        spec = F.compute_features_spec(record(row), prior + [record(o) for o in injected.itertuples() if o.t < row.t])
        got = feats.loc[feats["row_id"] == row.row_id].iloc[0]
        for name in ("u_n_success", "new_country", "new_ip", "llr_sum", "rare_asn", "ip_attempts_24h", "asn_attempts_24h"):
            assert got[name] == pytest.approx(spec[name], rel=1e-4, abs=1e-4, nan_ok=True), name


def test_replaced_logins_leave_the_event_stream_so_counts_are_conserved(world):
    """Đăng nhập gốc bị BỎ khỏi luồng sự kiện khi tính đặc trưng: đăng nhập giả thay thế, không cộng thêm vào số đếm toàn cục
    (nếu chỉ chèn, độ hiếm/LLR của đăng nhập giả lệch đều vài phần vạn so với đăng nhập thật và LightGBM học được độ lệch)."""
    events, victims, injected, con = world
    replaced = victims.loc[victims["victim_id"].isin(injected["victim_id"]), "anchor_row_id"]
    kwargs = dict(end_us=10**15, infra_chunk_rows=10**7)
    swapped = A.compute_attacker_features(con, injected, "SELECT * FROM events_src", replaced_row_ids=replaced, **kwargs)
    inserted = A.compute_attacker_features(con, injected, "SELECT * FROM events_src", **kwargs)

    record = lambda r: EventRecord(int(r.t), None if pd.isna(r.uid) else int(r.uid), r.ip, None if pd.isna(r.asn) else int(r.asn), r.country, r.ua, r.browser, r.os, r.device_type, bool(r.success))
    gone = set(replaced)
    kept = [record(r) for r in events.itertuples() if r.row_id not in gone]
    names = ("u_n_success", "rare_country", "rare_asn", "rare_ip", "llr_sum", "llr_ip", "ip_prior_attempts_all", "ip_attempts_24h", "asn_attempts_24h")
    for row in injected.itertuples():
        spec = F.compute_features_spec(record(row), kept + [record(o) for o in injected.itertuples() if o.t < row.t])
        got = swapped.loc[swapped["row_id"] == row.row_id].iloc[0]
        for name in names:
            assert got[name] == pytest.approx(spec[name], rel=1e-4, abs=1e-4, nan_ok=True), name

    diff = (swapped.set_index("row_id")[list(names)] - inserted.set_index("row_id")[list(names)]).abs().to_numpy()
    assert np.nanmax(diff) > 1e-4  # bỏ đăng nhập gốc THẬT SỰ đổi đặc trưng (test có tác dụng, không so hai thứ giống nhau)


def test_ip_context_of_a_fake_login_is_the_real_history_of_the_borrowed_ip(world):
    """IP mượn là IP thật nên đặc trưng IP của đăng nhập giả là hoạt động thật của IP đó TRƯỚC mốc chèn — không phải "IP chưa
    từng ai dùng" (toàn số 0, độ hiếm cực đại) mà mô hình dùng làm lối tắt."""
    events, _, injected, con = world
    feats = A.compute_attacker_features(con, injected, "SELECT * FROM events_src", end_us=10**15, infra_chunk_rows=10**7)
    record = lambda r: EventRecord(int(r.t), None if pd.isna(r.uid) else int(r.uid), r.ip, None if pd.isna(r.asn) else int(r.asn), r.country, r.ua, r.browser, r.os, r.device_type, bool(r.success))
    prior = [record(r) for r in events.itertuples()]
    had_history = 0
    for row in injected.itertuples():
        spec = F.compute_features_spec(record(row), prior + [record(o) for o in injected.itertuples() if o.t < row.t])
        got = feats.loc[feats["row_id"] == row.row_id].iloc[0]
        for name in F.FEATURE_GROUPS["infra_ip"]:
            assert got[name] == pytest.approx(spec[name], rel=1e-4, abs=1e-4, nan_ok=True), name
        had_history += got["ip_prior_attempts_all"] > 0
    assert had_history >= 0.8 * len(injected)


def test_rhythm_features_equal_those_of_the_real_login_the_attacker_replaces():
    events = make_events(seed=3)
    con = duckdb.connect()
    con.register("events_df", events)
    con.execute("CREATE TABLE events_src AS SELECT * FROM events_df")
    real = events[(events["success"]) & (events["t"] > 12 * DAY_US)].groupby("uid").head(1).head(24)
    victims = pd.DataFrame(
        {
            "victim_id": np.arange(len(real)), "attacker_type": ["targeted"] * len(real), "uid": real["uid"].astype("int64").to_numpy(),
            "anchor_row_id": real["row_id"].astype("int64").to_numpy(), "anchor_us": real["t"].to_numpy(), "t_inj_us": real["t"].to_numpy(),
        }
    )
    injected = A.simulate_attackers(con, victims, "events_src")
    feats = A.compute_attacker_features(con, injected, "SELECT * FROM events_src", end_us=10**15, infra_chunk_rows=10**7)

    def record(r):
        return EventRecord(int(r.t), int(r.uid), r.ip, int(r.asn), r.country, r.ua, r.browser, r.os, r.device_type, bool(r.success))

    prior_all = [record(r) for r in events.itertuples()]
    checked = 0
    for r in real.itertuples():
        row = feats[(feats["user_id"] == r.uid) & (feats["ts"] == pd.to_datetime(r.t, unit="us"))]
        if row.empty:
            continue
        spec = F.compute_features_spec(record(r), prior_all)  # đặc trưng của CHÍNH đăng nhập thật đó
        for name in ("u_n_attempts", "u_n_success", "u_age_days", "u_secs_since_last", "u_attempts_1h", "u_attempts_24h", "u_fail_streak", "u_distinct_ips_24h"):
            assert row.iloc[0][name] == pytest.approx(spec[name], rel=1e-4, abs=1e-4, nan_ok=True), name
        checked += 1
    assert checked >= 15


def test_select_victims_supports_train_val_periods_and_user_exclusions():
    rng = np.random.default_rng(2)
    n = 6000
    ts = pd.Timestamp("2020-03-01") + pd.to_timedelta(rng.integers(0, 170 * 24 * 3600, n), unit="s")
    table = pd.DataFrame(
        {
            "row_id": np.arange(n), "user_id": rng.integers(0, 1500, n), "ts": ts, "in_warmup": False, "cur_success": 1.0,
            "is_attack_ip": False, "is_ato": False, "u_n_success": 2.0,
        }
    )
    table["partition"] = splits.assign_time_split(table["ts"])
    banned = set(range(0, 300))

    train = A.select_victims(table, A.SimulationConfig(per_type=100, seed=1), "train", banned, id_offset=0)
    val = A.select_victims(table, A.SimulationConfig(per_type=100, seed=2), "val", banned, id_offset=1_000_000)

    assert not (set(train["uid"]) & banned) and not (set(val["uid"]) & banned)
    assert (train["t_inj_us"] < A._to_us(splits.TRAIN_END)).all() and (val["t_inj_us"] < A._to_us(splits.VAL_END)).all()
    assert (val["t_inj_us"] >= A._to_us(splits.TRAIN_END)).all()  # nạn nhân val có mốc thuộc giai đoạn val
    assert (train["period_end_us"] == A._to_us(splits.TRAIN_END)).all() and (val["period_end_us"] == A._to_us(splits.VAL_END)).all()
    assert train["victim_id"].max() < 1_000_000 <= val["victim_id"].min()  # id không trùng giữa hai bộ
    assert not (set(train["anchor_row_id"]) & set(val["anchor_row_id"]))  # đăng nhập gốc khác nhau (giai đoạn khác nhau)
    assert len(train) == 300 and len(val) == 300
    assert set(train["uid"]) & set(val["uid"])  # nhưng user có thể chung: user hoạt động nhiều xuất hiện ở cả hai (như khi triển khai)


def test_profile_comes_from_the_anchor_login_and_victims_with_invalid_anchors_are_dropped(world):
    events, victims, _, con = world
    extra = pd.DataFrame(
        [
            dict(row_id=10**7 + 1, t=1 * DAY_US, uid=9001, ip="5.5.5.1", asn=1, country="ZZ", ua="uaZ", browser="B 1.0", os="O 1", device_type="mobile", success=True),
            dict(row_id=10**7 + 2, t=2 * DAY_US, uid=9001, ip="5.5.5.2", asn=2, country="AA", ua="uaA", browser="B 2.0", os="O 2", device_type="tablet", success=True),  # đăng nhập gốc
            dict(row_id=10**7 + 3, t=3 * DAY_US, uid=9001, ip="5.5.5.3", asn=3, country="QQ", ua="uaQ", browser="B 1.0", os="O 1", device_type="mobile", success=False),  # thất bại
            dict(row_id=10**7 + 4, t=2 * DAY_US, uid=9002, ip="5.5.5.4", asn=4, country="XX", ua="uaX", browser="B 1.0", os="O 1", device_type="mobile", success=True),  # user khác
        ]
    )
    combined = pd.concat([events, extra], ignore_index=True)
    victim = pd.DataFrame(
        {
            "victim_id": [0, 1, 2, 3], "attacker_type": ["targeted"] * 4, "uid": [9001, 9001, 9001, 9002],
            "anchor_row_id": [10**7 + 2, 10**7 + 3, 10**7 + 4, 10**7 + 4],
            "anchor_us": [2 * DAY_US, 3 * DAY_US, 2 * DAY_US, 2 * DAY_US], "t_inj_us": [2 * DAY_US, 3 * DAY_US, 2 * DAY_US, 2 * DAY_US],
        }
    )
    results = set()
    for threads in (1, 2, 8):
        local = duckdb.connect()
        local.execute(f"PRAGMA threads={threads}")
        local.register("events_df", combined)
        local.execute("CREATE TABLE events_src AS SELECT * FROM events_df")
        A.simulate_attackers(local, victim, "events_src")
        results.add(tuple(local.execute("SELECT victim_id, a_country, a_asn, a_ua, a_browser, a_os, a_device FROM victim_profile ORDER BY victim_id").fetchall()))
    assert len(results) == 1  # cùng một kết quả bất kể số luồng
    # nạn nhân 1: đăng nhập gốc thất bại; nạn nhân 2: đăng nhập gốc của user khác; nạn nhân 3: chưa từng đăng nhập thành công trước mốc
    assert next(iter(results)) == ((0, "AA", 2, "uaA", "B 2.0", "O 2", "tablet"),)


def test_simulate_attackers_requires_the_anchor_login(world):
    events, victims, _, con = world
    with pytest.raises(ValueError, match="anchor_row_id"):
        A.simulate_attackers(con, victims.drop(columns=["anchor_row_id"]), "events_src")
