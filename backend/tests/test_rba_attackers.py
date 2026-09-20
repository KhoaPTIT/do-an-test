"""MR4 — mô phỏng kẻ tấn công: mỗi loại đúng "biết gì về nạn nhân", đặc trưng đúng pipeline MR3."""

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
    victims = pd.DataFrame(
        {
            "victim_id": np.arange(30),
            "attacker_type": [A.ATTACKER_TYPES[i % 3] for i in range(30)],
            "uid": picked.astype("int64"),
            "anchor_us": np.full(30, 9 * DAY_US, dtype=np.int64),
            "t_inj_us": (10 * DAY_US + rng.integers(0, 5 * DAY_US, 30)).astype(np.int64),
        }
    )
    injected = A.simulate_attackers(con, victims, "events_src", seed=5)
    return events, victims, injected, con


def victim_profile(events, victim):
    prior = events[(events["uid"] == victim.uid) & (events["t"] < victim.t_inj_us) & events["success"]]
    return prior, {col: prior[col].mode().iloc[0] for col in ("country", "asn", "ua", "browser", "os", "device_type")}


def test_every_victim_gets_one_successful_login_at_the_planned_time(world):
    events, victims, injected, _ = world
    assert len(injected) == len(victims)
    assert injected["victim_id"].is_unique and injected["row_id"].is_unique
    assert (injected["row_id"] >= A.INJECT_ROW_ID_BASE).all()
    assert injected["success"].all()
    merged = injected.merge(victims, on="victim_id", suffixes=("", "_v"))
    assert (merged["t"] == merged["t_inj_us"]).all() and (merged["uid"] == merged["uid_v"]).all()
    assert set(injected["attacker_type"]) == set(A.ATTACKER_TYPES)


def test_naive_attacker_copies_a_real_login_of_someone_else_from_the_same_hour(world):
    events, victims, injected, _ = world
    for row in injected[injected["attacker_type"] == "naive"].itertuples():
        window = events[(events["t"] < row.t) & (events["t"] >= row.t - A.HOUR_US) & events["success"] & (events["uid"] != row.uid)]
        assert ((window["ip"] == row.ip) & (window["ua"] == row.ua) & (window["country"] == row.country)).any()


def test_vpn_attacker_uses_the_victims_most_common_country_but_not_her_device(world):
    events, victims, injected, _ = world
    seen_other_ua = 0
    for row in injected[injected["attacker_type"] == "vpn"].itertuples():
        _, profile = victim_profile(events, victims.loc[victims.victim_id == row.victim_id].iloc[0])
        assert row.country == profile["country"]
        seen_other_ua += row.ua != profile["ua"]
    assert seen_other_ua > 0  # kẻ tấn công VPN không biết thiết bị của nạn nhân


def test_targeted_attacker_matches_asn_and_device_but_uses_a_new_ip(world):
    events, victims, injected, _ = world
    for row in injected[injected["attacker_type"] == "targeted"].itertuples():
        victim = victims.loc[victims.victim_id == row.victim_id].iloc[0]
        prior, profile = victim_profile(events, victim)
        assert row.asn == profile["asn"]
        assert (row.ua, row.browser, row.os, row.device_type) == (profile["ua"], profile["browser"], profile["os"], profile["device_type"])
        assert row.ip not in set(prior["ip"])


def test_simulation_is_deterministic_and_seed_dependent(world):
    events, victims, injected, con = world
    again = A.simulate_attackers(con, victims, "events_src", seed=5)
    other = A.simulate_attackers(con, victims, "events_src", seed=6)
    pd.testing.assert_frame_equal(injected, again)
    assert not injected["ip"].equals(other["ip"])


def test_victim_without_any_donor_is_dropped(world):
    events, victims, _, con = world
    lonely = victims.iloc[[0]].copy()
    lonely["t_inj_us"] = 400 * DAY_US  # xa mọi sự kiện: không có người cho trong 24h trước
    lonely["attacker_type"] = "naive"
    assert A.simulate_attackers(con, lonely, "events_src", seed=5).empty


def test_select_victims_uses_only_eligible_rows_and_balances_types():
    rng = np.random.default_rng(0)
    n = 3000
    users = rng.integers(0, 900, n)
    ts = pd.Timestamp("2020-09-01") + pd.to_timedelta(rng.integers(0, 80 * 24 * 3600, n), unit="s")
    table = pd.DataFrame(
        {
            "user_id": users, "ts": ts, "partition": "test", "in_warmup": False, "cur_success": 1.0,
            "is_attack_ip": rng.random(n) < 0.1, "is_ato": False,
        }
    )
    table.loc[table["user_id"] < 5, "partition"] = "train"  # 5 user đầu không có đăng nhập ở giai đoạn test
    victims = A.select_victims(table, A.SimulationConfig(per_type=100, seed=3))
    assert victims["uid"].is_unique and len(victims) == 300
    assert set(victims["attacker_type"]) == set(A.ATTACKER_TYPES)
    assert victims["attacker_type"].value_counts().nunique() == 1  # chia đều
    assert not (set(victims["uid"]) & set(range(5)))
    assert (victims["t_inj_us"] > victims["anchor_us"]).all()
    assert (victims["t_inj_us"] < A._to_us(splits.TEST_END)).all()
    offsets = (victims["t_inj_us"] - victims["anchor_us"]) / A.HOUR_US
    assert offsets.min() >= 1 / 3600  # luôn sau mốc


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


def test_modal_profile_is_deterministic_when_two_values_tie(world):
    events, victims, _, con = world
    # nạn nhân chỉ có đúng 2 lần thành công, ở 2 quốc gia khác nhau (hoà 1-1)
    two = pd.DataFrame(
        [
            dict(row_id=10**7 + 1, t=1 * DAY_US, uid=9001, ip="5.5.5.1", asn=1, country="ZZ", ua="uaZ", browser="B 1.0", os="O 1", device_type="mobile", success=True),
            dict(row_id=10**7 + 2, t=2 * DAY_US, uid=9001, ip="5.5.5.2", asn=2, country="AA", ua="uaA", browser="B 1.0", os="O 1", device_type="mobile", success=True),
        ]
    )
    combined = pd.concat([events, two], ignore_index=True)
    victim = pd.DataFrame(
        {"victim_id": [0], "attacker_type": ["vpn"], "uid": [9001], "anchor_us": [2 * DAY_US], "t_inj_us": [10 * DAY_US + 5]}
    )
    results = set()
    for threads in (1, 2, 8):
        local = duckdb.connect()
        local.execute(f"PRAGMA threads={threads}")
        local.register("events_df", combined)
        local.execute("CREATE TABLE events_src AS SELECT * FROM events_df")
        A.simulate_attackers(local, victim, "events_src", seed=5)
        results.add(tuple(local.execute("SELECT m_country, m_asn FROM victim_profile").fetchall()[0]))
    assert len(results) == 1  # cùng một kết quả bất kể số luồng
    assert next(iter(results))[0] == "AA"  # hoà -> giá trị nhỏ nhất theo thứ tự chuỗi
