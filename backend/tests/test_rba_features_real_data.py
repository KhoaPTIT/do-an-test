"""MR3 — đối chiếu đặc trưng trên một lát DỮ LIỆU RBA THẬT (60.000 dòng đầu của Parquet đầy đủ).

Tự bỏ qua nếu chưa chạy `python -m ml.rba.etl`. Bổ sung cho test ngẫu nhiên: xác nhận không có gì
lạ trong dữ liệu thật (giá trị thiếu, chuỗi UA dài, tài khoản "thùng chứa"...) làm lệch SQL khỏi đặc tả.
"""

import math

import duckdb
import numpy as np
import pandas as pd
import pytest

from ml.rba import features as F
from ml.rba.build_features import events_sql_for_full
from ml.rba.etl import FULL_PARQUET
from ml.rba.features import EventRecord
from ml.rba.features_sql import compute_features_sql

pytestmark = pytest.mark.skipif(not FULL_PARQUET.is_file(), reason="chưa có rba_full.parquet")

SLICE_ROWS = 60_000


@pytest.fixture(scope="module")
def con():
    connection = duckdb.connect()
    connection.execute(f"CREATE VIEW full_events AS {events_sql_for_full(FULL_PARQUET)}")
    connection.execute(f"CREATE TABLE slice_events AS SELECT * FROM full_events WHERE row_id < {SLICE_ROWS}")
    return connection


@pytest.fixture(scope="module")
def slice_df(con):
    return con.execute("SELECT * FROM slice_events ORDER BY row_id").df()


def _records(df):
    def none_if_na(value):
        return None if pd.isna(value) else value

    return [
        EventRecord(
            ts_us=int(r.t),
            user_id=None if pd.isna(r.uid) else int(r.uid),
            ip=r.ip,
            asn=None if pd.isna(r.asn) else int(r.asn),
            country=none_if_na(r.country),
            ua=none_if_na(r.ua),
            browser=none_if_na(r.browser),
            os=none_if_na(r.os),
            device_type=none_if_na(r.device_type),
            success=bool(r.success),
        )
        for r in df.itertuples(index=False)
    ]


def _pick_rows(df):
    """Các dòng đại diện: có lịch sử dài, vừa thành công vừa thất bại, cả tài khoản không tồn tại."""
    rng = np.random.default_rng(3)
    counts = df.groupby("uid").cumcount()
    with_history = df.index[(counts >= 4) & df["uid"].notna() & (df.index >= SLICE_ROWS // 2)].to_list()
    unknown = df.index[df["uid"].isna() & (df.index >= SLICE_ROWS // 2)].to_list()
    failures = df.index[(~df["success"]) & df["uid"].notna() & (counts >= 2)].to_list()
    return sorted(set(rng.choice(with_history, 14, replace=False)) | set(rng.choice(unknown, 5, replace=False)) | set(rng.choice(failures, 6, replace=False)))


def test_sql_matches_spec_on_real_slice(con, slice_df):
    picked = _pick_rows(slice_df)
    ids = ",".join(str(int(slice_df.loc[i, "row_id"])) for i in picked)
    compute_features_sql(con, "SELECT * FROM slice_events", f"SELECT row_id FROM slice_events WHERE row_id IN ({ids})")
    sql = con.execute("SELECT * FROM features ORDER BY row_id").df().set_index("row_id")

    events = _records(slice_df)
    spec = pd.DataFrame([F.compute_features_spec(events[i], events) for i in picked], index=[int(slice_df.loc[i, "row_id"]) for i in picked])

    mismatches = []
    for name in F.FEATURE_NAMES:
        a, b = sql[name].to_numpy(dtype=float), spec[name].to_numpy(dtype=float)
        ok = np.isclose(a, b, rtol=1e-9, atol=1e-9, equal_nan=True)
        if not ok.all():
            mismatches.append(f"{name}: {int((~ok).sum())} dòng lệch (SQL={a[~ok][0]}, spec={b[~ok][0]})")
    assert not mismatches, "\n".join(mismatches)
    assert sql["u_n_attempts"].notna().sum() >= 15  # thật sự có dòng với lịch sử user
    assert sql["u_n_attempts"].isna().sum() >= 3  # và có dòng tài khoản không tồn tại


def test_future_events_do_not_change_earlier_features_on_real_data(con):
    early_rows = 40_000
    compute_features_sql(
        con,
        f"SELECT * FROM slice_events WHERE row_id < {early_rows}",
        f"SELECT row_id FROM slice_events WHERE row_id < {early_rows}",
    )
    truncated = con.execute("SELECT * FROM features ORDER BY row_id").df().set_index("row_id")

    compute_features_sql(con, "SELECT * FROM slice_events", f"SELECT row_id FROM slice_events WHERE row_id < {early_rows}")
    with_future = con.execute("SELECT * FROM features ORDER BY row_id").df().set_index("row_id")

    assert len(truncated) == early_rows
    pd.testing.assert_frame_equal(truncated, with_future, check_exact=False, rtol=1e-12, atol=1e-12)


def test_real_data_features_are_informative(con):
    compute_features_sql(con, "SELECT * FROM slice_events")
    df = con.execute("SELECT * FROM features").df()
    for name in ("llr_sum", "rare_asn", "ip_attempts_24h", "asn_distinct_users_24h"):
        assert df[name].nunique() > 20, f"{name} gần như hằng số trên dữ liệu thật"
    assert df["u_fail_streak"].nunique() > 5  # đếm số nguyên nhỏ nên ít giá trị khác nhau hơn
    assert not math.isnan(df["ip_fail_ratio_24h"].mean())
