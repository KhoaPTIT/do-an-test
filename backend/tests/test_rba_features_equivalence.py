"""MR3 — chứng minh đường SQL (DuckDB, chạy trên toàn bộ dữ liệu) cho ĐÚNG kết quả như đặc tả Python,
và đặc trưng không rò rỉ thông tin từ tương lai.

Dữ liệu ngẫu nhiên có cố ý: sự kiện trùng micro-giây, sự kiện cách đúng 1h/24h/7d (sát biên cửa sổ),
tài khoản không tồn tại, ASN/quốc gia/UA thiếu, chuỗi thất bại rồi thành công.
"""

import math

import duckdb
import numpy as np
import pandas as pd
import pytest

from ml.rba import features as F
from ml.rba.features import EventRecord, W_1H, W_24H, W_7D
from ml.rba.features_sql import compute_features_sql

_BROWSERS = ["Chrome 90.0.1", "Chrome 91.0.2", "Firefox 80.0", "Safari 13.1", "Edge 88", "Other", None]
_OSES = ["Windows 10", "Windows 7", "Android 10.0", "iOS 13.4", "Linux", None]
_DEVICES = ["mobile", "desktop", "tablet", "bot", "unknown", None, "weird"]
_COUNTRIES = ["NO", "US", "RU", "DE", "NA", None]
_ASNS = [None, 100, 200, 300, 400]


def make_events(n_bursts=14, per_burst=48, seed=0):
    rng = np.random.default_rng(seed)
    users = [None] * 3 + list(range(1, 21))  # None nhiều hơn 1 lần để có nhiều lần thử vào tài khoản không tồn tại
    ips = [f"10.0.{i // 8}.{i % 8}" for i in range(30)]
    uas = [f"ua{i}" for i in range(10)] + [None]

    def random_event(t, base=None):
        pick = lambda seq: seq[int(rng.integers(len(seq)))]
        if base is not None and rng.random() < 0.85:  # phần lớn bản sao giữ nguyên user/IP/ASN để chạm cửa sổ
            return EventRecord(t, base.user_id, base.ip, base.asn, pick(_COUNTRIES), pick(uas), pick(_BROWSERS), pick(_OSES), pick(_DEVICES), bool(rng.random() < 0.6))
        return EventRecord(t, pick(users), pick(ips), pick(_ASNS), pick(_COUNTRIES), pick(uas), pick(_BROWSERS), pick(_OSES), pick(_DEVICES), bool(rng.random() < 0.55))

    events = []
    for center in rng.uniform(0, 30 * W_24H, n_bursts):
        for offset in rng.exponential(45 * 60 * 1_000_000, per_burst):
            events.append(random_event(int(center + offset)))

    anchors = [events[int(i)] for i in rng.integers(0, len(events), 60)]
    for anchor in anchors:
        for window in (W_1H, W_24H, W_7D):
            for delta in (-1, 0, 1):  # sát biên: cách đúng W-1, W, W+1 micro-giây
                events.append(random_event(anchor.ts_us - window - delta, base=anchor))
        events.append(random_event(anchor.ts_us, base=anchor))  # trùng micro-giây

    events.sort(key=lambda e: e.ts_us)
    return events


def to_frame(events):
    return pd.DataFrame(
        {
            "row_id": range(len(events)),
            "t": [e.ts_us for e in events],
            "uid": pd.array([e.user_id for e in events], dtype="Int64"),
            "ip": [e.ip for e in events],
            "asn": pd.array([e.asn for e in events], dtype="Int64"),
            "country": [e.country for e in events],
            "ua": [e.ua for e in events],
            "browser": [e.browser for e in events],
            "os": [e.os for e in events],
            "device_type": [e.device_type for e in events],
            "success": [e.success for e in events],
        }
    )


def sql_features(events, output_ids_sql=None, **kwargs):
    con = duckdb.connect()
    frame = to_frame(events)
    con.register("t_events", frame)
    compute_features_sql(con, "SELECT * FROM t_events", output_ids_sql, **kwargs)
    return con.execute("SELECT * FROM features ORDER BY row_id").df().set_index("row_id")


def spec_features(events, indices):
    return pd.DataFrame([F.compute_features_spec(events[i], events) for i in indices], index=list(indices))[F.FEATURE_NAMES]


@pytest.fixture(scope="module")
def events():
    return make_events()


def test_generated_data_really_exercises_ties_and_boundaries(events):
    times = [e.ts_us for e in events]
    assert len(times) != len(set(times))  # có sự kiện trùng micro-giây
    pairs = {(a, b) for a in times for b in times if a - b in (W_1H, W_24H, W_7D)}
    assert len(pairs) > 30  # có nhiều cặp cách đúng 1h/24h/7d
    assert any(e.user_id is None for e in events) and any(e.asn is None for e in events)


def test_sql_and_python_spec_agree_on_every_feature(events):
    sql = sql_features(events)
    indices = range(len(events))
    spec = spec_features(events, indices)

    assert list(sql.columns) == F.FEATURE_NAMES
    assert len(sql) == len(events)
    mismatches = []
    for name in F.FEATURE_NAMES:
        a, b = sql[name].to_numpy(dtype=float), spec[name].to_numpy(dtype=float)
        ok = np.isclose(a, b, rtol=1e-9, atol=1e-9, equal_nan=True)
        if not ok.all():
            first = int(np.flatnonzero(~ok)[0])
            mismatches.append(f"{name}: dòng {first} SQL={a[first]} spec={b[first]} (tổng {int((~ok).sum())} dòng lệch)")
    assert not mismatches, "\n".join(mismatches)


def test_features_for_a_subset_of_rows_equal_features_computed_for_all(events):
    subset = list(range(0, len(events), 7))
    con_ids = "SELECT row_id FROM src WHERE row_id % 7 = 0"
    partial = sql_features(events, con_ids)
    full = sql_features(events)
    assert list(partial.index) == subset
    pd.testing.assert_frame_equal(partial, full.loc[subset], check_exact=False, rtol=1e-12, atol=1e-12)


@pytest.mark.parametrize("chunk_rows", [400, 120, 37])
def test_infra_stage_chunked_by_time_gives_identical_features(events, chunk_rows):
    single = sql_features(events, infra_chunk_rows=len(events) + 1)
    chunked = sql_features(events, infra_chunk_rows=chunk_rows)
    pd.testing.assert_frame_equal(single, chunked, check_exact=False, rtol=1e-12, atol=1e-12)


def test_future_events_never_change_the_features_of_earlier_events(events):
    cut = len(events) * 2 // 3
    boundary_t = events[cut].ts_us
    while cut > 0 and events[cut - 1].ts_us == boundary_t:  # không cắt giữa các sự kiện trùng giờ
        cut -= 1

    truncated = sql_features(events[:cut])
    full = sql_features(events).iloc[:cut]
    pd.testing.assert_frame_equal(truncated, full, check_exact=False, rtol=1e-12, atol=1e-12)

    later = events[cut:]
    assert later and all(e.ts_us >= events[cut].ts_us for e in later)


def test_spec_ignores_events_at_or_after_the_current_time(events):
    target_index = len(events) // 2
    target = events[target_index]
    only_past = [e for e in events if e.ts_us < target.ts_us]
    with_future = events  # có cả sự kiện trùng giờ và sự kiện tương lai
    a = F.compute_features_spec(target, only_past)
    b = F.compute_features_spec(target, with_future)
    for name in F.FEATURE_NAMES:
        assert (math.isnan(a[name]) and math.isnan(b[name])) or a[name] == b[name], name
