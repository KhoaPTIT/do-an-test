"""Đặc trưng v2 bằng DuckDB (MR3) — đường NHANH cho toàn bộ dữ liệu.

Tính đúng các đặc trưng được định nghĩa trong `features.py` (đặc tả Python), nhưng bằng window
function trên hàng chục triệu dòng. `tests/test_rba_features_equivalence.py` chứng minh hai bên
cho kết quả bằng nhau trên dữ liệu ngẫu nhiên (có sự kiện trùng micro-giây và sát biên cửa sổ).

Đầu vào `events_sql` là một câu SELECT trả các cột:
    row_id, t (micro-giây epoch, BIGINT), uid (BIGINT, NULL = tài khoản không tồn tại), ip, asn
    (BIGINT, có thể NULL), country, ua (định danh UA, dạng chuỗi), browser, os, device_type,
    success (BOOLEAN).
`output_ids_sql` (tuỳ chọn) là câu SELECT trả cột row_id các dòng cần đặc trưng; bỏ trống = mọi dòng.

Kết quả: bảng tạm `features(row_id, <FEATURE_NAMES>)` trong `con`.

Bốn giai đoạn, mỗi giai đoạn nhìn phần dữ liệu nó cần:
  - toàn cục  : đếm lũy kế lần đăng nhập THÀNH CÔNG của tài khoản thật (chỉ cần các dòng đó + dòng đầu ra);
  - hạ tầng   : cửa sổ theo IP / ASN trên MỌI sự kiện (kể cả tài khoản không tồn tại);
  - theo user : cửa sổ theo tài khoản, chỉ trên user có dòng đầu ra (lịch sử của họ nằm đủ trong dữ liệu);
  - ghép      : công thức LLR/độ hiếm/tỉ lệ.
"""

from __future__ import annotations

from typing import Callable

import duckdb

from ml.rba.features import (
    ALPHA, DEVICE_CODES, DEVICE_CODE_MISSING, FEATURE_NAMES, FREEMAN_ATTRS, NOVELTY_ATTRS, NULL_KEY,
    W_1H, W_24H, W_7D,
)

_KEY_EXPR = {
    "ip": "ip",
    "country": f"COALESCE(country, '{NULL_KEY}')",
    "asn": f"COALESCE(CAST(asn AS VARCHAR), '{NULL_KEY}')",
    "ua": f"COALESCE(ua, '{NULL_KEY}')",
    "browser": f"COALESCE(browser, '{NULL_KEY}')",
    "os": f"COALESCE(os, '{NULL_KEY}')",
    "device": f"COALESCE(device_type, '{NULL_KEY}')",
    "browser_family": f"regexp_replace(COALESCE(browser, '{NULL_KEY}'), ' +[0-9][0-9.]*$', '')",
    "os_family": f"regexp_replace(COALESCE(os, '{NULL_KEY}'), ' +[0-9][0-9.]*$', '')",
}

_PRIOR = "RANGE BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING"


def _count_where(condition: str, window: str) -> str:
    # Không dùng COUNT(*) FILTER (...) OVER: trên partition lớn DuckDB chạy theo đường bậc hai
    # (347 giây so với 12 giây cho 3 triệu dòng); SUM(CASE ...) cho cùng kết quả và nhanh hơn ~30 lần.
    return f"COALESCE(SUM(CASE WHEN {condition} THEN 1 ELSE 0 END) OVER {window}, 0)"


def _within(window_us: int) -> str:
    # (t - W, t): strictly trước và strictly trong cửa sổ, mở ở đầu cũ
    return f"RANGE BETWEEN {window_us - 1} PRECEDING AND 1 PRECEDING"


def _stage_global(con: duckdb.DuckDBPyConnection) -> None:
    """Đếm lũy kế "trước đó strictly" theo từng thuộc tính: gom theo (giá trị, thời điểm) rồi cộng dồn
    bằng ROWS. Cộng dồn qua các nhóm thời điểm cho đúng ngữ nghĩa "sự kiện cùng micro-giây không tính
    là trước đó" và nhanh hơn window RANGE 3-11 lần trên partition lớn (cửa sổ "tổng": 27 giây -> 2,4 giây
    cho 3 triệu dòng)."""
    key_cols = ", ".join(f"{_KEY_EXPR[a]} AS k_{a}" for a in FREEMAN_ATTRS)
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE ev_g AS
        SELECT s.row_id, s.t, (s.success AND s.uid IS NOT NULL) AS contrib, {key_cols}
        FROM src s
        WHERE (s.success AND s.uid IS NOT NULL) OR s.row_id IN (SELECT row_id FROM out_rows)
        """
    )
    con.execute("CREATE OR REPLACE TEMP TABLE ev_go AS SELECT * FROM ev_g WHERE row_id IN (SELECT row_id FROM out_rows)")

    def cumulative(name: str, key_expr: str | None) -> None:
        partition = f"PARTITION BY k " if key_expr else ""
        key_select = f"{key_expr} AS k, " if key_expr else ""
        group_by = "1, 2" if key_expr else "1"
        join_on = "e.t = cum.t" + (f" AND {key_expr.replace('k_', 'e.k_')} = cum.k" if key_expr else "")
        con.execute(
            f"""
            CREATE OR REPLACE TEMP TABLE g_{name} AS
            WITH grp AS (SELECT {key_select}t, SUM(contrib::INT) AS n FROM ev_g GROUP BY {group_by}),
                 cum AS (
                   SELECT {"k, " if key_expr else ""}t,
                          COALESCE(SUM(n) OVER ({partition}ORDER BY t ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING), 0) AS g
                   FROM grp
                 )
            SELECT e.row_id, cum.g AS g_{name} FROM ev_go e JOIN cum ON {join_on}
            """
        )

    cumulative("total", None)
    for a in FREEMAN_ATTRS:
        cumulative(a, f"k_{a}")

    joins = " ".join(f"JOIN g_{name} USING (row_id)" for name in ("total", *FREEMAN_ATTRS))
    columns = ", ".join(f"g_{name}" for name in ("total", *FREEMAN_ATTRS))
    con.execute(f"CREATE OR REPLACE TEMP TABLE st_glob AS SELECT o.row_id, {columns} FROM out_rows o {joins}")


def _infra_chunk_bounds(con: duckdb.DuckDBPyConnection, chunk_rows: int) -> list[int]:
    n, t_min, t_max = con.execute("SELECT COUNT(*), MIN(t), MAX(t) FROM ev_i").fetchone()
    n_chunks = max(1, -(-n // chunk_rows))
    if n_chunks == 1:
        return [t_min, t_max + 1]
    quantiles = [i / n_chunks for i in range(1, n_chunks)]
    inner = con.execute("SELECT quantile_disc(t, ?) FROM ev_i", [quantiles]).fetchone()[0]
    return sorted({t_min, *inner, t_max + 1})


def _stage_infra(
    con: duckdb.DuckDBPyConnection, chunk_rows: int = 3_000_000, say: Callable[[str], None] | None = None
) -> None:
    """Cửa sổ theo IP và ASN chỉ nhìn lại tối đa 24h nên có thể tính theo từng KHỐI thời gian (mỗi khối
    cộng thêm 24h ngữ cảnh phía trước) mà cho kết quả giống hệt tính một lượt. Tính một lượt trên 31 triệu
    dòng chạy siêu tuyến tính và tranh RAM (hơn 30 phút, có lúc treo); theo khối thì thời gian gần tuyến tính
    và bộ nhớ bị chặn. Riêng số lần IP từng xuất hiện (mọi thời điểm) cần toàn bộ lịch sử nên tính một lượt
    riêng — window đơn giản, rất rẻ."""
    con.execute(
        "CREATE OR REPLACE TEMP TABLE ev_i AS SELECT row_id, t, uid, ip, asn, success, COALESCE(ua, '"
        + NULL_KEY
        + "') AS k_ua FROM src"
    )
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE st_ip_all AS
        SELECT * FROM (
          SELECT row_id, COUNT(*) OVER (PARTITION BY ip ORDER BY t {_PRIOR}) AS ip_prior_attempts_all FROM ev_i
        ) WHERE row_id IN (SELECT row_id FROM out_rows)
        """
    )

    fails = _count_where("NOT success", "w24")
    unknown = _count_where("uid IS NULL", "w24")
    windows = f"WINDOW w1 AS (PARTITION BY {{p}} ORDER BY t {_within(W_1H)}), w24 AS (PARTITION BY {{p}} ORDER BY t {_within(W_24H)})"
    ip_columns = f"""COUNT(*) OVER w1 AS ip_attempts_1h,
               COUNT(*) OVER w24 AS ip_attempts_24h,
               {fails} AS ip_fails_24h,
               COUNT(DISTINCT uid) OVER w24 AS ip_distinct_users_24h,
               {unknown} AS ip_unknown_attempts_24h,
               COUNT(DISTINCT k_ua) OVER w24 AS ip_distinct_ua_24h"""
    asn_columns = f"""COUNT(*) OVER w1 AS asn_attempts_1h,
               COUNT(*) OVER w24 AS asn_attempts_24h,
               {fails} AS asn_fails_24h,
               COUNT(DISTINCT uid) OVER w24 AS asn_distinct_users_24h,
               COUNT(DISTINCT ip) OVER w24 AS asn_distinct_ips_24h,
               {unknown} AS asn_unknown_attempts_24h"""

    bounds = _infra_chunk_bounds(con, chunk_rows)
    con.execute("DROP TABLE IF EXISTS st_ip_w")
    con.execute("DROP TABLE IF EXISTS st_asn")
    for i, (lower, upper) in enumerate(zip(bounds, bounds[1:])):
        if say:
            say(f"hạ tầng: khối {i + 1}/{len(bounds) - 1}")
        con.execute(
            f"CREATE OR REPLACE TEMP TABLE ev_ic AS SELECT * FROM ev_i WHERE t >= {lower - W_24H} AND t < {upper}"
        )
        for table, partition, columns in (("st_ip_w", "ip", ip_columns), ("st_asn", "asn", asn_columns)):
            query = f"""
                SELECT row_id, {columns.replace("{p}", partition)}
                FROM (SELECT * FROM ev_ic)
                {windows.format(p=partition)}
            """
            # chỉ giữ dòng thuộc khối này và là dòng đầu ra (phần 24h phía trước chỉ là ngữ cảnh)
            filtered = f"""
                SELECT * FROM ({query}) w
                WHERE row_id IN (SELECT row_id FROM out_rows WHERE t >= {lower} AND t < {upper})
            """
            if i == 0:
                con.execute(f"CREATE OR REPLACE TEMP TABLE {table} AS {filtered}")
            else:
                con.execute(f"INSERT INTO {table} {filtered}")

    con.execute("CREATE OR REPLACE TEMP TABLE st_ip AS SELECT * FROM st_ip_w JOIN st_ip_all USING (row_id)")


def _stage_user(con: duckdb.DuckDBPyConnection) -> None:
    key_cols = ", ".join(f"{_KEY_EXPR[a]} AS k_{a}" for a in NOVELTY_ATTRS)
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE ev_u AS
        SELECT row_id, t, uid, success, ip, {key_cols}
        FROM src
        WHERE uid IN (SELECT DISTINCT uid FROM src WHERE uid IS NOT NULL AND row_id IN (SELECT row_id FROM out_rows))
        """
    )
    attr_counts = ",\n".join(
        _count_where("success", f"(PARTITION BY uid, k_{a} ORDER BY t {_PRIOR})") + f" AS c_{a}"
        for a in NOVELTY_ATTRS
    )
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE st_user AS
        SELECT * FROM (
          SELECT row_id,
            COUNT(*) OVER wall AS u_n_attempts,
            {_count_where('success', 'wall')} AS u_n_success,
            MIN(t) OVER wall AS u_first_t,
            MAX(t) OVER wall AS u_last_t,
            MAX(CASE WHEN success THEN t END) OVER wall AS u_last_success_t,
            MAX(CASE WHEN success THEN a_cum END) OVER wall AS u_last_success_acum,
            COUNT(*) OVER w1 AS u_attempts_1h,
            COUNT(*) OVER w24 AS u_attempts_24h,
            {_count_where('NOT success', 'w24')} AS u_fails_24h,
            COUNT(DISTINCT ip) OVER w24 AS u_distinct_ips_24h,
            COUNT(DISTINCT k_country) OVER w7 AS u_distinct_countries_7d,
            {attr_counts}
          FROM (
            SELECT *, COUNT(*) OVER (PARTITION BY uid ORDER BY t RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS a_cum
            FROM ev_u
          )
          WINDOW wall AS (PARTITION BY uid ORDER BY t {_PRIOR}),
                 w1 AS (PARTITION BY uid ORDER BY t {_within(W_1H)}),
                 w24 AS (PARTITION BY uid ORDER BY t {_within(W_24H)}),
                 w7 AS (PARTITION BY uid ORDER BY t {_within(W_7D)})
        ) WHERE row_id IN (SELECT row_id FROM out_rows)
        """
    )


def _final_expressions() -> dict[str, str]:
    expr: dict[str, str] = {}
    device_case = (
        "CASE "
        + " ".join(f"WHEN o.device_type = '{name}' THEN {code}" for name, code in DEVICE_CODES.items())
        + f" ELSE {DEVICE_CODE_MISSING} END"
    )
    expr["cur_success"] = "CASE WHEN o.success THEN 1.0 ELSE 0.0 END"
    expr["cur_device_code"] = device_case

    for a in NOVELTY_ATTRS:
        expr[f"new_{a}"] = f"CASE WHEN u.c_{a} IS NULL THEN NULL WHEN u.c_{a} = 0 THEN 1.0 ELSE 0.0 END"

    expr["u_n_attempts"] = "u.u_n_attempts"
    expr["u_n_success"] = "u.u_n_success"
    expr["u_age_days"] = f"(o.t - u.u_first_t) / {W_24H}.0"
    expr["u_secs_since_last"] = "(o.t - u.u_last_t) / 1000000.0"
    expr["u_secs_since_last_success"] = "(o.t - u.u_last_success_t) / 1000000.0"
    expr["u_fail_streak"] = "u.u_n_attempts - COALESCE(u.u_last_success_acum, 0)"
    for name in ("u_attempts_1h", "u_attempts_24h", "u_fails_24h", "u_distinct_ips_24h", "u_distinct_countries_7d"):
        expr[name] = f"u.{name}"

    for a in FREEMAN_ATTRS:
        pg = f"((g.g_{a} + 1.0) / (g.g_total + 1.0))"
        pu = f"((u.c_{a} + {ALPHA} * {pg}) / (u.u_n_success + {ALPHA}))"
        expr[f"rare_{a}"] = f"-LN({pg})"
        expr[f"llr_{a}"] = f"LN({pg}) - LN({pu})"
    expr["llr_sum"] = " + ".join(f"(LN((g.g_{a} + 1.0) / (g.g_total + 1.0)) - LN((u.c_{a} + {ALPHA} * ((g.g_{a} + 1.0) / (g.g_total + 1.0))) / (u.u_n_success + {ALPHA})))" for a in FREEMAN_ATTRS)

    for name in ("ip_attempts_1h", "ip_attempts_24h", "ip_distinct_users_24h", "ip_unknown_attempts_24h", "ip_distinct_ua_24h", "ip_prior_attempts_all"):
        expr[name] = f"i.{name}"
    expr["ip_fail_ratio_24h"] = "CASE WHEN i.ip_attempts_24h > 0 THEN i.ip_fails_24h * 1.0 / i.ip_attempts_24h END"

    for name in ("asn_attempts_1h", "asn_attempts_24h", "asn_distinct_users_24h", "asn_distinct_ips_24h"):
        expr[name] = f"CASE WHEN o.asn IS NULL THEN NULL ELSE n.{name} END"
    expr["asn_fail_ratio_24h"] = "CASE WHEN o.asn IS NOT NULL AND n.asn_attempts_24h > 0 THEN n.asn_fails_24h * 1.0 / n.asn_attempts_24h END"
    expr["asn_unknown_share_24h"] = "CASE WHEN o.asn IS NOT NULL AND n.asn_attempts_24h > 0 THEN n.asn_unknown_attempts_24h * 1.0 / n.asn_attempts_24h END"
    return expr


def compute_features_sql(
    con: duckdb.DuckDBPyConnection,
    events_sql: str,
    output_ids_sql: str | None = None,
    on_stage: Callable[[str], None] | None = None,
    infra_chunk_rows: int = 3_000_000,
) -> None:
    say = on_stage or (lambda _msg: None)
    con.execute(f"CREATE OR REPLACE TEMP VIEW src AS {events_sql}")
    ids_sql = output_ids_sql or "SELECT row_id FROM src"
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE out_rows AS SELECT s.row_id, s.t, s.asn, s.success, s.device_type "
        f"FROM src s WHERE s.row_id IN ({ids_sql})"
    )

    say("giai đoạn toàn cục (đếm lũy kế đăng nhập thành công)")
    _stage_global(con)
    say("giai đoạn hạ tầng (cửa sổ theo IP/ASN trên mọi sự kiện)")
    _stage_infra(con, infra_chunk_rows, say)
    say("giai đoạn theo user")
    _stage_user(con)
    say("ghép công thức")

    expressions = _final_expressions()
    missing = set(FEATURE_NAMES) - set(expressions)
    if missing:
        raise RuntimeError(f"thiếu công thức SQL cho đặc trưng: {sorted(missing)}")
    columns = ",\n  ".join(f"CAST({expressions[name]} AS DOUBLE) AS {name}" for name in FEATURE_NAMES)
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE features AS
        SELECT o.row_id,
          {columns}
        FROM out_rows o
        JOIN st_glob g USING (row_id)
        JOIN st_ip i USING (row_id)
        JOIN st_asn n USING (row_id)
        LEFT JOIN st_user u USING (row_id)
        ORDER BY o.row_id
        """
    )
