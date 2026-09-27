"""Nhóm "Đoán và dò mật khẩu": dò một tài khoản, nhồi thông tin đăng nhập, rải mật khẩu chậm, dò phân tán, dò danh sách tài khoản, thành công sau chuỗi sai.

Hai luật đầu (`brute_force`, `credential_stuffing`) là luật tầng 1 gốc (app/detection/rules.py) với NGƯỠNG MẶC ĐỊNH GIỮ NGUYÊN, được nâng cấp:
`credential_stuffing` thêm phạm vi ASN, nới ngưỡng khi thấy xoay User-Agent và loại trừ khi tỉ lệ thành công cao (cổng NAT của cơ quan).
"""

from __future__ import annotations

from app.detection.engine import indexes as K
from app.detection.engine.messages import window_text
from app.detection.engine.registry import Param, RuleContext, rule
from app.detection.engine.types import Finding

_DAY = 86_400

CATEGORY = "Đoán và dò mật khẩu"


@rule(
    id="brute_force",
    title="Dò mật khẩu một tài khoản",
    category=CATEGORY,
    severity="high",
    techniques=("T1110.001",),
    description="Nhiều lần đăng nhập sai vào CÙNG một tên đăng nhập trong thời gian ngắn (đoán mật khẩu), từ bất kỳ IP nào.",
    params=(
        Param("threshold", 5, "số lần sai tối thiểu để báo", "lần", 2, 1000),
        Param("window_s", 300, "độ dài cửa sổ", "giây", 10, _DAY),
    ),
    notes="Ngưỡng và cửa sổ là luật tầng 1 gốc (docs/api-contract.md mục 6, giả định chưa đối chiếu). Báo ở MỖI lần sai từ lần thứ `threshold` trở đi; gộp cảnh báo trùng là việc của MR13.",
)
def brute_force(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if a.success:
        return None
    fails = ctx.store.log_count(K.fail_user(a.username), ctx.since(p.window_s))
    if fails < p.threshold:
        return None
    return Finding(
        f"Dò mật khẩu '{a.username}': {fails} lần sai/{window_text(p.window_s)} (ngưỡng {p.threshold}).",
        {"username": a.username, "fails": fails, "window_s": p.window_s},
    )


@rule(
    id="credential_stuffing",
    title="Nhồi thông tin đăng nhập",
    category=CATEGORY,
    severity="high",
    techniques=("T1110.004",),
    description=(
        "Một IP (hoặc một nhà mạng/ASN) thử nhiều tên đăng nhập KHÁC NHAU với nhiều lần sai trong thời gian ngắn — dùng danh sách tài khoản/mật khẩu bị lộ. "
        "So với luật gốc: thêm phạm vi ASN (botnet xoay IP trong cùng nhà mạng), nới ngưỡng một nửa khi thấy xoay User-Agent, và bỏ qua khi tỉ lệ "
        "thành công cao (nhiều người dùng thật sau cùng một cổng NAT)."
    ),
    params=(
        Param("window_s", 300, "độ dài cửa sổ", "giây", 10, _DAY),
        Param("min_fails", 10, "số lần sai tối thiểu từ một IP", "lần", 2, 100_000),
        Param("min_users", 5, "số tên đăng nhập khác nhau tối thiểu từ một IP", "tên", 2, 100_000),
        Param("max_success_ratio", 0.5, "quá tỉ lệ thành công này (trên tổng thử của IP/ASN) thì coi là lưu lượng hợp lệ", "", 0.0, 1.0),
        Param("asn_min_fails", 40, "số lần sai tối thiểu từ một ASN (phạm vi ASN)", "lần", 2, 1_000_000),
        Param("asn_min_users", 20, "số tên đăng nhập khác nhau tối thiểu từ một ASN", "tên", 2, 1_000_000),
        Param("ua_rotation_min", 4, "số User-Agent khác nhau (trong các lần sai của IP) coi là đang xoay UA", "UA", 2, 1000),
        Param("ua_rotation_relax", 0.5, "hệ số nhân ngưỡng IP khi đang xoay UA (0,5 = nới một nửa)", "", 0.1, 1.0),
    ),
    needs=(),
    notes="Phạm vi ASN chỉ chạy khi biết ASN (GeoLite2-ASN). Ngưỡng IP (10 lần, 5 tên, 5 phút) là luật gốc.",
)
def credential_stuffing(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if a.success:
        return None
    since = ctx.since(p.window_s)
    store = ctx.store

    fails = store.log_count(K.fail_ip(a.ip), since)
    users = store.set_count(K.fail_users_of_ip(a.ip), since, K.CAP)
    oks = store.log_count(K.ok_ip(a.ip), since)
    rotating = store.set_count(K.fail_agents_of_ip(a.ip), since, p.ua_rotation_min) >= p.ua_rotation_min
    relax = p.ua_rotation_relax if rotating else 1.0
    if fails >= p.min_fails * relax and users >= p.min_users * relax and oks <= p.max_success_ratio * (oks + fails):
        return Finding(
            f"IP {a.ip} thử {users} tài khoản khác nhau, {fails} lần sai/{window_text(p.window_s)} "
            f"(ngưỡng {p.min_users} TK / {p.min_fails} lần" + (", nới do xoay User-Agent" if rotating else "") + ").",
            {"scope": "ip", "ip": a.ip, "fails": fails, "distinct_users": users, "successes": oks, "rotating_user_agent": rotating},
        )

    if a.asn is None:
        return None
    asn_fails = store.log_count(K.fail_asn(a.asn), since)
    asn_users = store.set_count(K.fail_users_of_asn(a.asn), since, K.CAP)
    asn_oks = store.log_count(K.ok_asn(a.asn), since)
    if asn_fails >= p.asn_min_fails and asn_users >= p.asn_min_users and asn_oks <= p.max_success_ratio * (asn_oks + asn_fails):
        return Finding(
            f"ASN {a.asn} thử {asn_users} tài khoản khác nhau, {asn_fails} lần sai/{window_text(p.window_s)} (ngưỡng {p.asn_min_users} TK / {p.asn_min_fails} lần).",
            {"scope": "asn", "asn": a.asn, "fails": asn_fails, "distinct_users": asn_users, "successes": asn_oks},
        )
    return None


@rule(
    id="password_spray_slow",
    title="Rải mật khẩu chậm",
    category=CATEGORY,
    severity="high",
    techniques=("T1110.003",),
    description=(
        "Một IP (hoặc ASN) thử NHIỀU tài khoản nhưng mỗi tài khoản chỉ vài lần, trải dài hàng giờ — một hai mật khẩu phổ biến rải khắp danh sách để "
        "né ngưỡng theo tài khoản và theo thời gian ngắn. Không báo khi tốc độ đã đủ nhanh để `credential_stuffing` xử lý."
    ),
    params=(
        Param("window_s", _DAY, "độ dài cửa sổ", "giây", 600, _DAY),
        Param("min_users", 15, "số tài khoản khác nhau tối thiểu từ một IP trong cửa sổ", "tên", 3, 100_000),
        Param("max_fails_per_user", 3.0, "trung bình tối đa số lần sai mỗi tài khoản (rải mỏng)", "lần/TK", 1.0, 100.0),
        Param("max_fails_per_hour", 120, "tối đa số lần sai của IP trong 1 giờ gần nhất; 120 = 10 lần/5 phút, ngưỡng nhồi thông tin quy ra giờ (nhanh hơn thì không phải \"chậm\")", "lần", 1, 100_000),
        Param("asn_min_users", 40, "số tài khoản khác nhau tối thiểu từ một ASN (phạm vi ASN)", "tên", 3, 1_000_000),
        Param("asn_max_fails_per_hour", 600, "tối đa số lần sai của ASN trong 1 giờ gần nhất (nhiều IP nên cho phép nhiều hơn một IP)", "lần", 1, 1_000_000),
    ),
    notes="Đếm tài khoản khác nhau bị chặn ở 200 (K.CAP) nên tỉ lệ lần sai/tài khoản là cận trên; IP tấn công khổng lồ do `credential_stuffing` bắt.",
)
def password_spray_slow(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if a.success:
        return None
    since, store = ctx.since(p.window_s), ctx.store
    hour = ctx.since(3600)

    users = store.set_count(K.fail_users_of_ip(a.ip), since, K.CAP)
    if users >= p.min_users:
        fails = store.log_count(K.fail_ip(a.ip), since)
        hourly = store.log_count(K.fail_ip(a.ip), hour)
        if fails <= p.max_fails_per_user * users and hourly <= p.max_fails_per_hour:
            return Finding(
                f"IP {a.ip} thử {users} tài khoản trong {window_text(p.window_s)}, mỗi tài khoản ≤ {p.max_fails_per_user:g} lần, chậm ({hourly} lần/giờ): rải mật khẩu.",
                {"scope": "ip", "ip": a.ip, "distinct_users": users, "fails": fails, "fails_last_hour": hourly},
            )
    if a.asn is None:
        return None
    asn_users = store.set_count(K.fail_users_of_asn(a.asn), since, K.CAP)
    if asn_users >= p.asn_min_users:
        asn_fails = store.log_count(K.fail_asn(a.asn), since)
        asn_hourly = store.log_count(K.fail_asn(a.asn), hour)
        if asn_fails <= p.max_fails_per_user * asn_users and asn_hourly <= p.asn_max_fails_per_hour:
            return Finding(
                f"ASN {a.asn} thử {asn_users} tài khoản trong {window_text(p.window_s)}, mỗi tài khoản ≤ {p.max_fails_per_user:g} lần: rải mật khẩu qua nhiều IP.",
                {"scope": "asn", "asn": a.asn, "distinct_users": asn_users, "fails": asn_fails, "fails_last_hour": asn_hourly},
            )
    return None


@rule(
    id="distributed_bruteforce",
    title="Dò mật khẩu phân tán vào một tài khoản",
    category=CATEGORY,
    severity="high",
    techniques=("T1110.001", "T1090"),
    description="Một tài khoản bị đoán mật khẩu từ NHIỀU IP khác nhau (mỗi IP chỉ vài lần nên không chạm ngưỡng theo IP), thường qua proxy hoặc botnet.",
    params=(
        Param("window_s", 3600, "độ dài cửa sổ", "giây", 60, _DAY),
        Param("min_fails", 8, "số lần sai tối thiểu vào tài khoản", "lần", 2, 100_000),
        Param("min_ips", 5, "số IP khác nhau tối thiểu", "IP", 2, 100_000),
    ),
)
def distributed_bruteforce(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if a.success:
        return None
    since = ctx.since(p.window_s)
    fails = ctx.store.log_count(K.fail_user(a.username), since)
    if fails < p.min_fails:
        return None
    ips = ctx.store.set_count(K.fail_ips_of_user(a.username), since, K.CAP)
    if ips < p.min_ips:
        return None
    return Finding(
        f"Tài khoản '{a.username}' bị {fails} lần sai từ {ips} IP khác nhau/{window_text(p.window_s)} (dò phân tán; ngưỡng {p.min_ips} IP / {p.min_fails} lần).",
        {"username": a.username, "fails": fails, "distinct_ips": ips, "window_s": p.window_s},
    )


@rule(
    id="username_enumeration",
    title="Dò danh sách tài khoản",
    category=CATEGORY,
    severity="medium",
    techniques=("T1589",),
    description="Một IP thử nhiều tên đăng nhập KHÔNG tồn tại — dò xem tài khoản nào có thật trước khi đoán mật khẩu.",
    params=(
        Param("window_s", 600, "độ dài cửa sổ", "giây", 10, _DAY),
        Param("min_usernames", 8, "số tên không tồn tại khác nhau tối thiểu từ một IP", "tên", 2, 100_000),
    ),
    notes="Ánh xạ MITRE gần đúng: ATT&CK xếp việc thu thập danh tính nạn nhân vào giai đoạn trinh sát (T1589), không có kỹ thuật riêng cho dò tên đăng nhập.",
)
def username_enumeration(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if a.success or a.user_exists:
        return None
    unknown = ctx.store.set_count(K.unknown_users_of_ip(a.ip), ctx.since(p.window_s), K.CAP)
    if unknown < p.min_usernames:
        return None
    return Finding(
        f"IP {a.ip} thử {unknown} tên đăng nhập không tồn tại/{window_text(p.window_s)} (dò danh sách tài khoản; ngưỡng {p.min_usernames}).",
        {"ip": a.ip, "distinct_unknown_usernames": unknown, "window_s": p.window_s},
    )


@rule(
    id="success_after_failures",
    title="Thành công sau chuỗi sai",
    category=CATEGORY,
    severity="high",
    techniques=("T1110.001",),
    description="Đăng nhập THÀNH CÔNG vào một tài khoản ngay sau nhiều lần sai gần đây (từ bất kỳ IP nào) — dấu hiệu kẻ tấn công đã đoán trúng mật khẩu.",
    params=(
        Param("window_s", 600, "độ dài cửa sổ nhìn lại", "giây", 10, _DAY),
        Param("min_fails", 5, "số lần sai tối thiểu trước đó vào tài khoản", "lần", 2, 100_000),
    ),
    needs=("account",),
    notes="Người dùng thật cũng gõ sai vài lần rồi đúng; ngưỡng 5 (cao hơn mức 3 của điểm rủi ro tầng 2) để giảm báo nhầm — cần đo trên log thật ở MR10.",
)
def success_after_failures(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if not a.success:
        return None
    since = ctx.since(p.window_s)
    fails = ctx.store.log_count(K.fail_user(a.username), since)
    if fails < p.min_fails:
        return None
    ips = ctx.store.set_count(K.fail_ips_of_user(a.username), since, K.CAP)
    return Finding(
        f"Đăng nhập thành công '{a.username}' sau {fails} lần sai/{window_text(p.window_s)} từ {ips} IP (có thể đã đoán trúng mật khẩu).",
        {"username": a.username, "fails_before": fails, "distinct_ips_before": ips, "window_s": p.window_s},
    )
