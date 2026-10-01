"""Nhóm "Ngữ cảnh tài khoản": di chuyển bất khả thi, nhiều quốc gia cùng lúc, nhảy quốc gia, tài khoản ngủ đông, nhà mạng cực hiếm.

Các luật này so lần đăng nhập với QUÁ KHỨ của tài khoản (`ctx.history`) hoặc của cả hệ thống (`ctx.stats`); lịch sử chỉ chứa các lần thử TRƯỚC lần đang chấm.
"""

from __future__ import annotations

from app.detection.engine import indexes as K
from app.detection.engine.messages import window_text
from app.detection.engine.registry import Param, RuleContext, rule
from app.detection.engine.types import Finding
from app.detection.rules import IMPOSSIBLE_TRAVEL_SPEED_KMH, haversine_distance

CATEGORY = "Ngữ cảnh tài khoản"
_DAY = 86_400


@rule(
    id="impossible_travel",
    verification="verified",  # Milestone A — artifacts/behavior_verification/impossible_travel.json
    title="Di chuyển bất khả thi",
    category=CATEGORY,
    severity="high",
    techniques=("T1078",),
    description=(
        "Hai lần đăng nhập THÀNH CÔNG liên tiếp của một tài khoản cách nhau quá xa so với thời gian trôi qua (tốc độ vượt ngưỡng của máy bay). "
        "Lần thử SAI không được tính: nó không chứng minh chủ tài khoản đã ở nơi đó (thử sai từ nhiều nước là việc của country_hop/brute_force)."
    ),
    params=(Param("max_speed_kmh", IMPOSSIBLE_TRAVEL_SPEED_KMH, "tốc độ di chuyển tối đa hợp lý", "km/h", 100.0, 20_000.0),),
    needs=("account", "geo", "history"),
    notes="Luật tầng 1 gốc (ngưỡng 900 km/h lấy nguyên văn từ checklist). Bỏ qua khi thiếu GeoIP ở một trong hai lần. VPN/proxy làm sai lệch vị trí. Không chạy được trên RBA (không có toạ độ).",
)
def impossible_travel(ctx: RuleContext) -> Finding | None:
    a, h, p = ctx.attempt, ctx.history, ctx.p
    if not a.success or h is None or h.last_success_ts is None or h.last_success_lat is None or h.last_success_lon is None:
        return None
    elapsed_hours = (a.ts - h.last_success_ts) / 3600
    if elapsed_hours <= 0:
        return None  # timestamp trùng/không hợp lệ: không kết luận được
    distance = haversine_distance(h.last_success_lat, h.last_success_lon, a.latitude, a.longitude)
    speed = distance / elapsed_hours
    if speed <= p.max_speed_kmh:
        return None
    return Finding(
        f"Cách {distance:.0f}km chỉ sau {elapsed_hours * 60:.1f} phút (~{speed:,.0f} km/h, ngưỡng {p.max_speed_kmh:.0f}).",
        {
            "distance_km": round(distance, 1), "elapsed_minutes": round(elapsed_hours * 60, 2), "speed_kmh": round(speed, 1),
            "previous_latitude": h.last_success_lat, "previous_longitude": h.last_success_lon,  # frontend vẽ đường nối hai điểm trên bản đồ
        },
    )


@rule(
    id="multi_context_simultaneous",
    title="Đăng nhập cùng lúc từ nhiều quốc gia",
    category=CATEGORY,
    severity="high",
    techniques=("T1078",),
    description="Một tài khoản có đăng nhập THÀNH CÔNG từ hai quốc gia khác nhau trong vài phút — hai phiên song song không thể cùng một người. Bổ sung cho `impossible_travel` khi thiếu toạ độ.",
    params=(
        Param("window_s", 600, "độ dài cửa sổ", "giây", 10, _DAY),
        Param("min_countries", 2, "số quốc gia khác nhau tối thiểu", "nước", 2, 50),
    ),
    needs=("account", "country"),
    notes="Người dùng thật dùng VPN trên một thiết bị và đăng nhập thiết bị khác không VPN sẽ khớp; cần đối chiếu thiết bị ở MR11.",
)
def multi_context_simultaneous(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if not a.success:
        return None
    values = ctx.store.set_values(K.contexts_of_user(a.user_key), ctx.since(p.window_s), limit=K.CAP)
    countries = sorted({v.split("|", 1)[0] for v in values if not v.startswith("?|")})
    if len(countries) < p.min_countries:
        return None
    return Finding(
        f"Tài khoản '{a.username}' đăng nhập thành công từ {len(countries)} quốc gia ({', '.join(countries)}) trong {window_text(p.window_s)}.",
        {"username": a.username, "countries": countries, "window_s": p.window_s},
    )


@rule(
    id="country_hop",
    verification="verified",  # Milestone B — artifacts/behavior_verification/country_hop.json
    title="Tài khoản bị thử từ nhiều quốc gia",
    category=CATEGORY,
    severity="medium",
    techniques=("T1078", "T1090"),
    description=(
        "Một tên đăng nhập bị thử SAI từ nhiều quốc gia khác nhau trong 24 giờ — proxy xoay vòng theo nước hoặc botnet toàn cầu. "
        "Mặc định chỉ đếm lần THẤT BẠI: người đi công tác đăng nhập ĐÚNG ở nhiều nước không phải dấu hiệu tấn công."
    ),
    params=(
        Param("window_s", _DAY, "độ dài cửa sổ", "giây", 600, 7 * _DAY),
        Param("min_countries", 3, "số quốc gia khác nhau tối thiểu", "nước", 2, 50),
        Param("failures_only", True, "chỉ đếm quốc gia của các lần thử THẤT BẠI (false = mọi lần thử, hành vi trước Milestone B)"),
    ),
    needs=("country",),
    default_mode="enforce",  # Milestone B: shadow -> enforce sau khi qua kiểm chứng (chỉ tạo cảnh báo, không tự step_up/lock)
    notes=(
        "Milestone B: chỉ khớp ở lần thử THẤT BẠI và chỉ đếm quốc gia của lần thất bại (`failures_only`) — trước đó đếm cả lần thành công nên "
        "khách du lịch hợp lệ có thể khớp. Người dùng VPN đổi nước liên tục vẫn có thể khớp nếu gõ sai nhiều lần."
    ),
)
def country_hop(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if p.failures_only and a.success:
        return None
    key = K.fail_countries_of_username(a.username) if p.failures_only else K.countries_of_username(a.username)
    values = ctx.store.set_values(key, ctx.since(p.window_s), limit=K.CAP)
    if len(values) < p.min_countries:
        return None
    return Finding(
        f"Tài khoản '{a.username}' bị thử {'sai ' if p.failures_only else ''}từ {len(values)} quốc gia ({', '.join(sorted(values))}) trong {window_text(p.window_s)} (ngưỡng {p.min_countries}).",
        {"username": a.username, "distinct_countries": len(values), "countries": sorted(values), "window_s": p.window_s, "failures_only": p.failures_only},
    )


@rule(
    id="dormant_account_login",
    verification="verified",  # Milestone A — artifacts/behavior_verification/dormant_account_login.json
    title="Tài khoản ngủ đông đăng nhập lại",
    category=CATEGORY,
    severity="medium",
    techniques=("T1078",),
    description="Tài khoản không có lần đăng nhập thành công nào trong nhiều tháng bỗng đăng nhập lại (mặc định chỉ báo khi kèm quốc gia hoặc thiết bị chưa từng thấy).",
    params=(
        Param("dormant_days", 90, "số ngày không đăng nhập thành công để coi là ngủ đông", "ngày", 1, 3650),
        Param("require_change", True, "chỉ báo khi lần này có quốc gia hoặc thiết bị mới so với lịch sử"),
    ),
    needs=("account", "history"),
    notes="Người dùng thật quay lại sau kỳ nghỉ là chuyện thường: mặc định phải kèm dấu hiệu 'mới' để giảm báo nhầm.",
)
def dormant_account_login(ctx: RuleContext) -> Finding | None:
    a, h, p = ctx.attempt, ctx.history, ctx.p
    if not a.success or h is None or h.last_success_ts is None:
        return None
    idle_days = (a.ts - h.last_success_ts) / _DAY
    if idle_days < p.dormant_days:
        return None
    new_country = bool(a.country) and a.country not in h.known_countries
    new_device = bool(a.ua_hash) and a.ua_hash not in h.known_devices
    if p.require_change and not (new_country or new_device):
        return None
    changes = [label for flag, label in ((new_country, f"quốc gia mới {a.country}"), (new_device, "thiết bị mới")) if flag]
    return Finding(
        f"Tài khoản '{a.username}' ngủ đông {idle_days:.0f} ngày rồi đăng nhập lại" + (f" ({', '.join(changes)})" if changes else "") + ".",
        {"idle_days": round(idle_days, 1), "new_country": new_country, "new_device": new_device, "country": a.country},
    )


@rule(
    id="rare_network_login",
    title="Đăng nhập từ nhà mạng cực hiếm",
    category=CATEGORY,
    severity="medium",
    techniques=("T1078",),
    description="Đăng nhập thành công từ một ASN mà tỉ lệ đăng nhập thành công của CẢ HỆ THỐNG từ ASN đó cực nhỏ (hoặc chưa từng có) — nhà mạng lạ so với mọi người dùng khác.",
    params=(
        Param("max_share", 2e-5, "tỉ lệ đăng nhập thành công của cả hệ thống từ ASN này (bằng hoặc thấp hơn thì báo)", "", 0.0, 0.01),
        Param("min_total", 20_000, "số đăng nhập thành công toàn hệ thống tối thiểu trước khi luật có hiệu lực (thống kê quá ít thì ASN nào cũng 'hiếm')", "lần", 100, 100_000_000),
    ),
    needs=("account", "asn", "global_stats"),
    default_mode="shadow",
    notes=(
        "Thêm theo quyết định D3 ở CP2. Trên RBA, luật một đặc trưng `rare_asn` với ngưỡng ở phân vị 99 của đăng nhập hợp lệ bắt 65,8% trong 38 ATO tương lai (chẩn đoán MR7, chọn sau "
        "khi đã thấy ATO) nhưng ATO của bộ dữ liệu tổng hợp đến từ nhà mạng hiếm một cách nhân tạo, nên đánh giá luật trên ATO của RBA mang tính vòng tròn; giá trị thật đo bằng kịch bản "
        "mô phỏng ở MR18. Ngưỡng mặc định 2e-5 ≈ phân vị 99 của đăng nhập hợp lệ ở RBA; chỉnh ở MR10."
    ),
)
def rare_network_login(ctx: RuleContext) -> Finding | None:
    a, p, stats = ctx.attempt, ctx.p, ctx.stats
    if not a.success:
        return None
    total = stats.total_successes
    if total < p.min_total:
        return None
    seen = stats.asn_successes(a.asn)  # chưa gồm lần này: thống kê được cập nhật SAU khi chấm
    share = seen / total
    if share > p.max_share:
        return None
    return Finding(
        f"Đăng nhập từ nhà mạng cực hiếm AS{a.asn}: {seen} lần trong {total:,} lượt thành công ({share:.4%}; ngưỡng {p.max_share:.4%}).",
        {"asn": a.asn, "asn_successes": seen, "total_successes": total, "share": share, "never_seen": seen == 0},
    )
