"""Nhóm "Tự động hoá": User-Agent bot, client kịch bản (curl, python-requests...), xoay User-Agent, nhịp thử đều như máy.

Không luật nào ở đây kết luận "là tấn công" một mình: người dùng thật cũng có thể dùng script hợp lệ. Chúng cho biết lưu lượng do MÁY sinh ra; ý nghĩa
được quyết định khi kết hợp với luật đoán mật khẩu và mô hình (MR11).
"""

from __future__ import annotations

import statistics

from app.detection.engine import indexes as K
from app.detection.engine.messages import short, window_text
from app.detection.engine.registry import Param, RuleContext, rule
from app.detection.engine.types import Finding

CATEGORY = "Tự động hoá"

# Dấu hiệu (chữ thường) của HTTP client/công cụ dò quét/trình duyệt không đầu hay gặp trong tấn công. `okhttp` cố ý KHÔNG có: là thư viện của ứng dụng Android thật.
SCRIPT_MARKERS = (
    "curl/", "wget/", "httpie/", "python-requests", "python-urllib", "python-httpx", "aiohttp", "go-http-client", "libwww-perl", "java/", "apache-httpclient",
    "postmanruntime", "insomnia", "axios/", "node-fetch", "undici", "scrapy", "hydra", "sqlmap", "nikto", "nmap", "masscan",
    "headlesschrome", "phantomjs", "selenium", "playwright", "puppeteer",
)


@rule(
    id="bot_user_agent",
    title="User-Agent là bot",
    category=CATEGORY,
    severity="low",
    techniques=("T1110",),
    description="User-Agent được thư viện phân tích UA nhận là bot/trình thu thập tự động.",
    notes="Chỉ dựa vào UA nên kẻ tấn công nói dối UA là né được; giá trị là bắt các bot lười.",
)
def bot_user_agent(ctx: RuleContext) -> Finding | None:
    a = ctx.attempt
    if a.device_type != "bot":
        return None
    return Finding(f"User-Agent là bot/công cụ tự động: {short(a.user_agent)}.", {"user_agent": short(a.user_agent, 120)})


@rule(
    id="scripted_client",
    title="Client kịch bản / công cụ",
    category=CATEGORY,
    severity="medium",
    techniques=("T1110",),
    description="User-Agent thuộc một công cụ HTTP/dò quét ĐÃ BIẾT (curl, python-requests, HTTPie, Hydra, trình duyệt không đầu...).",
    params=(
        Param("markers", SCRIPT_MARKERS, "chuỗi con (chữ thường) của User-Agent coi là client kịch bản"),
        Param("flag_empty_ua", False, "coi User-Agent trống là client kịch bản (mặc định KHÔNG: thiếu UA chỉ là thiếu telemetry)"),
    ),
    notes=(
        "Milestone B (B0.2): User-Agent TRỐNG không còn được coi là client kịch bản — đó là THIẾU telemetry (proxy/SDK có thể bỏ header), "
        "không phải bằng chứng tự động hoá; pipeline ghi `telemetry_gaps=[\"missing_user_agent\"]` trong giải thích cảnh báo thay vào đó. "
        "`okhttp` cố ý không nằm trong danh sách (thư viện của ứng dụng Android thật). Các script demo trong attack-sim/ dùng httpx nên khớp luật này."
    ),
)
def scripted_client(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    ua = (a.user_agent or "").strip()
    if not ua:
        if not p.flag_empty_ua:
            return None
        return Finding("Thiếu User-Agent (trình duyệt thật luôn gửi): client kịch bản.", {"marker": "(trống)"})
    lowered = ua.lower()
    for marker in p.markers:
        if marker in lowered:
            return Finding(f"Client kịch bản/công cụ '{marker}': {short(ua)}.", {"marker": marker, "user_agent": short(ua, 120)})
    return None


@rule(
    id="ua_rotation",
    title="Xoay User-Agent",
    category=CATEGORY,
    severity="medium",
    techniques=("T1110.004",),
    description="Cùng một IP thất bại đăng nhập với NHIỀU User-Agent khác nhau trong thời gian ngắn — công cụ nhồi thông tin đổi UA để né nhận diện.",
    params=(
        Param("window_s", 600, "độ dài cửa sổ", "giây", 10, 86_400),
        Param("min_distinct_ua", 5, "số User-Agent khác nhau tối thiểu", "UA", 2, 1000),
        Param("min_fails", 8, "số lần sai tối thiểu của IP", "lần", 2, 100_000),
    ),
    needs=("user_agent",),
    notes="Nhiều người dùng thật sau cùng một NAT có UA khác nhau nhưng hiếm khi cùng thất bại nhiều lần; ngưỡng `min_fails` tách hai trường hợp.",
)
def ua_rotation(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if a.success:
        return None
    since = ctx.since(p.window_s)
    fails = ctx.store.log_count(K.fail_ip(a.ip), since)
    if fails < p.min_fails:
        return None
    agents = ctx.store.set_count(K.fail_agents_of_ip(a.ip), since, K.CAP)
    if agents < p.min_distinct_ua:
        return None
    return Finding(
        f"IP {a.ip} đổi {agents} User-Agent khác nhau trong {fails} lần sai/{window_text(p.window_s)} (xoay UA để né nhận diện).",
        {"ip": a.ip, "distinct_user_agents": agents, "fails": fails, "window_s": p.window_s},
    )


@rule(
    id="regular_rhythm",
    title="Nhịp thử đều như máy",
    category=CATEGORY,
    severity="medium",
    techniques=("T1110",),
    description="Các lần đăng nhập SAI gần nhất từ một IP cách nhau đều đặn và dày (độ lệch chuẩn nhỏ so với trung bình) — con người không gõ đều đến vậy.",
    params=(
        Param("samples", 10, "số lần sai gần nhất dùng để đo nhịp", "lần", 5, 100),
        Param("max_mean_interval_s", 30.0, "khoảng cách trung bình tối đa giữa hai lần (chậm hơn thì không tính là dồn dập)", "giây", 0.0, 3600.0),
        Param("max_cv", 0.15, "hệ số biến thiên tối đa (độ lệch chuẩn / trung bình) của khoảng cách", "", 0.0, 1.0),
    ),
    default_mode="shadow",
    notes="Chưa kiểm chứng trên log thật (chỉ dựa vào giả thuyết nhịp), nên mặc định ở chế độ shadow; máy có jitter ngẫu nhiên lớn sẽ né được.",
)
def regular_rhythm(ctx: RuleContext) -> Finding | None:
    a, p = ctx.attempt, ctx.p
    if a.success:
        return None
    times = ctx.store.log_recent(K.fail_ip(a.ip), p.samples)
    if len(times) < p.samples:
        return None
    intervals = [b - c for c, b in zip(times, times[1:])]
    mean = statistics.fmean(intervals)
    if mean > p.max_mean_interval_s:
        return None
    cv = 0.0 if mean <= 0 else statistics.pstdev(intervals) / mean
    if cv > p.max_cv:
        return None
    return Finding(
        f"IP {a.ip}: {p.samples} lần sai gần nhất cách nhau đều ~{mean:.2f}s (lệch {cv:.0%}) — nhịp của máy.",
        {"ip": a.ip, "samples": p.samples, "mean_interval_s": round(mean, 3), "cv": round(cv, 4)},
    )
