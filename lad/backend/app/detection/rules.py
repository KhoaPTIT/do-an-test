"""Rule engine: các luật phát hiện viết tay.

Ưu điểm của rule so với ML là giải thích được. Khi hệ thống chặn một
lần đăng nhập, analyst nhìn vào danh sách rule là biết ngay lý do.
Mỗi rule trả về RuleResult nếu kích hoạt, trả về None nếu không.
"""
from dataclasses import asdict, dataclass
from typing import Callable, List, Optional

from app.detection.features import MAX_PLAUSIBLE_SPEED_KMH, EventData


@dataclass
class RuleResult:
    code: str
    name: str
    score: int          # điểm cộng vào tổng điểm rule
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


# --- Tham số ngưỡng, gom một chỗ để dễ hiệu chỉnh ---
BRUTE_FORCE_FAILS = 5           # số lần sai trong 15 phút
STUFFING_DISTINCT_USERS = 10    # số tài khoản khác nhau từ một IP trong 1 giờ
MIN_HISTORY_FOR_PROFILE = 3     # dưới mức này chưa đủ dữ liệu để nói "bất thường"
MIN_HISTORY_FOR_HOURS = 10
IMPOSSIBLE_TRAVEL_MIN_KM = 500


def rule_new_country(event: EventData, ctx: dict) -> Optional[RuleResult]:
    """R01: đăng nhập từ quốc gia chưa từng xuất hiện trong lịch sử user."""
    if (ctx["history_count"] >= MIN_HISTORY_FOR_PROFILE
            and event.country
            and event.country not in ctx["known_countries"]):
        return RuleResult("R01", "Quốc gia mới", 30,
                          f"Đăng nhập từ {event.country}, "
                          f"chưa từng ghi nhận với tài khoản này.")
    return None


def rule_impossible_travel(event: EventData, ctx: dict) -> Optional[RuleResult]:
    """R02: hai lần đăng nhập cách nhau quá xa trong thời gian quá ngắn.

    Đây là dấu hiệu mạnh của việc tài khoản bị dùng đồng thời ở hai nơi.
    """
    if (ctx["travel_speed_kmh"] > MAX_PLAUSIBLE_SPEED_KMH
            and ctx["travel_distance_km"] >= IMPOSSIBLE_TRAVEL_MIN_KM):
        return RuleResult("R02", "Di chuyển bất khả thi", 45,
                          f"Di chuyển {ctx['travel_distance_km']:.0f} km trong "
                          f"{ctx['hours_since_last_login']:.1f} giờ "
                          f"(≈{ctx['travel_speed_kmh']:.0f} km/h).")
    return None


def rule_brute_force(event: EventData, ctx: dict) -> Optional[RuleResult]:
    """R03: nhiều lần nhập sai mật khẩu liên tiếp cho cùng một tài khoản."""
    n = ctx["failed_last_15min"]
    if n >= BRUTE_FORCE_FAILS:
        return RuleResult("R03", "Nghi vấn brute-force", 35,
                          f"{n} lần đăng nhập thất bại trong 15 phút trước đó.")
    return None


def rule_credential_stuffing(event: EventData, ctx: dict) -> Optional[RuleResult]:
    """R04: một IP thử rất nhiều tài khoản khác nhau trong thời gian ngắn."""
    n = ctx["distinct_users_same_ip_1h"]
    if n >= STUFFING_DISTINCT_USERS:
        return RuleResult("R04", "Nghi vấn credential stuffing", 40,
                          f"IP {event.ip_address} đã thử {n} tài khoản "
                          f"khác nhau trong 1 giờ.")
    return None


def rule_new_device(event: EventData, ctx: dict) -> Optional[RuleResult]:
    """R05: vân tay thiết bị chưa từng thấy.

    Điểm thấp vì người dùng đổi máy hoặc đổi trình duyệt là chuyện bình thường.
    Rule này chủ yếu có giá trị khi cộng dồn với các rule khác.
    """
    if (ctx["history_count"] >= MIN_HISTORY_FOR_PROFILE
            and event.device_fingerprint not in ctx["known_devices"]):
        return RuleResult("R05", "Thiết bị mới", 20,
                          "Vân tay thiết bị chưa từng ghi nhận với tài khoản này.")
    return None


def rule_odd_hour(event: EventData, ctx: dict) -> Optional[RuleResult]:
    """R06: đăng nhập lệch hẳn khung giờ quen thuộc của user."""
    if ctx["history_count"] >= MIN_HISTORY_FOR_HOURS:
        h = event.timestamp.hour
        nearby = {(h + d) % 24 for d in (-1, 0, 1)}
        if not (nearby & ctx["typical_hours"]):
            return RuleResult("R06", "Giờ đăng nhập bất thường", 15,
                              f"Đăng nhập lúc {h:02d}h, lệch khỏi khung giờ "
                              f"thường dùng của tài khoản.")
    return None


def rule_risky_network(event: EventData, ctx: dict) -> Optional[RuleResult]:
    """R07: IP thuộc mạng Tor hoặc trung tâm dữ liệu.

    Người dùng thật hiếm khi đăng nhập từ dải IP của nhà cung cấp máy chủ.
    """
    if event.network_type == "tor":
        return RuleResult("R07", "Truy cập qua mạng ẩn danh", 35,
                          "Địa chỉ IP thuộc dải Tor exit node.")
    if event.network_type == "hosting" and ctx["history_count"] >= MIN_HISTORY_FOR_PROFILE:
        return RuleResult("R07", "IP thuộc trung tâm dữ liệu", 20,
                          "Địa chỉ IP thuộc dải hosting, không phải mạng dân cư.")
    return None


def rule_bot_agent(event: EventData, ctx: dict) -> Optional[RuleResult]:
    """R08: user-agent của công cụ tự động thay vì trình duyệt thật."""
    if event.device_type == "bot":
        return RuleResult("R08", "Công cụ tự động", 30,
                          "User-agent cho thấy đây là script, không phải trình duyệt.")
    return None


ALL_RULES: List[Callable] = [
    rule_new_country,
    rule_impossible_travel,
    rule_brute_force,
    rule_credential_stuffing,
    rule_new_device,
    rule_odd_hour,
    rule_risky_network,
    rule_bot_agent,
]


def run_rules(event: EventData, ctx: dict) -> List[RuleResult]:
    """Chạy toàn bộ rule, trả về danh sách rule đã kích hoạt."""
    results = []
    for rule in ALL_RULES:
        hit = rule(event, ctx)
        if hit is not None:
            results.append(hit)
    return results
