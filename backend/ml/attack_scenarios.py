"""MR18 — "Thư viện tấn công mô phỏng v2": 9 kịch bản THUẦN (không đụng DB/pipeline — chỉ đặc tả CHUỖI lần thử), khác
hẳn `scripts/alert_intelligence_sim.py` (MR13, đã tự nhận là "một giá trị lịch sử tự đặt của TÔI, không phải thư viện
tấn công đối kháng thật, để ngỏ cho MR18"): mỗi kịch bản ở đây nhắm THẲNG vào ngưỡng THẬT của một luật cụ thể
(`docs/rule-catalog.md`), dùng IP CÔNG KHAI THẬT đã xác nhận GeoIP/ASN qua `app.detection.geoip` (không phải IP bịa)
để né/khớp đúng tín hiệu địa lý/hạ tầng như tấn công thật sẽ gặp.

Hai nơi TIÊU THỤ CÙNG một `ScenarioSpec` (tách khỏi phần thực thi — spec này không biết gì về DB/pipeline):
  1. `scripts/attack_scenario_runner.py` (checklist "runner + scorecard"): phát lại qua `run_detection_pipeline` THẬT,
     đo có phát hiện không / bao lâu / bằng gì.
  2. Dữ liệu huấn luyện cho "mô hình B" (địa lý-thời gian, `ml/generate_dataset.py` + `ml/train.py` — xem
     `docs/checklist.md` MR6 "chuyển sang MR18"): một số kịch bản (không phải kịch bản NHIỀU bước như botnet/spray —
     những kịch bản đó không hợp với khuôn "một dòng nhãn bất thường" của `ml/generate_dataset.py`) được chuyển thành
     nhãn bất thường MỚI, xem `docs/attack-scenarios-v2.md` mục Mô hình B.

⚠️ `targeted_mimic` CỐ Ý thiết kế để KHÓ phát hiện (không luật nào khớp, chỉ còn tín hiệu ML yếu) — đây là kịch bản
"ML dẫn đầu" mà MR13 đã nói để ngỏ; báo cáo TRUNG THỰC nếu hệ thống bỏ sót, không coi là lỗi runner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
FIREFOX_UA = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
EDGE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/120.0.0.0 Safari/537.36"
SAFARI_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
MOBILE_UA = "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
CURL_UA = "curl/8.7.1"
DEVICE_POOL = (CHROME_UA, FIREFOX_UA, EDGE_UA, SAFARI_UA, MOBILE_UA)

# IP CÔNG KHAI THẬT — GeoIP/ASN đã xác nhận trực tiếp qua app.detection.geoip.lookup_ip/lookup_asn (không phải suy
# đoán) trước khi dùng, cùng kỷ luật đã áp dụng cho HANOI_IP/US_IP/CHINA_IP ở scripts/alert_intelligence_sim.py (MR13).
HANOI_FPT_IP = "210.245.88.1"  # FPT Telecom, ASN 18403, VN/Hanoi (21.0184, 105.8461) — IP "nhà" của nạn nhân mẫu
HCMC_VNPT_IP = "14.169.1.1"  # VNPT Corp, ASN 45899, VN/Ho Chi Minh City (10.822, 106.6257) — CÙNG nước, KHÁC ASN/thành phố
HUE_VIETTEL_IP = "203.113.128.1"  # Viettel Group, ASN 7552, VN (16.1667, 107.8333) — CÙNG nước, ASN thứ 3 (đủ hiếm)
HUE_VNPT_IP = "203.162.4.190"  # VNPT Corp, ASN 45899, VN (16.1667, 107.8333) — trùng ASN với HCMC_VNPT_IP, khác city
GOOGLE_US_IP = "8.8.8.8"  # Google, ASN 15169, US (37.751, -97.822)
LEVEL3_US_IP = "4.2.2.2"  # Level 3, ASN 3356, US/Greenville (34.8017, -82.3925)
ALIBABA_CN_IP = "223.5.5.5"  # Alibaba, ASN 45102, CN/Hangzhou (30.2943, 120.1663)
ZENLAYER_CN_IP = "114.114.114.114"  # Zenlayer, ASN 21859, CN (34.7732, 113.722)
CLOUDFLARE_IP = "1.1.1.1"  # Cloudflare, ASN 13335 — KHÔNG có city/country (geo rỗng), CÓ ASN
QUAD9_IP = "9.9.9.9"  # Quad9, ASN 19281 — KHÔNG có city/country, CÓ ASN
# "Botnet": nhiều IP CÔNG KHAI THẬT, ASN khác nhau — mô phỏng nhiều máy bị chiếm chứ không phải một dải giả.
BOTNET_IPS = (GOOGLE_US_IP, LEVEL3_US_IP, ALIBABA_CN_IP, ZENLAYER_CN_IP, CLOUDFLARE_IP, QUAD9_IP, HCMC_VNPT_IP, HUE_VIETTEL_IP)


@dataclass(frozen=True)
class AttemptSpec:
    """Một lần thử — THUẦN, không đụng DB. `username`: có thể KHÔNG tồn tại (dò tài khoản). `offset_s`: giây kể từ
    mốc bắt đầu kịch bản (có thể ÂM cho các bước BASELINE chèn trước ngày tấn công thật sự bắt đầu)."""

    username: str
    success: bool
    ip: str
    offset_s: float
    user_agent: str = CHROME_UA
    is_attack_step: bool = True  # False = bước BASELINE (lịch sử quen thuộc) — không tính vào "bước phát hiện thứ mấy"


@dataclass(frozen=True)
class ScenarioSpec:
    id: str
    title: str
    description: str
    rule_hint: str  # mã luật (hoặc "hybrid_ml") KỲ VỌNG bắt được — GỢI Ý để đối chiếu trong scorecard, không phải khẳng định
    victim_usernames: tuple[str, ...]  # tài khoản PHẢI được tạo trước khi phát lại attempts (kể cả tài khoản không tồn tại thì để rỗng)
    attempts: tuple[AttemptSpec, ...]
    expect_detectable: bool = True  # False = kịch bản CỐ Ý khó (targeted_mimic) — "miss" ở đây KHÔNG phải lỗi runner

    @property
    def attack_attempts(self) -> tuple[AttemptSpec, ...]:
        return tuple(a for a in self.attempts if a.is_attack_step)


def _spray_usernames(n: int) -> tuple[str, ...]:
    return tuple(f"victim_spray_{i:02d}" for i in range(n))


def _stuffing_usernames(n: int) -> tuple[str, ...]:
    return tuple(f"victim_stuffing_{i:02d}" for i in range(n))


def _baseline(usernames: Sequence[str], ip: str, *, count: int = 10, hour_offset_s: float = 10 * 3600) -> tuple[AttemptSpec, ...]:
    """`count` lần đăng nhập THÀNH CÔNG bình thường/tài khoản, cách nhau ~1 ngày, kết thúc TRƯỚC mốc tấn công (offset
    ÂM) — thiết lập lịch sử/thiết bị quen thuộc TRƯỚC khi tấn công. BẮT BUỘC cho MỌI kịch bản (kể cả kịch bản không
    cần tín hiệu "mới" của riêng luật nó nhắm tới): nếu không, tài khoản "trắng" hoàn toàn khiến tầng 3 (`ml_anomaly`,
    Tuần 7) tự báo CHỈ VÌ đây là lần đăng nhập ĐẦU TIÊN — xác nhận trực tiếp khi dựng MR18 (một tài khoản MỚI, đăng
    nhập THÀNH CÔNG lần đầu, KHÔNG có gì bất thường khác, VẪN tự tạo alert `ml_anomaly`) — không kiểm soát biến nhiễu
    này thì không thể phân biệt "phát hiện đúng kiểu tấn công" với "phát hiện vì tài khoản mới toanh", cùng tinh thần
    hai biến nhiễu MR15 đã tự phát hiện và kiểm soát khi dựng feedback_loop_sim.py."""
    return tuple(
        AttemptSpec(username=u, success=True, ip=ip, offset_s=-(count - i) * 86400 + hour_offset_s, user_agent=CHROME_UA, is_attack_step=False)
        for u in usernames
        for i in range(count)
    )


# ------------------------------------------------------------------------------------------------ 1. Rải mật khẩu chậm


def build_slow_password_spray(rng) -> ScenarioSpec:
    """Nhắm `password_spray_slow` (min_users=15, max_fails_per_user=3, window_s=86400) — 1 IP thử 18 tài khoản, ĐÚNG 1
    lần sai mỗi tài khoản, cách nhau ~25 phút (18 × 25' ≈ 7,5 giờ < 24h) — CHẬM đủ để KHÔNG chạm `credential_stuffing`
    (min_fails=10 trong CHỈ 300 giây: 25 phút/lần thì 300 giây chỉ lọt ĐÚNG 1 lần thử, không bao giờ đủ 10)."""
    usernames = _spray_usernames(18)
    baseline = _baseline(usernames, HANOI_FPT_IP, count=6)  # 6/TK đủ thiết lập quen thuộc, không cần nhiều vì đây không phải trọng tâm đo
    attack = tuple(
        AttemptSpec(username=u, success=False, ip=HUE_VIETTEL_IP, offset_s=i * 25 * 60, user_agent=CHROME_UA)
        for i, u in enumerate(usernames)
    )
    return ScenarioSpec(
        id="slow_password_spray", title="Rải mật khẩu chậm",
        description="1 IP thử 18 tài khoản khác nhau, đúng 1 lần sai mỗi tài khoản, cách nhau ~25 phút trong ~7,5 giờ.",
        rule_hint="password_spray_slow", victim_usernames=usernames, attempts=baseline + attack,
    )


# ------------------------------------------------------------------------------------------------ 2. Botnet phân tán


def build_distributed_botnet(rng) -> ScenarioSpec:
    """Nhắm `distributed_bruteforce` (min_fails=8, min_ips=5, window_s=3600) — 1 tài khoản bị 8 IP THẬT khác nhau
    (botnet, nhiều ASN khác nhau) thử sai, mỗi IP đúng 1 lần, dồn trong ~40 phút."""
    victim = "victim_botnet"
    baseline = _baseline((victim,), HANOI_FPT_IP)
    attack = tuple(
        AttemptSpec(username=victim, success=False, ip=ip, offset_s=i * 5 * 60, user_agent=rng.choice(DEVICE_POOL))
        for i, ip in enumerate(BOTNET_IPS)
    )
    return ScenarioSpec(
        id="distributed_botnet", title="Botnet phân tán vào một tài khoản",
        description="8 IP thật khác nhau (nhiều ASN — mô phỏng botnet), mỗi IP 1 lần sai vào CÙNG một tài khoản, dồn trong ~40 phút.",
        rule_hint="distributed_bruteforce", victim_usernames=(victim,), attempts=baseline + attack,
    )


# ------------------------------------------------------------------------------------------ 3. Proxy cùng quốc gia


def build_same_country_proxy(rng) -> ScenarioSpec:
    """Nạn nhân "nhà" ở Hà Nội (FPT, ASN 18403). Kẻ tấn công dùng proxy Việt Nam THẬT nhưng ASN khác (Viettel, ASN
    7552) — CÙNG nước (né tín hiệu "đổi quốc gia") nhưng ASN hiếm/lạ so với nạn nhân. Nhắm `rare_network_login`
    (shadow — checklist rule-catalog.md tự ghi "giá trị thật đo bằng kịch bản mô phỏng ở MR18", đây chính là câu trả
    lời) — vẫn là bằng chứng cho hybrid risk engine dù shadow không tự tạo alert riêng (MR11: shadow vẫn tính điểm)."""
    victim = "victim_proxy"
    baseline = tuple(
        AttemptSpec(username=victim, success=True, ip=HANOI_FPT_IP, offset_s=-86400 * (30 - i) + i * 3600, user_agent=CHROME_UA, is_attack_step=False)
        for i in range(10)
    )
    attack = (AttemptSpec(username=victim, success=True, ip=HUE_VIETTEL_IP, offset_s=0, user_agent=CHROME_UA),)
    return ScenarioSpec(
        id="same_country_proxy", title="Proxy cùng quốc gia, khác nhà mạng",
        description="Nạn nhân quen IP Hà Nội (FPT); đăng nhập THÀNH CÔNG một lần từ IP Việt Nam khác (Viettel) — cùng nước, khác ASN.",
        rule_hint="rare_network_login", victim_usernames=(victim,), attempts=baseline + attack,
    )


# ------------------------------------------------------------------------------------------------------- 4. Xoay UA


def build_ua_rotation(rng) -> ScenarioSpec:
    """Nhắm `ua_rotation` (min_distinct_ua=5, min_fails=8, window_s=600) — 1 IP, 9 lần sai vào 1 tài khoản, xoay qua
    6 User-Agent khác nhau, trong 6 phút."""
    victim = "victim_uarot"
    baseline = _baseline((victim,), HANOI_FPT_IP)
    attack = tuple(
        AttemptSpec(username=victim, success=False, ip=ALIBABA_CN_IP, offset_s=i * 40, user_agent=DEVICE_POOL[i % len(DEVICE_POOL)])
        for i in range(9)
    )
    return ScenarioSpec(
        id="ua_rotation", title="Xoay User-Agent",
        description="1 IP, 9 lần sai vào 1 tài khoản, xoay qua 6 User-Agent khác nhau trong 6 phút.",
        rule_hint="ua_rotation", victim_usernames=(victim,), attempts=baseline + attack,
    )


# ------------------------------------------------------------------------------------------- 5. Tài khoản ngủ đông


def build_dormant_account_reactivation(rng) -> ScenarioSpec:
    """Nhắm `dormant_account_login` (dormant_days=90, require_change=true) — 1 lần thành công 120 ngày trước (VN),
    im lặng, rồi đăng nhập lại thành công từ Trung Quốc (quốc gia MỚI — thoả require_change)."""
    victim = "victim_dormant"
    baseline = (AttemptSpec(username=victim, success=True, ip=HANOI_FPT_IP, offset_s=-120 * 86400, user_agent=CHROME_UA, is_attack_step=False),)
    attack = (AttemptSpec(username=victim, success=True, ip=ZENLAYER_CN_IP, offset_s=0, user_agent=FIREFOX_UA),)
    return ScenarioSpec(
        id="dormant_account_reactivation", title="Tài khoản ngủ đông đăng nhập lại",
        description="1 lần thành công 120 ngày trước (VN), im lặng, rồi đăng nhập lại thành công từ Trung Quốc.",
        rule_hint="dormant_account_login", victim_usernames=(victim,), attempts=baseline + attack,
    )


# --------------------------------------------------------------------------------------------------- 6. Mô phỏng tinh vi


def build_targeted_mimic(rng) -> ScenarioSpec:
    """CỐ Ý KHÓ (checklist + MR13 để ngỏ "kịch bản ML dẫn đầu"): nạn nhân quen Hà Nội, giờ hành chính, 1 thiết bị.
    Kẻ tấn công đăng nhập THÀNH CÔNG (mật khẩu đã lộ) đúng giờ hành chính, CÙNG THÀNH PHỐ (Hà Nội, ASN khác — VNPT thay
    vì FPT, nhưng city trùng nên không phải "đổi vị trí" rõ rệt), thiết bị KHÁC nhưng vẫn là Chrome desktop bình thường
    (không phải bot/kịch bản). KHÔNG luật enforce nào có lý do khớp rõ ràng — chỉ còn tín hiệu ML yếu (IP/ASN hơi mới)
    nếu có. `expect_detectable=False`: bỏ sót ở đây là kết quả TRUNG THỰC đáng báo cáo, không phải lỗi."""
    victim = "victim_mimic"
    baseline = tuple(
        AttemptSpec(username=victim, success=True, ip=HANOI_FPT_IP, offset_s=-86400 * (20 - i) + 10 * 3600, user_agent=CHROME_UA, is_attack_step=False)
        for i in range(15)
    )
    attack = (AttemptSpec(username=victim, success=True, ip=HCMC_VNPT_IP, offset_s=10 * 3600, user_agent=EDGE_UA),)
    return ScenarioSpec(
        id="targeted_mimic", title="Mô phỏng tinh vi (Targeted mimic)",
        description="Đăng nhập thành công đúng giờ hành chính quen thuộc, IP Việt Nam khác (không phải bot/kịch bản) — cố ý không có tín hiệu luật rõ ràng.",
        rule_hint="hybrid_ml", victim_usernames=(victim,), attempts=baseline + attack, expect_detectable=False,
    )


# ------------------------------------------------------------------------------------------------- 7. Dò danh sách TK


def build_account_enumeration(rng) -> ScenarioSpec:
    """Nhắm `username_enumeration` (min_usernames=8, window_s=600) — 1 IP thử 10 tên đăng nhập KHÔNG TỒN TẠI, cách
    nhau ~50 giây, trong ~8 phút."""
    attempts = tuple(
        AttemptSpec(username=f"khong_ton_tai_{i:02d}", success=False, ip=LEVEL3_US_IP, offset_s=i * 50, user_agent=CURL_UA)
        for i in range(10)
    )
    return ScenarioSpec(
        id="account_enumeration", title="Dò danh sách tài khoản",
        description="1 IP thử 10 tên đăng nhập KHÔNG TỒN TẠI, cách nhau ~50 giây.",
        rule_hint="username_enumeration", victim_usernames=(), attempts=attempts,
    )


# -------------------------------------------------------------------------------------- 8. Nhồi thông tin quy mô lớn


def build_large_scale_credential_stuffing(rng) -> ScenarioSpec:
    """Nhắm `credential_stuffing` (min_fails=10, min_users=5, window_s=300) — 1 IP thử 12 tài khoản CÓ THẬT, mỗi tài
    khoản 1-2 lần sai (16 lần sai tổng), trong 4 phút — QUY MÔ LỚN hơn hẳn attack-sim/credential_stuffing.py gốc."""
    usernames = _stuffing_usernames(12)
    baseline = _baseline(usernames, HANOI_FPT_IP, count=6)
    attack = []
    t = 0.0
    for i, u in enumerate(usernames):
        fails = 2 if i % 3 == 0 else 1
        for _ in range(fails):
            attack.append(AttemptSpec(username=u, success=False, ip=QUAD9_IP, offset_s=t, user_agent=CURL_UA))
            t += 15
    return ScenarioSpec(
        id="large_scale_credential_stuffing", title="Nhồi thông tin đăng nhập quy mô lớn",
        description="1 IP thử 12 tài khoản có thật, 16 lần sai tổng cộng, trong 4 phút.",
        rule_hint="credential_stuffing", victim_usernames=usernames, attempts=baseline + tuple(attack),
    )


# ------------------------------------------------------------------------------------------------ 9. Di chuyển bất khả thi


def build_impossible_travel(rng) -> ScenarioSpec:
    """Nhắm `impossible_travel` (max_speed_kmh=900) + `multi_context_simultaneous` — 1 tài khoản, 2 lần đăng nhập
    THÀNH CÔNG cách nhau 4 phút, Hà Nội rồi Mỹ (GeoIP thật, ~13.000km — tốc độ ước lượng hàng trăm nghìn km/h)."""
    victim = "victim_travel"
    baseline = _baseline((victim,), HANOI_FPT_IP)
    attack = (
        AttemptSpec(username=victim, success=True, ip=HANOI_FPT_IP, offset_s=0, user_agent=CHROME_UA),
        AttemptSpec(username=victim, success=True, ip=GOOGLE_US_IP, offset_s=4 * 60, user_agent=CHROME_UA),
    )
    return ScenarioSpec(
        id="impossible_travel", title="Di chuyển bất khả thi",
        description="2 lần đăng nhập thành công cách nhau 4 phút, Hà Nội rồi Mỹ (~13.000km).",
        rule_hint="impossible_travel", victim_usernames=(victim,), attempts=baseline + attack,
    )


BUILDERS = (
    build_slow_password_spray, build_distributed_botnet, build_same_country_proxy, build_ua_rotation,
    build_dormant_account_reactivation, build_targeted_mimic, build_account_enumeration,
    build_large_scale_credential_stuffing, build_impossible_travel,
)


def all_scenarios(rng) -> list[ScenarioSpec]:
    return [build(rng) for build in BUILDERS]
