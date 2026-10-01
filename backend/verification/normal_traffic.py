"""Bộ lưu lượng BÌNH THƯỜNG tổng hợp (Phase 3, bước 7): ≥50 người dùng × 30 ngày mô phỏng, chạy qua pipeline thật để
tìm detector QUÁ NHẠY. Mọi alert quy kết cho một detector trên bộ này là báo nhầm của detector đó.

Hành vi bình thường được mô phỏng (mỗi mục đều có trong dữ liệu sinh ra, xem `NormalTraffic.profile_counts`):
  - đăng nhập sáng hoặc tối theo thói quen riêng, 0–3 lần/ngày;
  - gõ sai mật khẩu 1–2 lần rồi đúng; thỉnh thoảng gõ sai CẢ tên đăng nhập;
  - laptop (Chrome/Firefox/Edge/Safari) + điện thoại, đổi giữa IP nhà và IP di động;
  - nhân viên văn phòng đăng nhập từ CÙNG một IP NAT vào giờ hành chính ngày thường;
  - đi công tác hợp lý (trong nước hoặc nước ngoài, lần đăng nhập đầu ở nơi mới cách lần cuối ở nhà ≥ thời gian bay);
  - tài khoản lâu ngày (100–200 ngày) mới đăng nhập lại nhưng CÙNG thiết bị, cùng mạng nhà;
  - (v2, trước khi đo Milestone B) người dùng laptop + điện thoại đã dùng CẢ HAI trong lịch sử (thiết bị đã quen);
    người dùng cập nhật phiên bản trình duyệt giữa kỳ (Chrome 120 → 121/122 — cùng thiết bị); người dùng dùng 2–3
    trình duyệt hợp lệ trên cùng máy;
  - (v3, trước khi đo Milestone C — C10) lịch sử sinh từ cùng quy trình với kỳ mô phỏng; người làm ca đêm (đăng nhập
    quanh 23:00–01:00, tràn qua nửa đêm); người đăng nhập 4–7 lần/ngày; lập trình viên đăng nhập lại 3–15 phút/lần
    trong giờ làm; tài khoản dùng chung kiểu kiosk (đợt 6–10 lần trong ~8 phút, nhiều đợt/ngày, User-Agent trình duyệt);
    chuyến công tác nước ngoài tới nước ĐÃ TỪNG đến (có trong lịch sử); người dùng có IP không nằm trong GeoIP; tài
    khoản mới tạo giữa kỳ. Không mô phỏng: đổi múi giờ (hệ thống không có dữ liệu múi giờ), chuyến đi ĐẦU TIÊN tới một
    nước mới (thuộc định nghĩa DƯƠNG TÍNH của unusual_location ở C2), thiết bị mới mua (dương tính của unusual_device),
    tự động hoá hợp lệ bằng công cụ kịch bản (dương tính của scripted_client).

⚠️ Tổng hợp, không phải log thật: 0 báo nhầm ở đây là điều kiện CẦN, không chứng minh tỉ lệ báo nhầm ngoài thực tế."""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field

from verification.harness import CHROME_UA, EDGE_UA, FIREFOX_UA, MOBILE_UA, SAFARI_UA
from verification.scenarios import (  # noqa: I001
    DANANG_POOL,
    DAY,
    FR_POOL,
    HAIPHONG_POOL,
    HCM_POOL,
    HOME_POOL,
    JP_POOL,
    MOBILE_POOL,
    OFFICE_POOL,
    HistoryLogin,
    Step,
)

LAPTOP_UAS = (CHROME_UA, FIREFOX_UA, EDGE_UA, SAFARI_UA)
CHROME_UPDATES = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36",
)


@dataclass
class NormalTraffic:
    accounts: list[str] = field(default_factory=list)
    history: list[HistoryLogin] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    profile_counts: Counter = field(default_factory=Counter)


def generate(seed: int = 20260302, n_users: int = 50, days: int = 30) -> NormalTraffic:
    """`n_users` người dùng "cũ" (các nhóm Milestone A/B) + 13 người dùng các nhóm Milestone C (C10). Lịch sử trước kỳ
    mô phỏng (14 ngày) và kỳ mô phỏng (`days` ngày) sinh từ CÙNG một quy trình hằng ngày của từng người — người dùng ổn
    định thì lịch sử phải giống hành vi hiện tại (v3, định nghĩa TRƯỚC khi đo Milestone C; v2 chỉ ghi 1 lần/ngày đúng giờ
    thói quen vào lịch sử nên hồ sơ giờ "đều" một cách giả tạo)."""
    rng = random.Random(seed)
    out = NormalTraffic()
    office_ip = rng.choice(OFFICE_POOL)
    home_pools = (HOME_POOL, HOME_POOL, HCM_POOL, HAIPHONG_POOL, DANANG_POOL)
    history_days = 14

    roles = {}
    for u in range(n_users):
        roles[u] = "office" if u < 12 else "traveller" if u < 16 else "dormant" if u < 19 else "regular"
    extra = ("night_shift",) * 3 + ("heavy_daily",) * 3 + ("developer",) + ("service_like",) + ("geo_missing",) * 2 + ("new_account",) * 3
    for i, role in enumerate(extra):
        roles[n_users + i] = role

    for u, role in roles.items():
        name = f"user{u:03d}"
        out.accounts.append(name)
        home_pool = rng.choice(home_pools)
        home_ip = rng.choice(home_pool)
        # IP di động CÙNG thành phố với nhà (fixture chỉ có dải di động Hà Nội). ⚠️ Không mô phỏng việc IP di động
        # (CGNAT) bị định vị về thành phố khác — một nguồn báo nhầm impossible_travel đã biết ngoài thực tế.
        mobile_ip = rng.choice(MOBILE_POOL) if home_pool is HOME_POOL else rng.choice(home_pool)
        if role == "geo_missing":  # IP không có trong cơ sở GeoIP (fixture): thiếu quốc gia/toạ độ/ASN
            home_ip = mobile_ip = f"100.64.{u}.10"
        laptop = CHROME_UA if u % 5 == 0 else rng.choice(LAPTOP_UAS)
        browser_update_day = rng.randint(8, 20) if u % 5 == 0 and role in ("office", "regular", "traveller") else None
        extra_browsers = (FIREFOX_UA, EDGE_UA) if u % 9 == 4 else ()
        has_phone = rng.random() < 0.6 and role not in ("service_like",)
        habit_hour = {"night_shift": 23.0, "developer": 9.0, "service_like": 8.5}.get(role, rng.choice((8.0, 9.0, 12.0, 19.5, 21.0)))
        daily_p = 0.3 if u % 7 == 0 and role == "regular" else 0.85
        logins_per_day = {"heavy_daily": (4, 5, 6, 7)}.get(role, (1, 1, 2, 2, 3))

        out.profile_counts["users"] += 1
        out.profile_counts[role] += 1
        if has_phone:
            out.profile_counts["laptop_and_phone"] += 1
        if browser_update_day is not None:
            out.profile_counts["browser_version_update"] += 1
        if extra_browsers:
            out.profile_counts["multiple_browsers_same_machine"] += 1

        trip_start = trip_end = trip_ip = None
        if role == "traveller":
            trip_start = rng.randint(8, 14)
            trip_end = trip_start + rng.randint(2, 4)
            trip_pool = rng.choice((HCM_POOL, DANANG_POOL, JP_POOL, FR_POOL))
            trip_ip = rng.choice(trip_pool)
            if trip_pool in (JP_POOL, FR_POOL):  # chuyến đi nước ngoài CÓ trong lịch sử: đã từng đến nước này 60–120 ngày trước
                visit = -rng.uniform(60, 120) * DAY
                for k in range(rng.randint(3, 5)):
                    out.history.append(HistoryLogin(name, rng.choice(trip_pool), visit + k * DAY + habit_hour * 3600, laptop))
                out.profile_counts["trip_to_previously_visited_country"] += 1

        def session_hours(rng=rng):
            """Giờ (có thể > 24: sang ngày sau) các lần đăng nhập THÀNH CÔNG trong một ngày của người này."""
            if role == "developer":  # đăng nhập lại liên tục trong giờ làm (3–15 phút/lần)
                hours, h = [], habit_hour
                while h < 17.0:
                    hours.append(h)
                    h += rng.uniform(3, 15) / 60
                return hours
            if role == "service_like":  # tài khoản dùng chung kiểu kiosk: 3–5 đợt/ngày, mỗi đợt 6–10 lần trong ~8 phút
                hours = []
                for b in range(rng.randint(3, 5)):
                    start = habit_hour + b * 2.0 + rng.uniform(0, 0.5)
                    hours += [start + k * rng.uniform(0.6, 0.9) / 60 for k in range(rng.randint(6, 10))]
                return hours
            n = rng.choice(logins_per_day)
            out_hours = []
            for k in range(n):
                h = habit_hour + rng.uniform(-1.0, 1.0) + k * rng.uniform(1.0, 2.5 if role == "heavy_daily" else 4.0)
                out_hours.append(h if role == "night_shift" else min(h, 23.5))  # ca đêm: được tràn qua nửa đêm
            return out_hours

        first_day = -history_days
        if role == "dormant":
            out.history.append(HistoryLogin(name, home_ip, -rng.uniform(100, 200) * DAY, laptop))
        if role == "new_account":
            first_day = rng.randint(10, 20)  # tài khoản tạo giữa kỳ, không có lịch sử
        for day in range(first_day, days):
            if role == "dormant":
                if day == 20:
                    out.steps.append(Step(name, True, home_ip, day * DAY + habit_hour * 3600, laptop))
                continue
            weekday = day % 7 < 5
            if role in ("developer", "service_like") and not weekday:
                continue
            if role not in ("developer", "service_like") and rng.random() > daily_p:
                continue
            travel_day = trip_start is not None and day in (trip_start, trip_end)
            hours = [20.0] if travel_day else session_hours()  # ngày đi/về: một lần lúc 20h, cách lần cuối ở nơi cũ ≥ 20h
            for hour in hours:
                at = day * DAY + hour * 3600
                on_trip = trip_start is not None and trip_start <= day < trip_end
                if on_trip:
                    ip, ua = trip_ip, laptop
                elif role == "office" and weekday and 8 <= hour <= 18:
                    ip, ua = office_ip, laptop
                elif has_phone and rng.random() < 0.35:
                    ip, ua = (mobile_ip if rng.random() < 0.6 else home_ip), MOBILE_UA
                else:
                    ip, ua = home_ip, laptop
                    if extra_browsers and rng.random() < 0.3:
                        ua = rng.choice(extra_browsers)
                if ua == laptop and browser_update_day is not None and day >= browser_update_day:
                    ua = CHROME_UPDATES[0] if day < browser_update_day + 7 else CHROME_UPDATES[1]
                if day < 0:  # lịch sử trước kỳ mô phỏng: chỉ lần thành công (hồ sơ chỉ học từ thành công)
                    out.history.append(HistoryLogin(name, ip, at, ua))
                    continue
                if rng.random() < 0.12:  # gõ sai mật khẩu 1–2 lần
                    for t in range(rng.randint(1, 2)):
                        out.steps.append(Step(name, False, ip, at - 40 + t * 15, ua))
                    out.profile_counts["password_typo"] += 1
                if rng.random() < 0.03:  # gõ sai cả tên đăng nhập
                    out.steps.append(Step(name[:-1] + "x", False, ip, at - 70, ua))
                    out.profile_counts["username_typo"] += 1
                out.steps.append(Step(name, True, ip, at, ua))
                out.profile_counts["successful_logins"] += 1

    out.steps.sort(key=lambda s: s.offset_s)
    out.profile_counts["total_steps"] = len(out.steps)
    out.profile_counts["history_logins"] = len(out.history)
    return out
