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
    trình duyệt hợp lệ trên cùng máy.

⚠️ Tổng hợp, không phải log thật: 0 báo nhầm ở đây là điều kiện CẦN, không chứng minh tỉ lệ báo nhầm ngoài thực tế."""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field

from verification.harness import CHROME_UA, EDGE_UA, FIREFOX_UA, MOBILE_UA, SAFARI_UA
from verification.scenarios import (
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
    rng = random.Random(seed)
    out = NormalTraffic()
    office_ip = rng.choice(OFFICE_POOL)
    home_pools = (HOME_POOL, HOME_POOL, HCM_POOL, HAIPHONG_POOL, DANANG_POOL)

    for u in range(n_users):
        name = f"user{u:03d}"
        out.accounts.append(name)
        home_pool = rng.choice(home_pools)
        home_ip = rng.choice(home_pool)
        # IP di động CÙNG thành phố với nhà (fixture chỉ có dải di động Hà Nội). ⚠️ Không mô phỏng việc IP di động
        # (CGNAT) bị định vị về thành phố khác — một nguồn báo nhầm impossible_travel đã biết ngoài thực tế.
        mobile_ip = rng.choice(MOBILE_POOL) if home_pool is HOME_POOL else rng.choice(home_pool)
        laptop = CHROME_UA if u % 5 == 0 else rng.choice(LAPTOP_UAS)
        browser_update_day = rng.randint(8, 20) if u % 5 == 0 else None  # Chrome tự cập nhật phiên bản giữa kỳ
        extra_browsers = (FIREFOX_UA, EDGE_UA) if u % 9 == 4 else ()  # dùng thêm trình duyệt khác trên cùng máy
        has_phone = rng.random() < 0.6
        habit_hour = rng.choice((8.0, 9.0, 12.0, 19.5, 21.0))
        office = u < 12
        traveller = 12 <= u < 16
        dormant = 16 <= u < 19
        daily_p = 0.3 if u % 7 == 0 else 0.8

        out.profile_counts["users"] += 1
        out.profile_counts["office_nat" if office else "home"] += 1
        if traveller:
            out.profile_counts["business_trip"] += 1
        if dormant:
            out.profile_counts["dormant_same_context_return"] += 1
        if has_phone:
            out.profile_counts["laptop_and_phone"] += 1
        if browser_update_day is not None:
            out.profile_counts["browser_version_update"] += 1
        if extra_browsers:
            out.profile_counts["multiple_browsers_same_machine"] += 1

        # Lịch sử trước khi mô phỏng: 7 ngày quen thuộc (tài khoản ngủ đông: một lần duy nhất 100–200 ngày trước).
        if dormant:
            out.history.append(HistoryLogin(name, home_ip, -rng.uniform(100, 200) * DAY, laptop))
        else:
            for d in range(14, 0, -1):  # 2 tuần quen thuộc — thiết bị người dùng đang dùng đều có mặt trong lịch sử
                ua = MOBILE_UA if has_phone and d % 3 == 0 else (extra_browsers[d % 2] if extra_browsers and d % 4 == 1 else laptop)
                out.history.append(HistoryLogin(name, mobile_ip if ua == MOBILE_UA else home_ip, -d * DAY + habit_hour * 3600, ua))

        trip_start, trip_end = (rng.randint(8, 14), None) if traveller else (None, None)
        if trip_start is not None:
            trip_end = trip_start + rng.randint(2, 4)
            trip_pool = rng.choice((HCM_POOL, DANANG_POOL, JP_POOL, FR_POOL))
            trip_ip = rng.choice(trip_pool)

        for day in range(days):
            if dormant and day < 20:
                continue
            if dormant and day == 20:
                out.steps.append(Step(name, True, home_ip, day * DAY + habit_hour * 3600, laptop))
                continue
            if rng.random() > daily_p:
                continue
            weekday = day % 7 < 5
            travel_day = trip_start is not None and day in (trip_start, trip_end)
            for k in range(1 if travel_day else rng.choice((1, 1, 2, 2, 3))):
                hour = min(habit_hour + rng.uniform(-1.0, 1.0) + k * rng.uniform(2.0, 4.0), 23.5)  # không tràn sang ngày sau
                at = day * DAY + hour * 3600
                on_trip = trip_start is not None and trip_start <= day < trip_end
                if travel_day:  # ngày đi/ngày về: chỉ một lần đăng nhập lúc 20h, cách lần cuối ở nơi cũ ≥ 20h (đi lại hợp lý)
                    at = day * DAY + 20 * 3600
                if on_trip:
                    ip, ua = trip_ip, laptop
                elif office and weekday and 8 <= hour <= 18:
                    ip, ua = office_ip, laptop
                elif has_phone and rng.random() < 0.35:
                    ip, ua = (mobile_ip if rng.random() < 0.6 else home_ip), MOBILE_UA
                else:
                    ip, ua = home_ip, laptop
                    if extra_browsers and rng.random() < 0.3:
                        ua = rng.choice(extra_browsers)
                if ua == laptop and browser_update_day is not None and day >= browser_update_day:
                    ua = CHROME_UPDATES[0] if day < browser_update_day + 7 else CHROME_UPDATES[1]
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
    return out
