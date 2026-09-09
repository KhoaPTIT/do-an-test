"""Sinh dữ liệu đăng nhập mô phỏng có gán nhãn.

Chạy:  python ml/generate_dataset.py --users 120 --days 90 --out data/login_events.csv

Nguyên tắc thiết kế bộ dữ liệu:

1. Hành vi bình thường phải CÓ QUY LUẬT nhưng không cứng nhắc. Mỗi tài khoản
   có thành phố quen, một hai thiết bị quen, khung giờ quen, và có nhiễu.

2. Phải có "ca khó" ở phía dữ liệu bình thường. Nếu mọi lần đăng nhập hợp lệ
   đều từ đúng một thành phố và đúng một thiết bị thì mô hình đạt kết quả rất
   cao nhưng vô nghĩa. Vì vậy có thêm: người dùng đi công tác nước ngoài,
   người dùng đổi điện thoại, người dùng thỉnh thoảng thức khuya.

3. Tỷ lệ tấn công giữ ở mức thấp (mặc định 4%) để phản ánh thực tế mất cân bằng.
"""
import argparse
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# Dải IP tương ứng với bảng tra cứu trong app/utils/geoip.py
HOME_NETWORKS = {
    "Ha Noi": "14.161",
    "Ho Chi Minh": "14.162",
    "Da Nang": "117.0",
}
TRAVEL_NETWORKS = {
    "Singapore": "165.21",
    "Tokyo": "1.2.3",
}
ATTACK_NETWORKS = {
    "tor": "185.220.101",
    "moscow": "91.219.236",
    "lagos": "197.210",
    "amsterdam": "45.134.140",
}

BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Mobile Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

BOT_AGENTS = [
    "python-requests/2.31.0",
    "curl/8.4.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; scanner-bot/1.0)",
]


def rand_ip(prefix: str) -> str:
    """Sinh IP ngẫu nhiên trong một tiền tố mạng."""
    parts = prefix.split(".")
    while len(parts) < 4:
        parts.append(str(random.randint(1, 254)))
    return ".".join(parts)


def make_profile(uid: int) -> dict:
    city = random.choice(list(HOME_NETWORKS))
    net = HOME_NETWORKS[city]
    # Người dùng thật quay vòng trong một tập IP nhỏ: mạng nhà, mạng cơ quan,
    # mạng di động. Nếu sinh IP hoàn toàn ngẫu nhiên thì đặc trưng "IP lạ"
    # luôn bằng 1 và mất hết giá trị phân biệt.
    ip_pool = [rand_ip(net) for _ in range(random.randint(2, 4))]
    return {
        "username": f"user{uid:03d}",
        "city": city,
        "net": net,
        "ip_pool": ip_pool,
        "agents": random.sample(BROWSER_AGENTS, random.randint(1, 2)),
        "peak_hour": random.choice([8, 9, 10, 13, 14, 20, 21, 22]),
        "logins_per_day": random.choice([1, 1, 2, 2, 3, 4]),
        # 12% số tài khoản sẽ đi công tác nước ngoài một đợt
        "travels": random.random() < 0.12,
        # 15% số tài khoản đổi thiết bị giữa kỳ
        "switches_device": random.random() < 0.15,
    }


def row(username, ip, agent, ts, success, is_attack=False, attack_type=""):
    return {
        "username": username,
        "ip_address": ip,
        "user_agent": agent,
        "timestamp": ts.isoformat(timespec="seconds"),
        "login_successful": int(success),
        "is_attack": int(is_attack),
        "attack_type": attack_type,
    }


def normal_events(p: dict, start: datetime, days: int) -> list:
    """Sinh chuỗi đăng nhập bình thường cho một tài khoản."""
    out = []
    agents = list(p["agents"])

    ip_pool = list(p["ip_pool"])

    # Đợt công tác nước ngoài: một khoảng liên tục vài ngày
    travel_city = travel_start = travel_end = None
    if p["travels"] and days > 20:
        travel_start = random.randint(10, days - 8)
        travel_end = travel_start + random.randint(3, 6)
        travel_city = random.choice(list(TRAVEL_NETWORKS))

    # Đổi thiết bị: từ một ngày nào đó trở đi dùng thiết bị mới
    switch_day = random.randint(15, days - 5) if (p["switches_device"] and days > 25) else None
    new_agent = random.choice([a for a in BROWSER_AGENTS if a not in agents])

    for d in range(days):
        if switch_day is not None and d == switch_day:
            agents = [new_agent]

        n = max(0, int(random.gauss(p["logins_per_day"], 1)))
        for _ in range(n):
            # Giờ dao động quanh khung quen, thỉnh thoảng lệch hẳn
            if random.random() < 0.05:
                hour = random.randint(0, 23)
            else:
                hour = int(random.gauss(p["peak_hour"], 1.4)) % 24

            ts = start + timedelta(days=d, hours=hour,
                                   minutes=random.randint(0, 59),
                                   seconds=random.randint(0, 59))

            if travel_start is not None and travel_start <= d < travel_end:
                ip = rand_ip(TRAVEL_NETWORKS[travel_city])
            elif random.random() < 0.08:
                # Thỉnh thoảng dùng mạng lạ trong nước: quán cà phê, nhà bạn.
                # Đây là ca khó hợp lệ mà hệ thống không được báo động.
                ip = rand_ip(p["net"])
            else:
                ip = random.choice(ip_pool)

            # 6% lần đăng nhập thất bại do gõ nhầm mật khẩu, hoàn toàn bình thường
            success = random.random() > 0.06
            out.append(row(p["username"], ip, random.choice(agents), ts, success))

    return out


def hard_negative_forgot_password(p: dict, start: datetime, days: int) -> list:
    """Người dùng thật quên mật khẩu và gõ sai liên tiếp.

    Đây là ca khó quan trọng nhất của phía hợp lệ. Nếu bộ dữ liệu không có
    tình huống này thì rule brute-force không bao giờ sinh báo động giả,
    và con số đánh giá sẽ đẹp một cách phi thực tế.
    """
    ts = start + timedelta(days=random.randint(3, days - 1),
                           hours=random.gauss(p["peak_hour"], 1) % 24,
                           minutes=random.randint(0, 59))
    ip = random.choice(p["ip_pool"])
    agent = random.choice(p["agents"])
    n = random.randint(5, 9)

    out = []
    t = ts
    for i in range(n):
        t = t + timedelta(seconds=random.randint(15, 90))
        out.append(row(p["username"], ip, agent, t, i == n - 1))
    return out


def hard_negative_vpn_jump(p: dict, start: datetime, days: int) -> list:
    """Người dùng thật bật VPN doanh nghiệp, IP nhảy sang Singapore.

    Tạo ra tốc độ di chuyển bất khả thi nhưng hoàn toàn hợp lệ. Đây là
    nguyên nhân báo động giả phổ biến nhất của luật impossible travel
    trong các hệ thống thật.
    """
    day = random.randint(5, days - 1)
    base = start + timedelta(days=day,
                             hours=random.gauss(p["peak_hour"], 1) % 24)
    agent = random.choice(p["agents"])

    out = [row(p["username"], random.choice(p["ip_pool"]), agent, base, True)]
    for i in range(random.randint(2, 5)):
        t = base + timedelta(minutes=random.randint(5, 40) * (i + 1))
        out.append(row(p["username"], rand_ip(TRAVEL_NETWORKS["Singapore"]),
                       agent, t, True))
    return out


def attack_brute_force(p: dict, start: datetime, days: int,
                       stealthy: bool = False) -> list:
    """Thử mật khẩu liên tục cho một tài khoản từ một IP.

    Biến thể stealthy mô phỏng kẻ tấn công có nghề: dùng IP dân cư trong nước,
    giả user-agent trình duyệt thật, và giãn thời gian giữa các lần thử.
    Biến thể này không lộ ra ở đặc trưng mạng hay user-agent, buộc mô hình
    phải dựa vào nhịp độ hành vi.
    """
    ts = start + timedelta(days=random.randint(5, days - 1),
                           hours=random.randint(0, 23),
                           minutes=random.randint(0, 59))
    if stealthy:
        ip = rand_ip(random.choice(list(HOME_NETWORKS.values())))
        agent = random.choice(BROWSER_AGENTS)
        gap = lambda: random.randint(40, 180)
        n = random.randint(8, 18)
    else:
        ip = rand_ip(ATTACK_NETWORKS["tor"])
        agent = random.choice(BOT_AGENTS)
        gap = lambda: random.randint(3, 20)
        n = random.randint(12, 40)

    out = []
    t = ts
    for i in range(n):
        t = t + timedelta(seconds=gap())
        # Lần cuối có 30% khả năng thành công, mô phỏng dò trúng mật khẩu
        success = (i == n - 1) and random.random() < 0.3
        out.append(row(p["username"], ip, agent, t, success,
                       is_attack=True, attack_type="brute_force"))
    return out


def attack_credential_stuffing(profiles: list, start: datetime, days: int,
                               stealthy: bool = False) -> list:
    """Một IP thử hàng loạt tài khoản khác nhau, mỗi tài khoản một hai lần.

    Biến thể stealthy dùng IP hosting trong nước và user-agent trình duyệt,
    nhưng vẫn không giấu được việc một địa chỉ chạm vào quá nhiều tài khoản.
    """
    if stealthy:
        ip = rand_ip("103.20")
        agent = random.choice(BROWSER_AGENTS)
        n_victims = random.randint(14, 25)
        gap = (60, 200)
    else:
        ip = rand_ip(ATTACK_NETWORKS["amsterdam"])
        agent = random.choice(BOT_AGENTS)
        n_victims = random.randint(25, 45)
        gap = (20, 70)

    base = start + timedelta(days=random.randint(5, days - 1),
                             hours=random.randint(0, 23))
    victims = random.sample(profiles, min(len(profiles), n_victims))

    out = []
    t = base
    for v in victims:
        t = t + timedelta(seconds=random.randint(*gap))
        success = random.random() < 0.04
        out.append(row(v["username"], ip, agent, t, success,
                       is_attack=True, attack_type="credential_stuffing"))
    return out


def attack_takeover(p: dict, start: datetime, days: int,
                    stealthy: bool = False) -> list:
    """Chiếm đoạt tài khoản: đăng nhập thành công từ nước ngoài,
    thiết bị lạ, ngay sau một lần đăng nhập hợp lệ trong nước.

    Biến thể stealthy đến từ Singapore hoặc Tokyo, tức là những nơi mà
    người dùng Việt Nam hoàn toàn có thể đi công tác, và dùng trình duyệt thật.
    Dấu hiệu duy nhất còn lại là tốc độ di chuyển bất khả thi.
    """
    day = random.randint(10, days - 1)
    # Kẻ tấn công ngụy trang còn chọn đúng khung giờ nạn nhân hay hoạt động,
    # nên đặc trưng lệch giờ cũng không còn tác dụng phân biệt.
    hour = (random.gauss(p["peak_hour"], 1) % 24 if stealthy
            else random.choice([2, 3, 4, 15, 16]))
    base = start + timedelta(days=day, hours=hour)
    if stealthy:
        # Kẻ tấn công dùng đúng loại trình duyệt nạn nhân hay dùng và đi qua
        # một nước mà nạn nhân có thể đến công tác. Khi đó vector đặc trưng
        # gần như trùng với tình huống bật VPN hợp lệ ở trên, tạo ra vùng
        # chồng lấn thật giữa hai lớp. Không hệ thống nào tách được hoàn toàn
        # vùng này, và đó là lý do thực tế người ta chọn bắt xác thực hai lớp
        # thay vì chặn thẳng ở mức rủi ro trung bình.
        ip = rand_ip(random.choice(list(TRAVEL_NETWORKS.values())))
        agent = random.choice(p["agents"])
    else:
        net = ATTACK_NETWORKS[random.choice(["moscow", "lagos", "tor"])]
        ip = rand_ip(net)
        agent = random.choice(BROWSER_AGENTS + BOT_AGENTS)

    out = []
    # Lần đăng nhập hợp lệ trong nước ngay trước đó, tạo ra di chuyển bất khả thi
    out.append(row(p["username"], rand_ip(p["net"]),
                   random.choice(p["agents"]),
                   base - timedelta(minutes=random.randint(20, 90)), True))

    for i in range(random.randint(2, 6)):
        t = base + timedelta(minutes=i * random.randint(2, 15))
        out.append(row(p["username"], ip, agent, t, True,
                       is_attack=True, attack_type="account_takeover"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--users", type=int, default=120)
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--attack-ratio", type=float, default=0.04,
                    help="tỷ lệ bản ghi tấn công mong muốn")
    ap.add_argument("--stealth-ratio", type=float, default=0.35,
                    help="tỷ lệ cuộc tấn công dùng biến thể ngụy trang")
    ap.add_argument("--hard-negative-ratio", type=float, default=0.35,
                    help="tỷ lệ tài khoản có tình huống hợp lệ nhưng dễ bị "
                         "nhận nhầm là tấn công")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/login_events.csv")
    args = ap.parse_args()

    random.seed(args.seed)
    start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) \
            - timedelta(days=args.days)

    profiles = [make_profile(i) for i in range(1, args.users + 1)]

    rows = []
    for p in profiles:
        rows.extend(normal_events(p, start, args.days))

    # Ca khó phía hợp lệ: hành vi bình thường nhưng kích hoạt cùng những
    # đặc trưng mà tấn công kích hoạt. Không có phần này thì mọi chỉ số
    # đánh giá đều đẹp giả tạo.
    n_hard = int(len(profiles) * args.hard_negative_ratio)
    for p in random.sample(profiles, min(n_hard, len(profiles))):
        rows.extend(hard_negative_forgot_password(p, start, args.days))
    for p in random.sample(profiles, min(n_hard, len(profiles))):
        rows.extend(hard_negative_vpn_jump(p, start, args.days))

    n_normal = len(rows)

    target_attacks = int(n_normal * args.attack_ratio / (1 - args.attack_ratio))
    added = 0
    while added < target_attacks:
        # Chiếm đoạt tài khoản sinh ra ít bản ghi mỗi lần nhất nhưng lại là
        # kịch bản khó phát hiện nhất, nên cần cho nó xuất hiện thường xuyên
        # để tập kiểm thử có đủ mẫu khó.
        kind = random.choices(
            ["brute_force", "credential_stuffing", "account_takeover"],
            weights=[0.30, 0.20, 0.50])[0]

        # Một phần ba số cuộc tấn công dùng biến thể ngụy trang. Nếu bỏ phần
        # này, mô hình chỉ cần nhìn loại mạng và user-agent là phân loại đúng
        # gần như tuyệt đối, và kết quả đánh giá mất hết ý nghĩa.
        stealthy = random.random() < args.stealth_ratio

        if kind == "brute_force":
            batch = attack_brute_force(random.choice(profiles), start,
                                       args.days, stealthy)
        elif kind == "credential_stuffing":
            batch = attack_credential_stuffing(profiles, start, args.days,
                                               stealthy)
        else:
            batch = attack_takeover(random.choice(profiles), start,
                                    args.days, stealthy)

        rows.extend(batch)
        added += sum(r["is_attack"] for r in batch)

    rows.sort(key=lambda r: r["timestamp"])

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    n_attack = sum(r["is_attack"] for r in rows)
    print(f"Đã ghi {len(rows)} bản ghi vào {out_path}")
    print(f"  Bình thường: {len(rows) - n_attack}")
    print(f"  Tấn công   : {n_attack} ({n_attack / len(rows) * 100:.2f}%)")
    by_type = {}
    for r in rows:
        if r["is_attack"]:
            by_type[r["attack_type"]] = by_type.get(r["attack_type"], 0) + 1
    for k, v in sorted(by_type.items()):
        print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
