"""Mô phỏng chiếm đoạt tài khoản.

Chạy:  python attack-sim/account_takeover.py --target user007

Kịch bản: kẻ tấn công đã có mật khẩu đúng, đăng nhập thành công từ
nước ngoài ngay sau khi nạn nhân vừa đăng nhập trong nước. Không có
lần thất bại nào, nên luật đếm số lần sai hoàn toàn vô dụng. Dấu hiệu
duy nhất là tốc độ di chuyển bất khả thi giữa hai lần đăng nhập,
cộng thêm quốc gia lạ và thiết bị lạ.

Đây là kịch bản khó nhất trong ba kịch bản và cũng là kịch bản gây
thiệt hại lớn nhất, vì kẻ tấn công đã vào được bên trong.
"""
import argparse
import random
import time

from common import BROWSER_AGENTS, NET, rand_ip, send, summarize


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="user007")
    ap.add_argument("--from-country", default="moscow",
                    choices=["moscow", "lagos", "tor", "singapore"])
    ap.add_argument("--actions", type=int, default=4,
                    help="số thao tác kẻ tấn công thực hiện sau khi vào được")
    args = ap.parse_args()

    victim_ip = rand_ip(NET["vn_hanoi"])
    victim_agent = random.choice(BROWSER_AGENTS)
    attacker_ip = rand_ip(NET[args.from_country])
    attacker_agent = random.choice(BROWSER_AGENTS)

    print(f"Chiếm đoạt tài khoản {args.target}")
    print(f"  Nạn nhân đăng nhập từ : {victim_ip} (Việt Nam)")
    print(f"  Kẻ tấn công từ        : {attacker_ip} ({args.from_country})\n")

    print("Bước 1: nạn nhân đăng nhập bình thường")
    send(args.target, victim_ip, victim_agent, True)
    time.sleep(1)

    print("\nBước 2: kẻ tấn công đăng nhập bằng mật khẩu đã đánh cắp")
    results = []
    for _ in range(args.actions):
        results.append(send(args.target, attacker_ip, attacker_agent,
                            True, "account_takeover"))
        time.sleep(0.5)

    summarize(results, "Kết quả chiếm đoạt tài khoản")
    print("\nĐiểm đáng chú ý: mọi lần đăng nhập đều THÀNH CÔNG. Một hệ thống")
    print("chỉ đếm số lần đăng nhập thất bại sẽ không phát hiện được gì.")


if __name__ == "__main__":
    main()
