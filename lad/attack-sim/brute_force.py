"""Mô phỏng tấn công dò mật khẩu.

Chạy:  python attack-sim/brute_force.py --target user007

Kịch bản: kẻ tấn công thử liên tiếp nhiều mật khẩu cho một tài khoản
từ cùng một địa chỉ IP. Luật R03 đếm số lần thất bại trong 15 phút,
nên cảnh báo sẽ xuất hiện từ lần thử thứ sáu trở đi.

Tham số --stealth chuyển sang biến thể ngụy trang: dùng IP dân cư
trong nước và giả user-agent trình duyệt thật, giãn thời gian giữa
các lần thử. Chạy cả hai biến thể khi demo để cho thấy hệ thống
không chỉ dựa vào loại mạng hay user-agent.
"""
import argparse
import random
import time

from common import BOT_AGENTS, BROWSER_AGENTS, NET, rand_ip, send, summarize


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="user007", help="tài khoản bị nhắm tới")
    ap.add_argument("--attempts", type=int, default=12)
    ap.add_argument("--delay", type=float, default=0.4,
                    help="giãn cách giữa các lần thử, tính bằng giây")
    ap.add_argument("--stealth", action="store_true",
                    help="dùng biến thể ngụy trang")
    args = ap.parse_args()

    if args.stealth:
        ip = rand_ip(NET["vn_hanoi"])
        agent = random.choice(BROWSER_AGENTS)
        mode = "ngụy trang (IP dân cư Việt Nam, trình duyệt thật)"
    else:
        ip = rand_ip(NET["tor"])
        agent = random.choice(BOT_AGENTS)
        mode = "thô (IP Tor, user-agent script)"

    print(f"Dò mật khẩu tài khoản {args.target}")
    print(f"  Biến thể: {mode}")
    print(f"  Nguồn   : {ip}\n")

    results = []
    for i in range(args.attempts):
        # Lần cuối thành công, mô phỏng dò trúng mật khẩu
        success = (i == args.attempts - 1)
        results.append(send(args.target, ip, agent, success, "brute_force"))
        time.sleep(args.delay)

    summarize(results, "Kết quả dò mật khẩu")
    print("\nMở dashboard để xem cảnh báo vừa sinh ra.")


if __name__ == "__main__":
    main()
