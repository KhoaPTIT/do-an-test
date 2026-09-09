"""Mô phỏng tấn công nhồi thông tin đăng nhập.

Chạy:  python attack-sim/credential_stuffing.py --victims 20

Kịch bản: kẻ tấn công có sẵn một danh sách cặp tài khoản và mật khẩu
rò rỉ từ nơi khác, thử lần lượt trên hệ thống này. Đặc điểm nhận dạng
không nằm ở một tài khoản nào cả, mà ở chỗ một địa chỉ IP chạm vào
rất nhiều tài khoản khác nhau trong thời gian ngắn. Luật R04 đếm
số tài khoản khác nhau đến từ cùng một IP trong 1 giờ.
"""
import argparse
import random
import time

from common import BOT_AGENTS, BROWSER_AGENTS, NET, rand_ip, send, summarize


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--victims", type=int, default=20)
    ap.add_argument("--start-id", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--stealth", action="store_true")
    args = ap.parse_args()

    if args.stealth:
        ip = rand_ip("103.20")
        agent = random.choice(BROWSER_AGENTS)
        mode = "ngụy trang (hosting trong nước, trình duyệt thật)"
    else:
        ip = rand_ip(NET["amsterdam"])
        agent = random.choice(BOT_AGENTS)
        mode = "thô (hosting nước ngoài, user-agent script)"

    print(f"Nhồi thông tin đăng nhập lên {args.victims} tài khoản")
    print(f"  Biến thể: {mode}")
    print(f"  Nguồn   : {ip}\n")

    results = []
    for i in range(args.victims):
        username = f"user{args.start_id + i:03d}"
        # Tỷ lệ trúng thấp, đúng như thực tế của kiểu tấn công này
        success = random.random() < 0.05
        results.append(send(username, ip, agent, success, "credential_stuffing"))
        time.sleep(args.delay)

    summarize(results, "Kết quả nhồi thông tin đăng nhập")
    print("\nĐiểm đáng chú ý: những lần thử đầu tiên có điểm thấp vì hệ thống")
    print("chưa thấy dấu hiệu bất thường. Điểm tăng dần khi số tài khoản bị")
    print("chạm tới từ cùng một IP vượt ngưỡng của luật R04.")


if __name__ == "__main__":
    main()
