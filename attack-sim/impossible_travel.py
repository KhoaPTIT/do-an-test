"""Giả lập impossible travel: đăng nhập thành công từ vị trí A, rồi NGAY
SAU ĐÓ đăng nhập lại từ vị trí B cách rất xa trong thời gian ngắn (nhiệm
vụ 6.1). Kỳ vọng: alert `impossible_travel` + dashboard vẽ đường nối trên
bản đồ.

⚠️ CẦN backend bật `TRUST_FORWARDED_FOR=true` trong .env (mặc định TẮT).
Đây là công tắc CHỈ DÙNG CHO DEMO CỤC BỘ — xem cảnh báo trong
backend/app/config.py và docs/api-contract.md mục 6. Script gửi IP giả
qua header X-Forwarded-For; nếu backend không bật cờ này, IP nguồn thật
(127.0.0.1, private) sẽ được dùng và impossible_travel sẽ KHÔNG kích hoạt
(is_impossible_travel() bỏ qua khi thiếu GeoIP — đây là hành vi đúng, an
toàn, không phải bug).

2 IP mặc định đã kiểm tra thật cho toạ độ đầy đủ với GeoLite2-City thật
(và với chế độ mock cũng nhận diện được — 8.8.8.8 nằm sẵn trong
_MOCK_LOCATIONS ở app/detection/geoip.py):
  8.8.8.8         -> Mỹ (US)
  203.119.101.100 -> Úc (Brisbane) — cách xa, đủ vượt ngưỡng 900 km/h

⚠️ Lưu ý khi tự đổi IP: KHÔNG dùng dải IP dành cho tài liệu/test (VD
203.0.113.0/24, TEST-NET) — các dải này không có trong GeoLite2 thật nên
lookup sẽ thất bại (trả None có kiểm soát) và impossible_travel sẽ KHÔNG
kích hoạt, dù không phải lỗi. Kiểm tra trước bằng:
    python -c "from app.detection.geoip import lookup_ip; print(lookup_ip('<ip>'))"

Chạy:
    python impossible_travel.py --target user001 --password Demo@12345
"""

from __future__ import annotations

import argparse
import time

import httpx
from common import add_common_args

IP_A = "8.8.8.8"
IP_B = "203.119.101.100"


def _login_with_ip(client: httpx.Client, base_url: str, username: str, password: str, fake_ip: str) -> httpx.Response:
    return client.post(
        f"{base_url}/login",
        json={"username": username, "password": password},
        headers={"X-Forwarded-For": fake_ip},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--password", required=True, help="Mật khẩu ĐÚNG của tài khoản")
    parser.add_argument("--ip-a", default=IP_A)
    parser.add_argument("--ip-b", default=IP_B)
    add_common_args(parser)
    args = parser.parse_args()

    print(f"[impossible_travel] Đăng nhập '{args.target}' từ {args.ip_a}, rồi ngay sau đó từ {args.ip_b}...")
    with httpx.Client(timeout=10.0) as client:
        r1 = _login_with_ip(client, args.base_url, args.target, args.password, args.ip_a)
        print(f"  lần 1 (IP {args.ip_a}): HTTP {r1.status_code}")
        time.sleep(args.delay)

        r2 = _login_with_ip(client, args.base_url, args.target, args.password, args.ip_b)
        print(f"  lần 2 (IP {args.ip_b}): HTTP {r2.status_code}")

    print("[impossible_travel] Xong. Kiểm tra dashboard -> alert 'impossible_travel' + đường nối trên bản đồ.")
    print("Nếu KHÔNG thấy alert: kiểm tra .env có TRUST_FORWARDED_FOR=true và backend đã restart sau khi đổi chưa.")


if __name__ == "__main__":
    main()
