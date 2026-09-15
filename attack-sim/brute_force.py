"""Giả lập brute force: gửi liên tục request sai mật khẩu tới CÙNG một
tài khoản (nhiệm vụ 6.1). Kỳ vọng: dashboard nổi alert `brute_force`.

Ngưỡng backend: BRUTE_FORCE_THRESHOLD = 5 lần fail / 5 phút
(backend/app/detection/rules.py) — mặc định bắn 6 lần để chắc chắn vượt.

Chạy:
    python brute_force.py --target user001
"""

from __future__ import annotations

import argparse
import time

import httpx
from common import add_common_args

DEFAULT_ATTEMPTS = 6


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Username bị tấn công")
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    add_common_args(parser)
    args = parser.parse_args()

    print(f"[brute_force] Bắn {args.attempts} lần sai mật khẩu vào tài khoản '{args.target}'...")
    with httpx.Client(timeout=10.0) as client:
        for i in range(1, args.attempts + 1):
            response = client.post(
                f"{args.base_url}/login",
                json={"username": args.target, "password": f"mat-khau-sai-{i}"},
            )
            print(f"  lần {i}/{args.attempts}: HTTP {response.status_code}")
            time.sleep(args.delay)

    print("[brute_force] Xong. Kiểm tra dashboard -> mục Cảnh báo phải có alert kiểu 'brute_force'.")


if __name__ == "__main__":
    main()
