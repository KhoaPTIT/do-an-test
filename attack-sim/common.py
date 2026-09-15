"""Tham số & helper dùng chung cho 4 script giả lập tấn công (nhiệm vụ 6.1).

Dùng chung venv của backend (đã có httpx cài sẵn từ Tuần 1 cho test):

    cd backend && venv\\Scripts\\activate
    cd ..\\attack-sim
    python brute_force.py --target user001

Tốc độ gửi request (--delay, giây nghỉ giữa mỗi lần) và số lần thử tham
số hoá ở đầu mỗi file / qua CLI — chỉnh để phù hợp trình diễn trực tiếp
(không quá nhanh để người xem kịp theo dõi trên dashboard, không quá chậm
làm mất thời gian).
"""

from __future__ import annotations

import argparse

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_DELAY_SECONDS = 0.4


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Địa chỉ backend")
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY_SECONDS,
        help="Giây nghỉ giữa mỗi request — chỉnh tốc độ demo (mặc định %(default)s)",
    )
