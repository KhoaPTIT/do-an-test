"""Đo thời gian phản hồi POST /login (nhiệm vụ 5.2) — chạy trước và sau khi
tối ưu để so sánh. KHÔNG tự tối ưu gì — chỉ đo.

Chạy (backend phải đang chạy ở port 8000, có sẵn user 'alice'/'CorrectHorse123'):
    cd backend
    venv\\Scripts\\python.exe -m scripts.benchmark_login --n 50
"""

from __future__ import annotations

import argparse
import statistics
import time

import httpx

URL = "http://localhost:8000/login"
PAYLOAD = {"username": "alice", "password": "CorrectHorse123"}


def main(n: int) -> None:
    durations_ms: list[float] = []
    with httpx.Client(timeout=10.0) as client:
        for _ in range(n):
            start = time.perf_counter()
            client.post(URL, json=PAYLOAD)
            durations_ms.append((time.perf_counter() - start) * 1000)

    durations_ms.sort()
    p95_index = min(len(durations_ms) - 1, int(len(durations_ms) * 0.95))

    print(f"N = {n} request tuần tự tới {URL}")
    print(f"  min    = {durations_ms[0]:.1f} ms")
    print(f"  avg    = {statistics.mean(durations_ms):.1f} ms")
    print(f"  median = {statistics.median(durations_ms):.1f} ms")
    print(f"  p95    = {durations_ms[p95_index]:.1f} ms")
    print(f"  max    = {durations_ms[-1]:.1f} ms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=50)
    args = parser.parse_args()
    main(n=args.n)
