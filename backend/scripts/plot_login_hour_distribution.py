"""Vẽ biểu đồ phân bố giờ đăng nhập theo user — bước kiểm tra của nhiệm vụ 2.3.

Xác nhận dữ liệu giả lập có "thói quen" rõ ràng theo từng user, không rải
đều ngẫu nhiên 0-23h. Lưu ảnh vào docs/figures/.

Chạy:
    cd backend
    venv\\Scripts\\python.exe -m scripts.plot_login_hour_distribution
"""

from __future__ import annotations

import os

import matplotlib

matplotlib.use("Agg")  # headless, không cần màn hình
import matplotlib.pyplot as plt

from app.database import SessionLocal
from app.models import LoginEvent

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "figures", "login_hour_distribution.png")


def main() -> None:
    db = SessionLocal()
    try:
        events = (
            db.query(LoginEvent.attempted_username, LoginEvent.created_at)
            .filter(LoginEvent.is_synthetic.is_(True))
            .all()
        )
    finally:
        db.close()

    by_user: dict[str, list[float]] = {}
    for username, created_at in events:
        hour = created_at.hour + created_at.minute / 60
        by_user.setdefault(username, []).append(hour)

    # Lấy 6 user đầu tiên để biểu đồ không quá rối.
    sample_users = sorted(by_user.keys())[:6]

    fig, axes = plt.subplots(2, 3, figsize=(12, 6), sharex=True, sharey=True)
    for ax, username in zip(axes.flat, sample_users):
        ax.hist(by_user[username], bins=24, range=(0, 24), color="#4C72B0")
        ax.set_title(username)
        ax.set_xlim(0, 24)
        ax.set_xticks([0, 6, 12, 18, 24])

    fig.suptitle("Phân bố giờ đăng nhập theo user (dữ liệu giả lập) — mỗi user tập trung quanh 1 khung giờ riêng")
    fig.supxlabel("Giờ trong ngày")
    fig.supylabel("Số lần đăng nhập")
    fig.tight_layout()

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    fig.savefig(OUTPUT_PATH, dpi=120)
    print(f"Đã lưu biểu đồ: {os.path.abspath(OUTPUT_PATH)}")

    # In thêm số liệu thô để xác nhận không phải ngẫu nhiên rải đều: độ lệch
    # chuẩn của mỗi user phải nhỏ hơn nhiều so với độ lệch chuẩn của phân bố
    # đều trên [0, 24) (~6.93h).
    print("\nĐộ lệch chuẩn giờ đăng nhập theo user (càng nhỏ càng 'có thói quen'):")
    for username in sample_users:
        hours = by_user[username]
        mean = sum(hours) / len(hours)
        variance = sum((h - mean) ** 2 for h in hours) / len(hours)
        stddev = variance**0.5
        print(f"  {username}: mean={mean:.1f}h, stddev={stddev:.2f}h, n={len(hours)}")
    print("  (so sánh: stddev của phân bố đều ngẫu nhiên trên 0-24h là ~6.93h)")


if __name__ == "__main__":
    main()
