"""Tiện ích dùng chung cho các script mô phỏng tấn công.

Các script trong thư mục này gửi sự kiện đăng nhập vào API đang chạy
để chứng minh hệ thống phát hiện được tấn công theo thời gian thực.
Dùng khi demo trước hội đồng: chạy script ở một cửa sổ, mở dashboard
ở cửa sổ khác, cảnh báo sẽ hiện ra trong vòng vài giây.
"""
import os
import random
import sys

import requests

API_URL = os.getenv("LAD_API_URL", "http://localhost:8000")
API_KEY = os.getenv("LAD_API_KEY", "demo-api-key-doi-truoc-khi-nop")

BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]
BOT_AGENTS = ["python-requests/2.31.0", "curl/8.4.0", "Go-http-client/1.1"]

# Dải IP khớp với bảng tra cứu trong backend/app/utils/geoip.py
NET = {
    "vn_hanoi": "14.161",
    "vn_hcm": "14.162",
    "tor": "185.220.101",
    "moscow": "91.219.236",
    "lagos": "197.210",
    "amsterdam": "45.134.140",
    "singapore": "165.21",
}


def rand_ip(prefix: str) -> str:
    parts = prefix.split(".")
    while len(parts) < 4:
        parts.append(str(random.randint(1, 254)))
    return ".".join(parts)


def send(username, ip, user_agent, success=True, attack_type=None, verbose=True):
    """Gửi một sự kiện đăng nhập, in ra quyết định của hệ thống."""
    try:
        r = requests.post(
            f"{API_URL}/api/v1/login-event",
            headers={"X-API-Key": API_KEY},
            json={
                "username": username, "ip_address": ip,
                "user_agent": user_agent, "login_successful": success,
                "is_attack": attack_type is not None,
                "attack_type": attack_type,
            },
            timeout=10,
        )
    except requests.exceptions.ConnectionError:
        sys.exit(f"Không kết nối được tới {API_URL}. "
                 f"Kiểm tra backend đã chạy chưa: uvicorn app.main:app --port 8000")

    if r.status_code == 401:
        sys.exit("API key không hợp lệ. Đặt biến môi trường LAD_API_KEY cho đúng.")
    if r.status_code != 200:
        print(f"  lỗi {r.status_code}: {r.text[:120]}")
        return None

    d = r.json()
    if verbose:
        label = {"allow": "cho qua", "challenge": "BẮT XÁC THỰC 2 LỚP",
                 "block": "CHẶN"}[d["decision"]]
        codes = ",".join(h["code"] for h in d["rule_hits"]) or "-"
        print(f"  {username:10s} {ip:16s} điểm {d['risk_score']:6.1f}  "
              f"{label:20s} luật: {codes}")
    return d


def summarize(results, title):
    """In thống kê cuối đợt tấn công."""
    ok = [d for d in results if d]
    if not ok:
        print("Không có phản hồi hợp lệ.")
        return
    detected = sum(1 for d in ok if d["decision"] in ("challenge", "block"))
    blocked = sum(1 for d in ok if d["decision"] == "block")
    avg = sum(d["risk_score"] for d in ok) / len(ok)
    print(f"\n--- {title} ---")
    print(f"  Số lần thử       : {len(ok)}")
    print(f"  Bị phát hiện     : {detected} ({detected / len(ok) * 100:.1f}%)")
    print(f"  Trong đó bị chặn : {blocked}")
    print(f"  Điểm rủi ro TB   : {avg:.1f}")
