"""Phân tích chuỗi user-agent và sinh vân tay thiết bị.

Dùng cách nhận dạng bằng từ khóa để không phụ thuộc thư viện ngoài.
Nếu muốn chính xác hơn: pip install user-agents rồi thay thân hàm parse_ua().
"""
import hashlib
import re

_BOT_HINTS = ("bot", "spider", "crawler", "curl", "wget", "python-requests",
              "httpie", "go-http-client", "java/", "libwww", "scrapy")

_OS_PATTERNS = [
    (r"windows nt 10|windows nt 11", "Windows"),
    (r"windows", "Windows"),
    (r"iphone|ipad|ios", "iOS"),
    (r"android", "Android"),
    (r"mac os x|macintosh", "macOS"),
    (r"linux", "Linux"),
]

_BROWSER_PATTERNS = [
    (r"edg/", "Edge"),
    (r"opr/|opera", "Opera"),
    (r"chrome/", "Chrome"),
    (r"firefox/", "Firefox"),
    (r"safari/", "Safari"),
]


def parse_ua(user_agent: str) -> dict:
    """Trả về dict: device_type, os, browser."""
    ua = (user_agent or "").lower()

    if any(h in ua for h in _BOT_HINTS):
        return {"device_type": "bot", "os": "Unknown", "browser": "Unknown"}

    os_family = next((name for pat, name in _OS_PATTERNS if re.search(pat, ua)),
                     "Unknown")
    browser = next((name for pat, name in _BROWSER_PATTERNS if re.search(pat, ua)),
                   "Unknown")

    if "mobile" in ua or os_family in ("iOS", "Android"):
        device_type = "mobile"
    elif "tablet" in ua or "ipad" in ua:
        device_type = "tablet"
    elif os_family == "Unknown":
        device_type = "unknown"
    else:
        device_type = "desktop"

    return {"device_type": device_type, "os": os_family, "browser": browser}


def fingerprint(user_agent: str, ip_address: str = "") -> str:
    """Vân tay thiết bị: hash của hệ điều hành, trình duyệt và loại thiết bị.

    Cố tình KHÔNG đưa địa chỉ IP vào. Vân tay phải mô tả cái máy, không phải
    chỗ máy đang đứng. Nếu trộn IP vào, một người dùng chuyển từ wifi sang
    4G sẽ bị coi là thiết bị mới, và đặc trưng "thiết bị lạ" mất hết ý nghĩa.

    Trong hệ thống thật, vân tay được lấy từ phía trình duyệt (độ phân giải
    màn hình, danh sách phông chữ, canvas fingerprint) nên phân biệt được
    tốt hơn nhiều. Chuỗi user-agent chỉ là bản thay thế đơn giản cho đồ án.
    """
    parsed = parse_ua(user_agent)
    raw = f"{parsed['os']}|{parsed['browser']}|{parsed['device_type']}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
