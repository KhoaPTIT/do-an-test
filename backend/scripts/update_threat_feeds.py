"""Tải danh sách threat-intel công khai về backend/threat_intel/ (MR1).

Chạy:  python -m scripts.update_threat_feeds

Nguồn (đều công khai, dạng văn bản thuần, dùng cho rule Tor/VPN/datacenter ở MR9):
  - Tor Project: danh sách exit node chính thức.
  - X4BNet/lists_vpn: dải CIDR datacenter và VPN thương mại (danh sách cộng đồng,
    KHÔNG đầy đủ và có thể báo nhầm với VPN doanh nghiệp hợp lệ — chỉ là tín hiệu
    tham khảo, không phải kết luận).

Mỗi dòng được kiểm tra bằng module ipaddress; nếu bản tải về rỗng/hỏng thì giữ
nguyên file cũ. File ghi nguyên tử (ghi tạm rồi thay thế) để tiến trình đang đọc
không bao giờ thấy file dở dang.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

FEED_DIR = os.path.join(os.path.dirname(__file__), "..", "threat_intel")
_MAX_BYTES = 10 * 1024 * 1024
_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class Feed:
    filename: str
    description: str
    url: str
    kind: str  # "ip" | "cidr"


FEEDS = [
    Feed("tor_exit_ips.txt", "Tor Project — bulk exit list", "https://check.torproject.org/torbulkexitlist", "ip"),
    Feed(
        "datacenter_cidrs.txt",
        "X4BNet lists_vpn — datacenter IPv4",
        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
        "cidr",
    ),
    Feed(
        "vpn_cidrs.txt",
        "X4BNet lists_vpn — VPN IPv4",
        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
        "cidr",
    ),
]


def parse_feed_text(text: str, kind: str) -> tuple[list[str], int]:
    """Trả (các dòng hợp lệ đã chuẩn hoá, số dòng không hợp lệ). Bỏ dòng trống và dòng chú thích."""
    valid: list[str] = []
    invalid = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if kind == "ip":
                valid.append(str(ipaddress.ip_address(line)))
            else:
                valid.append(str(ipaddress.ip_network(line, strict=False)))
        except ValueError:
            invalid += 1
    return valid, invalid


def _download(url: str) -> str:
    if not url.startswith("https://"):
        raise ValueError(f"chỉ chấp nhận https: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "lad-threat-feed-updater/1.0"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310 — https đã kiểm tra ở trên
        body = response.read(_MAX_BYTES + 1)
    if len(body) > _MAX_BYTES:
        raise ValueError("file vượt giới hạn 10MB")
    return body.decode("utf-8")


def update_feed(feed: Feed, feed_dir: str = FEED_DIR) -> dict:
    text = _download(feed.url)
    valid, invalid = parse_feed_text(text, feed.kind)
    if not valid:
        raise ValueError("không có dòng hợp lệ nào — giữ nguyên file cũ")

    os.makedirs(feed_dir, exist_ok=True)
    target = os.path.join(feed_dir, feed.filename)
    tmp = target + ".tmp"
    content = "\n".join(valid) + "\n"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    os.replace(tmp, target)

    return {
        "file": feed.filename,
        "description": feed.description,
        "url": feed.url,
        "entries": len(valid),
        "invalid_lines": invalid,
        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    results = []
    failed = 0
    for feed in FEEDS:
        try:
            info = update_feed(feed)
            results.append(info)
            print(f"[OK]   {feed.filename}: {info['entries']:,} mục ({info['invalid_lines']} dòng bỏ qua)")
        except Exception as exc:  # noqa: BLE001 — một nguồn lỗi không được chặn các nguồn còn lại
            failed += 1
            print(f"[LỖI]  {feed.filename}: {exc}")

    if results:
        os.makedirs(FEED_DIR, exist_ok=True)
        with open(os.path.join(FEED_DIR, "sources.json"), "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
