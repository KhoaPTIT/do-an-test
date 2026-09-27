"""Nguồn danh tiếng cho các luật hạ tầng (MR9): danh sách Tor / datacenter / VPN công khai và blocklist do quản trị viên quản lý.

Danh sách tải bằng `python -m scripts.update_threat_feeds` vào `backend/threat_intel/` (ngoài git, xem docs/rule-catalog.md). Thiếu file thì
danh sách đó RỖNG và `loaded[...]` = False: luật tương ứng báo "bỏ qua: chưa có danh sách" chứ không báo động sai và không sập.

⚠️ Danh sách công khai KHÔNG đầy đủ và có thể báo nhầm (VPN doanh nghiệp, đám mây của chính khách hàng): chỉ là tín hiệu tham khảo, nên các luật
datacenter/VPN mặc định ở chế độ shadow.
"""

from __future__ import annotations

import ipaddress
import json
from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

from app.detection.engine.types import LoginAttempt

DEFAULT_DIR = Path(__file__).resolve().parents[3] / "threat_intel"
TOR_FILE, DATACENTER_FILE, VPN_FILE = "tor_exit_ips.txt", "datacenter_cidrs.txt", "vpn_cidrs.txt"


class CidrSet:
    """Tập mạng IPv4 tra cứu O(log n): gộp các dải giao nhau/liền kề thành khoảng [đầu, cuối], tìm nhị phân theo đầu khoảng. IPv6 không được hỗ trợ."""

    def __init__(self, cidrs: Iterable[str] = ()):
        networks = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        intervals = sorted((int(n.network_address), int(n.broadcast_address)) for n in networks if n.version == 4)
        merged: list[list[int]] = []
        for start, end in intervals:
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        self._starts = [s for s, _ in merged]
        self._ends = [e for _, e in merged]

    def __contains__(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if address.version != 4:
            return False
        value = int(address)
        i = bisect_right(self._starts, value) - 1
        return i >= 0 and value <= self._ends[i]

    def __len__(self) -> int:
        return len(self._starts)


def _read_lines(path: Path) -> list[str] | None:
    if not path.is_file():
        return None
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


@dataclass
class ThreatIntel:
    tor: frozenset[str] = frozenset()
    datacenter: CidrSet = field(default_factory=CidrSet)
    vpn: CidrSet = field(default_factory=CidrSet)
    loaded: dict[str, bool] = field(default_factory=lambda: {"tor": False, "datacenter": False, "vpn": False})
    fetched_at: datetime | None = None  # thời điểm tải bản mới nhất (từ sources.json), nếu có

    @classmethod
    def load(cls, directory: Path | str | None = None) -> "ThreatIntel":
        folder = Path(directory) if directory is not None else DEFAULT_DIR
        tor, datacenter, vpn = (_read_lines(folder / name) for name in (TOR_FILE, DATACENTER_FILE, VPN_FILE))
        fetched_at = None
        sources = folder / "sources.json"
        if sources.is_file():
            try:
                stamps = [datetime.fromisoformat(s["fetched_at"]) for s in json.loads(sources.read_text(encoding="utf-8")) if s.get("fetched_at")]
                fetched_at = min(stamps) if stamps else None
            except (ValueError, KeyError, TypeError):
                fetched_at = None
        return cls(
            tor=frozenset(tor or ()),
            datacenter=CidrSet(datacenter or ()),
            vpn=CidrSet(vpn or ()),
            loaded={"tor": tor is not None, "datacenter": datacenter is not None, "vpn": vpn is not None},
            fetched_at=fetched_at,
        )

    def is_tor(self, ip: str) -> bool:
        return ip in self.tor

    def in_datacenter(self, ip: str) -> bool:
        return ip in self.datacenter

    def in_vpn(self, ip: str) -> bool:
        return ip in self.vpn

    def status(self) -> dict:
        return {
            "loaded": dict(self.loaded),
            "entries": {"tor": len(self.tor), "datacenter": len(self.datacenter), "vpn": len(self.vpn)},
            "fetched_at": None if self.fetched_at is None else self.fetched_at.isoformat(),
        }


# ------------------------------------------------------------------------------------------------ blocklist

BLOCK_KINDS = ("ip", "cidr", "asn", "username")


@dataclass(frozen=True)
class BlockEntry:
    kind: str  # ip | cidr | asn | username
    value: str
    reason: str = ""
    expires_at: float | None = None  # epoch giây; None = vĩnh viễn
    added_by: str = "admin"

    def active_at(self, ts: float) -> bool:
        return self.expires_at is None or ts < self.expires_at


class Blocklist:
    """Danh sách chặn do quản trị viên quản lý (IP, dải CIDR, ASN, tên đăng nhập), có thể có hạn dùng. MR12 lưu vào DB; ở đây giữ trong bộ nhớ.
    Hạn dùng so với thời gian của SỰ KIỆN đang xét (replay cho cùng kết quả như lúc đó)."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], BlockEntry] = {}

    @staticmethod
    def _normalize(kind: str, value: str) -> str:
        if kind not in BLOCK_KINDS:
            raise ValueError(f"loại blocklist không hợp lệ: {kind!r} (có: {BLOCK_KINDS})")
        value = str(value).strip()
        if kind == "ip":
            return str(ipaddress.ip_address(value))
        if kind == "cidr":
            return str(ipaddress.ip_network(value, strict=False))
        if kind == "asn":
            return str(int(value.upper().removeprefix("AS")))
        return value.lower()

    def add(self, kind: str, value: str, reason: str = "", ttl: float | None = None, now: float | None = None, added_by: str = "admin") -> BlockEntry:
        if ttl is not None and now is None:
            raise ValueError("đặt hạn dùng (ttl) cần truyền `now`")
        normalized = self._normalize(kind, value)
        entry = BlockEntry(kind, normalized, reason, None if ttl is None else now + ttl, added_by)
        self._entries[(kind, normalized)] = entry
        return entry

    def remove(self, kind: str, value: str) -> bool:
        return self._entries.pop((kind, self._normalize(kind, value)), None) is not None

    def entries(self, ts: float | None = None) -> list[BlockEntry]:
        return [e for e in self._entries.values() if ts is None or e.active_at(ts)]

    def match(self, attempt: LoginAttempt) -> BlockEntry | None:
        """Mục chặn còn hiệu lực khớp lần thử này (ưu tiên IP > CIDR > ASN > tên đăng nhập), hoặc None."""
        ts = attempt.ts

        def live(kind: str, value: str) -> BlockEntry | None:
            entry = self._entries.get((kind, value))
            return entry if entry is not None and entry.active_at(ts) else None

        try:
            address = ipaddress.ip_address(attempt.ip)
        except ValueError:
            address = None
        if address is not None:
            if (entry := live("ip", str(address))) is not None:
                return entry
            for (kind, value), entry in self._entries.items():
                if kind == "cidr" and entry.active_at(ts) and address in ipaddress.ip_network(value):
                    return entry
        if attempt.asn is not None and (entry := live("asn", str(attempt.asn))) is not None:
            return entry
        return live("username", attempt.username.lower())
