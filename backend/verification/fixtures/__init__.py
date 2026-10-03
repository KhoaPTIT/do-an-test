"""TEST FIXTURE: GeoIP/ASN giả lập và danh sách threat intel giả lập (dải địa chỉ tài liệu RFC 5737, ASN private RFC 6996).

Chỉ cung cấp TELEMETRY (vị trí, ASN, danh sách danh tiếng) cho pipeline thật — KHÔNG chứa nhãn tấn công nào, và
detector không biết dữ liệu đến từ fixture hay từ GeoLite2/danh sách thật."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.detection.engine.intel import ThreatIntel
from app.detection.geoip import AsnResult, GeoResult

FIXTURE_DIR = Path(__file__).resolve().parent
THREAT_INTEL_FIXTURE_DIR = FIXTURE_DIR / "threat_intel"


@dataclass(frozen=True)
class GeoRange:
    network: ipaddress.IPv4Network
    geo: GeoResult
    asn: AsnResult
    role: str


@lru_cache(maxsize=1)
def geo_ranges() -> tuple[GeoRange, ...]:
    data = json.loads((FIXTURE_DIR / "geoip.json").read_text(encoding="utf-8"))
    return tuple(
        GeoRange(ipaddress.ip_network(r["cidr"]), GeoResult(r["country"], r["city"], r["lat"], r["lon"]), AsnResult(r["asn"], r["org"]), r["role"])
        for r in data["ranges"]
    )


def _match(ip: str) -> GeoRange | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((r for r in geo_ranges() if addr in r.network), None)


def fixture_lookup_ip(ip: str) -> GeoResult | None:
    r = _match(ip)
    return r.geo if r else None


def fixture_lookup_asn(ip: str) -> AsnResult | None:
    r = _match(ip)
    return r.asn if r else None


def fixture_threat_intel() -> ThreatIntel:
    return ThreatIntel.load(THREAT_INTEL_FIXTURE_DIR)


def ips_in(cidr: str) -> list[str]:
    """Mọi địa chỉ host của một dải (tiện cho bộ sinh kịch bản chọn IP trong đúng vùng)."""
    return [str(h) for h in ipaddress.ip_network(cidr).hosts()]
