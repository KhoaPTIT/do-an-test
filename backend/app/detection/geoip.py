"""GeoIP lookup wrapper (nhiệm vụ 3.1) — dùng chung cho toàn bộ detection engine.

Xử lý an toàn khi lookup thất bại (IP nội bộ, IP không có trong DB, chưa có
file .mmdb) — LUÔN trả None thay vì raise lỗi làm sập luồng đăng nhập.

Khi chưa có file GeoLite2-City.mmdb thật (cần tài khoản MaxMind miễn phí,
xem docs/geoip-setup.md), module tự chuyển sang "chế độ mock": vẫn đúng
interface, chỉ nhận diện đúng IP private/reserved + vài IP mẫu công khai,
còn lại trả None (được log như lookup thất bại, không phải lỗi crash).
Khi có file .mmdb thật đặt vào backend/geoip/, code gọi (rules.py, routers)
không cần sửa gì — tự động chuyển qua dùng dữ liệu thật.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass
from typing import Optional

import geoip2.database
import geoip2.errors

from app.config import get_settings

_LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
os.makedirs(_LOG_DIR, exist_ok=True)

logger = logging.getLogger("geoip")
if not logger.handlers:  # tránh add handler trùng khi module bị reload (pytest, uvicorn --reload)
    handler = logging.FileHandler(os.path.join(_LOG_DIR, "geoip_lookup_failures.log"), encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

failure_count = 0


@dataclass
class GeoResult:
    country: str | None
    city: str | None
    latitude: float | None
    longitude: float | None


# Vài IP public mẫu để test khi chưa có file .mmdb thật.
_MOCK_LOCATIONS: dict[str, GeoResult] = {
    "8.8.8.8": GeoResult("US", "Mountain View", 37.386, -122.0838),
    "1.1.1.1": GeoResult("AU", "Sydney", -33.8688, 151.2093),
    "203.0.113.10": GeoResult("VN", "Hanoi", 21.03, 105.85),  # TEST-NET-3, dùng làm IP mẫu VN
}

_reader: Optional["geoip2.database.Reader"] = None
_reader_loaded = False


def _get_reader():
    global _reader, _reader_loaded
    if _reader_loaded:
        return _reader
    _reader_loaded = True

    db_path = get_settings().geoip_db_path
    if os.path.exists(db_path):
        try:
            _reader = geoip2.database.Reader(db_path)
            logger.info(f"Đã tải GeoLite2 database thật từ {db_path}")
        except Exception as exc:  # noqa: BLE001 — file hỏng/không đọc được, coi như không có
            logger.warning(f"Không mở được file GeoLite2 tại {db_path}: {exc}")
            _reader = None
    else:
        logger.warning(
            f"Không tìm thấy file GeoLite2 tại {db_path} — dùng chế độ mock (xem docs/geoip-setup.md)"
        )
        _reader = None
    return _reader


def _record_failure(ip: str, reason: str) -> None:
    global failure_count
    failure_count += 1
    logger.warning(f"lookup thất bại ip={ip} reason={reason}")


def lookup_ip(ip: str) -> Optional[GeoResult]:
    """Tra vị trí theo IP. Trả None nếu thất bại — không bao giờ raise."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        _record_failure(ip, "invalid ip")
        return None

    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        _record_failure(ip, "private/reserved ip")
        return None

    reader = _get_reader()
    if reader is not None:
        try:
            response = reader.city(ip)
            return GeoResult(
                country=response.country.iso_code,
                city=response.city.name,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
            )
        except geoip2.errors.AddressNotFoundError:
            _record_failure(ip, "not found in GeoLite2 db")
            return None
        except Exception as exc:  # noqa: BLE001 — bất kỳ lỗi thư viện nào cũng không được sập luồng login
            _record_failure(ip, f"geoip2 error: {exc}")
            return None

    # Chế độ mock (chưa có file .mmdb thật)
    if ip in _MOCK_LOCATIONS:
        return _MOCK_LOCATIONS[ip]

    _record_failure(ip, "mock mode: ip khong nam trong tap mau")
    return None
