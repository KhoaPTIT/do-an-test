"""Tra cứu vị trí địa lý từ địa chỉ IP.

Bản này dùng bảng tra cứu offline dựng sẵn để đồ án chạy được ngay
mà không cần đăng ký tài khoản MaxMind. Khi muốn dùng dữ liệu thật:

    pip install geoip2
    Tải GeoLite2-City.mmdb từ maxmind.com, đặt vào backend/data/
    Đặt biến môi trường GEOIP_DB_PATH trỏ tới file đó.

Hàm lookup_ip() sẽ tự động ưu tiên GeoLite2 nếu có.
"""
import ipaddress
import os
from pathlib import Path

_GEOIP_DB = os.getenv("GEOIP_DB_PATH")
_reader = None

if _GEOIP_DB and Path(_GEOIP_DB).exists():
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(_GEOIP_DB)
    except Exception:
        _reader = None


# Bảng tra cứu offline: tiền tố mạng -> (quốc gia, thành phố, vĩ độ, kinh độ, loại mạng)
_PREFIX_TABLE = [
    ("14.161.0.0/16",   ("Vietnam", "Ha Noi", 21.028, 105.854, "residential")),
    ("14.162.0.0/16",   ("Vietnam", "Ho Chi Minh", 10.823, 106.630, "residential")),
    ("113.160.0.0/12",  ("Vietnam", "Ha Noi", 21.028, 105.854, "residential")),
    ("117.0.0.0/11",    ("Vietnam", "Da Nang", 16.047, 108.206, "residential")),
    ("103.20.0.0/14",   ("Vietnam", "Ho Chi Minh", 10.823, 106.630, "hosting")),
    ("165.21.0.0/16",   ("Singapore", "Singapore", 1.352, 103.820, "residential")),
    ("103.6.0.0/16",    ("Singapore", "Singapore", 1.352, 103.820, "hosting")),
    ("1.2.3.0/24",      ("Japan", "Tokyo", 35.676, 139.650, "residential")),
    ("185.220.100.0/22", ("Germany", "Frankfurt", 50.110, 8.682, "tor")),
    ("45.134.140.0/22", ("Netherlands", "Amsterdam", 52.370, 4.895, "hosting")),
    ("91.219.236.0/22", ("Russia", "Moscow", 55.755, 37.617, "hosting")),
    ("5.188.0.0/16",    ("Russia", "Saint Petersburg", 59.937, 30.308, "hosting")),
    ("197.210.0.0/16",  ("Nigeria", "Lagos", 6.524, 3.379, "residential")),
    ("41.58.0.0/16",    ("Nigeria", "Lagos", 6.524, 3.379, "residential")),
    ("123.30.0.0/16",   ("Vietnam", "Ha Noi", 21.028, 105.854, "hosting")),
    ("8.8.8.0/24",      ("United States", "Mountain View", 37.386, -122.084, "hosting")),
    ("104.28.0.0/14",   ("United States", "San Francisco", 37.775, -122.419, "hosting")),
]

_UNKNOWN = {
    "country": "Unknown", "city": "Unknown",
    "lat": None, "lon": None, "network_type": "unknown",
}


def _lookup_offline(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return dict(_UNKNOWN)

    if addr.is_private or addr.is_loopback:
        return {"country": "Vietnam", "city": "Local", "lat": 21.028,
                "lon": 105.854, "network_type": "residential"}

    for prefix, (country, city, lat, lon, net) in _PREFIX_TABLE:
        if addr in ipaddress.ip_network(prefix):
            return {"country": country, "city": city, "lat": lat,
                    "lon": lon, "network_type": net}
    return dict(_UNKNOWN)


def lookup_ip(ip: str) -> dict:
    """Trả về dict: country, city, lat, lon, network_type."""
    if _reader is not None:
        try:
            r = _reader.city(ip)
            return {
                "country": r.country.name or "Unknown",
                "city": r.city.name or "Unknown",
                "lat": r.location.latitude,
                "lon": r.location.longitude,
                "network_type": "unknown",
            }
        except Exception:
            pass
    return _lookup_offline(ip)
