"""Kiểm tra môi trường cho giai đoạn mở rộng AI (MR1).

Chạy:
    cd backend
    venv\\Scripts\\python.exe -m ml.check_env

Mã thoát 1 nếu có mục LỖI (thiếu thứ bắt buộc cho MR2-MR8). Mục CẢNH BÁO chỉ
nhắc thứ cần đến ở giai đoạn sau (file ASN, danh sách threat-intel) — không
chặn việc làm việc với dữ liệu RBA.
"""

from __future__ import annotations

import shutil
import sys
import zipfile
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

from app.config import get_settings
from ml.rba.paths import RBA_CSV_NAME, find_rba_zip
from scripts.update_threat_feeds import FEED_DIR, FEEDS

BACKEND_DIR = Path(__file__).resolve().parents[1]
MIN_FREE_GB = 5.0

# (tên distribution trên PyPI, dùng cho ở đâu)
REQUIRED_PACKAGES = [
    ("numpy", "nền tảng"),
    ("pandas", "nền tảng"),
    ("scikit-learn", "Isolation Forest, LOF, Autoencoder"),
    ("lightgbm", "mô hình supervised (MR6)"),
    ("shap", "giải thích mô hình (MR8)"),
    ("pyarrow", "đọc/ghi Parquet (MR2)"),
    ("duckdb", "đặc trưng cấp IP/ASN trên toàn bộ dữ liệu (MR3)"),
    ("user-agents", "phân tích User-Agent thời gian thực (MR12)"),
    ("geoip2", "GeoIP/ASN"),
]


@dataclass
class Check:
    status: str  # OK | CẢNH BÁO | LỖI
    message: str


def check_packages() -> list[Check]:
    results = []
    for name, purpose in REQUIRED_PACKAGES:
        try:
            results.append(Check("OK", f"{name} {metadata.version(name)} — {purpose}"))
        except metadata.PackageNotFoundError:
            results.append(Check("LỖI", f"thiếu thư viện {name} ({purpose}) — pip install {name}"))
    return results


def check_rba_zip() -> Check:
    path = find_rba_zip()
    if path is None:
        return Check("LỖI", "không thấy rba-dataset.zip (đặt biến môi trường RBA_ZIP_PATH hoặc chép vào backend/ml/data/rba/)")
    try:
        with zipfile.ZipFile(path) as zf:
            info = zf.getinfo(RBA_CSV_NAME)
    except (zipfile.BadZipFile, KeyError) as exc:
        return Check("LỖI", f"{path} không đọc được {RBA_CSV_NAME}: {exc}")
    gib = 1024**3
    return Check(
        "OK",
        f"RBA zip: {path} ({path.stat().st_size / gib:.2f} GB), chứa {RBA_CSV_NAME} ({info.file_size / gib:.2f} GB)",
    )


def _resolve(path_str: str) -> Path:
    path = Path(path_str)
    return path if path.is_absolute() else BACKEND_DIR / path


def check_geoip() -> list[Check]:
    settings = get_settings()
    results = []

    city = _resolve(settings.geoip_db_path)
    results.append(
        Check("OK", f"GeoLite2-City: {city.name}")
        if city.is_file()
        else Check("LỖI", f"thiếu {city} (xem docs/geoip-setup.md)")
    )

    asn = _resolve(settings.geoip_asn_db_path)
    results.append(
        Check("OK", f"GeoLite2-ASN: {asn.name}")
        if asn.is_file()
        else Check("CẢNH BÁO", f"chưa có {asn.name} — cần từ MR12 (tích hợp realtime), xem docs/geoip-setup.md")
    )
    return results


def check_threat_feeds() -> list[Check]:
    feed_dir = Path(FEED_DIR).resolve()
    results = []
    for feed in FEEDS:
        path = feed_dir / feed.filename
        if path.is_file():
            entries = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
            results.append(Check("OK", f"{feed.filename}: {entries:,} mục"))
        else:
            results.append(Check("CẢNH BÁO", f"chưa có {feed.filename} — chạy: python -m scripts.update_threat_feeds (cần từ MR9)"))
    return results


def check_disk() -> Check:
    free_gb = shutil.disk_usage(BACKEND_DIR).free / 1024**3
    if free_gb < MIN_FREE_GB:
        return Check("LỖI", f"ổ đĩa chỉ còn {free_gb:.1f} GB trống (cần ≥ {MIN_FREE_GB:.0f} GB cho Parquet/mẫu/artifact)")
    return Check("OK", f"ổ đĩa còn {free_gb:.1f} GB trống (cần ≥ {MIN_FREE_GB:.0f} GB)")


def run_all() -> list[Check]:
    return [*check_packages(), check_rba_zip(), *check_geoip(), *check_threat_feeds(), check_disk()]


def main() -> int:
    results = run_all()
    for check in results:
        print(f"[{check.status:<9}] {check.message}")

    errors = sum(1 for c in results if c.status == "LỖI")
    warnings = sum(1 for c in results if c.status == "CẢNH BÁO")
    print(f"\nTổng: {len(results) - errors - warnings} OK, {warnings} cảnh báo, {errors} lỗi")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
