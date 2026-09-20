"""Vị trí dữ liệu RBA. File zip ~1.1GB (CSV bên trong ~9GB) được đọc thẳng từ
zip theo từng chunk, không giải nén ra đĩa.

Thứ tự tìm file zip: biến môi trường RBA_ZIP_PATH, rồi backend/ml/data/rba/,
rồi thư mục Downloads của người dùng.
"""

from __future__ import annotations

import os
from pathlib import Path

RBA_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "rba"
RBA_CSV_NAME = "rba-dataset.csv"
RBA_ZIP_ENV_VAR = "RBA_ZIP_PATH"


def find_rba_zip() -> Path | None:
    candidates: list[Path] = []
    from_env = os.environ.get(RBA_ZIP_ENV_VAR)
    if from_env:
        candidates.append(Path(from_env))
    candidates.append(RBA_DATA_DIR / "rba-dataset.zip")
    candidates.append(Path.home() / "Downloads" / "rba-dataset.zip")

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
