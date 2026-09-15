"""Tạo tài khoản admin (nhiệm vụ 5.1) — chưa có UI đăng ký, dùng script này.

Chạy:
    cd backend
    venv\\Scripts\\python.exe -m scripts.create_admin --username admin --password "MatKhauManh123!"
"""

from __future__ import annotations

import argparse

from app.database import Base, SessionLocal, engine
from app.models import Admin
from app.security import hash_password


def main(username: str, password: str) -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(Admin).filter(Admin.username == username).first()
        if existing is not None:
            existing.password_hash = hash_password(password)
            db.commit()
            print(f"Đã cập nhật mật khẩu cho admin '{username}'.")
            return

        db.add(Admin(username=username, password_hash=hash_password(password)))
        db.commit()
        print(f"Đã tạo admin '{username}'.")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    main(username=args.username, password=args.password)
