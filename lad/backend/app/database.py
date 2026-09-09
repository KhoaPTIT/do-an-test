"""Khởi tạo kết nối cơ sở dữ liệu và session cho FastAPI."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    """Dependency của FastAPI: mở session, đảm bảo đóng sau khi xử lý xong."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Tạo bảng nếu chưa có. Gọi lúc khởi động ứng dụng."""
    from app.models import Base
    Base.metadata.create_all(bind=engine)
