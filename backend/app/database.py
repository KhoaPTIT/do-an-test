from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings

settings = get_settings()

# MR12: pool_size/max_overflow mặc định của SQLAlchemy (5 + 10 = 15) không đủ khi nhiều pipeline nền chạy đồng thời —
# mỗi lần chấm cần vài kết nối ngắn cho rule engine + đặc trưng RBA (đo tải thấy nghẽn ở đây sau khi đã sửa pipeline
# nền không còn chặn vòng lặp sự kiện chung — xem docs/realtime-integration.md, app/detection/pipeline.py).
engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=20, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """Dependency FastAPI: mở một session DB cho mỗi request, đóng lại sau khi xong."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
