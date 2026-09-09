"""Điểm khởi động ứng dụng.

Chạy:  uvicorn app.main:app --reload --port 8000
Tài liệu API tự sinh:  http://localhost:8000/docs
Dashboard:             http://localhost:8000/
"""
import logging
from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import alerts, events, stats
from app.database import init_db

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Chuẩn bị cơ sở dữ liệu trước khi nhận request đầu tiên."""
    init_db()
    logging.info("Cơ sở dữ liệu sẵn sàng")
    yield


app = FastAPI(
    lifespan=lifespan,
    title="Hệ thống phát hiện đăng nhập bất thường",
    description="API chấm điểm rủi ro cho từng lần đăng nhập, "
                "kết hợp luật và học máy.",
    version="1.0.0",
)

# Cho phép dashboard chạy ở cổng khác gọi API trong lúc phát triển.
# Khi triển khai thật phải liệt kê đúng tên miền, không để dấu sao.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8000",
                   "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(stats.router)


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}


# Phục vụ dashboard tĩnh. Đặt sau cùng để không che các route API.
_FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend"
if _FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=_FRONTEND), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(_FRONTEND / "index.html")
