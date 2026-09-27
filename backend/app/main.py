import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import get_settings
from app.database import SessionLocal
from app.routers import admin, alerts, auth, blocklist, campaigns, events, ws

settings = get_settings()
logger = logging.getLogger("main")

app = FastAPI(title="Anomaly Login Detection API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(campaigns.router)
app.include_router(blocklist.router)
app.include_router(ws.router)


@app.on_event("startup")
def _startup_mr12() -> None:
    """MR12: nạp threat intel + phiên bản mô hình hybrid MỘT LẦN khi tiến trình khởi động (không phải mỗi lần đăng nhập).
    Lỗi ở đây KHÔNG được chặn ứng dụng khởi động — `load_threat_intel_at_startup`/`ensure_registered` tự nuốt lỗi và ghi
    log, hybrid risk engine khi đó chạy ở hồ sơ dự phòng (chỉ luật, không có ML) cho tới khi khắc phục và khởi động lại."""
    from app.detection import hybrid_runtime, model_registry
    from app.detection.rule_engine_runtime import load_threat_intel_at_startup

    load_threat_intel_at_startup()
    db = SessionLocal()
    try:
        model_registry.ensure_registered(db)
        hybrid_runtime.load_at_startup(db)
    except Exception:  # noqa: BLE001 — không được chặn khởi động ứng dụng
        logger.exception("lỗi khi khởi tạo MR12 (threat intel / hybrid risk engine)")
    finally:
        db.close()


@app.get("/health")
def health_check():
    """Kiểm tra backend còn sống và kết nối được DB (nhiệm vụ 1.3)."""
    db_ok = True
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    return {"status": "ok", "database": "connected" if db_ok else "unavailable"}
