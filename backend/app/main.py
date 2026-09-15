from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import get_settings
from app.database import SessionLocal
from app.routers import alerts, auth, events

settings = get_settings()

app = FastAPI(title="Anomaly Login Detection API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(events.router)
app.include_router(alerts.router)


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
