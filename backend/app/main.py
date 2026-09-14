from fastapi import FastAPI
from sqlalchemy import text

from app.database import SessionLocal

app = FastAPI(title="Anomaly Login Detection API", version="0.1.0")


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
