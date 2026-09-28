"""MR17 — GET /model-health: danh sách phiên bản (`model_registry`, MR12) + trôi đặc trưng (PSI, `ml/rba/drift.py`,
MR12) giữa train RBA và `login_events` thật hiện tại. Chậm (đọc file parquet train + tính lại đặc trưng RBA) nên chỉ
vài test — cơ chế PSI/model_registry đã kiểm kỹ ở nơi khác (ml/rba/test_drift.py nếu có, test_model_registry.py)."""

from datetime import datetime, timezone

from app.models import Admin, ModelRegistryEntry, User
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"


def _admin_token(db_session, client):
    db_session.add(Admin(username="admin", password_hash=hash_password(ADMIN_PASSWORD)))
    db_session.commit()
    login = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    return login.json()["access_token"]


def test_requires_admin_auth(client):
    assert client.get("/model-health").status_code == 401


def test_returns_registered_versions_and_a_drift_summary(client, db_session):
    """`client` fixture tự đăng ký `hybrid_cp2`/`cp2` lúc "startup" (xem docstring tests/test_pipeline_mr12.py) — dùng
    tên/phiên bản KHÁC cho hàng của test này để không đụng UNIQUE(name, version), rồi kiểm hàng đó CÓ MẶT (không giả
    định danh sách chỉ có đúng 1 hàng)."""
    token = _admin_token(db_session, client)
    db_session.add(ModelRegistryEntry(
        name="test_model", version="v1", artifact_path="x.joblib", is_active=False, trained_at=datetime.now(timezone.utc),
    ))
    db_session.commit()

    response = client.get("/model-health", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    by_name = {v["name"]: v for v in body["versions"]}
    assert "test_model" in by_name and by_name["test_model"]["version"] == "v1" and by_name["test_model"]["is_active"] is False
    # Không có login_events thật nào trong DB test này -> quá ít dữ liệu, PSI đánh dấu low_confidence.
    assert body["drift_low_confidence"] is True
    assert body["drift_n_current"] == 0
    assert isinstance(body["drift_top_features"], list) and len(body["drift_top_features"]) > 0
