"""Fixture dùng chung: DB SQLite in-memory + Redis giả lập (fakeredis)
riêng cho mỗi test, tách biệt hoàn toàn khỏi Postgres/Redis dev — test
không cần Docker đang chạy.
"""

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Thay redis_client thật bằng fakeredis cho MỌI test — brute force,
    credential stuffing đều dùng chung module app.detection.rate_counter.
    """
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr("app.detection.rate_counter.redis_client", client)
    yield client
    client.flushall()


@pytest.fixture()
def db_session(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # app/detection/pipeline.py (background task của POST /login, nhiệm vụ
    # 5.2) mở SESSION RIÊNG qua app.database.SessionLocal — KHÔNG đi qua
    # Depends(get_db) nên override ở dưới không đụng tới nó. Không patch
    # chỗ này thì test sẽ âm thầm ghi vào Postgres dev thật (hoặc lỗi nếu
    # Postgres không chạy) thay vì SQLite in-memory của test.
    monkeypatch.setattr("app.detection.pipeline.SessionLocal", TestingSessionLocal)
    # app/main.py (MR12): sự kiện "startup" (đăng ký model_registry, nạp hybrid risk engine) cũng mở SESSION RIÊNG
    # qua app.database.SessionLocal, chạy khi TestClient(app) vào `with` — cùng lý do phải patch như trên.
    monkeypatch.setattr("app.main.SessionLocal", TestingSessionLocal)
    # app/detection/rule_engine_runtime.py cache blocklist (MR12) VÀ rule config (MR17) DB TTL 15s ở BIẾN MODULE
    # (persist giữa các test trong cùng tiến trình pytest) — xoá cả hai cache mỗi test để không đọc nhầm dữ liệu đã
    # cache từ DB (SQLite in-memory) của một test KHÁC chạy trước đó chưa quá 15 giây.
    from app.detection.rule_engine_runtime import invalidate_blocklist_cache, invalidate_rule_config_cache
    from app.routers.model_health import invalidate_drift_cache

    invalidate_blocklist_cache()
    invalidate_rule_config_cache()
    # app/routers/model_health.py (MR17): cache drift TTL 600s — RẤT dễ rò rỉ giữa các test nếu không xoá (dài hơn
    # nhiều so với thời gian chạy cả bộ test), không đụng _reference_frame_cache (file train RBA không đổi).
    invalidate_drift_cache()

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def ml_runtime_off_by_default(monkeypatch, tmp_path_factory):
    """Phase 4.1: model bất thường TẮT mặc định trong test — kết quả không phụ thuộc máy có artifact `ml/artifacts/` hay
    không (kể cả khi `TestClient` chạy sự kiện startup). Test cần model dùng fixture `trained_ml_model_dir`."""
    import ml.anomaly_model
    from app.detection import ml_runtime

    monkeypatch.setattr(ml.anomaly_model, "ARTIFACT_DIR", tmp_path_factory.mktemp("no_ml_artifact"))
    runtime = ml_runtime.MLRuntime()
    runtime.disable("tắt mặc định trong test")
    monkeypatch.setattr(ml_runtime, "_runtime", runtime)


@pytest.fixture(scope="session")
def trained_ml_model_dir(tmp_path_factory):
    """Một model THẬT train tại chỗ trên dataset nhỏ sinh bằng CÙNG mã với dataset chính (vài giây)."""
    from ml import build_features, dataset, train

    root = tmp_path_factory.mktemp("ml_model")
    raws, labels = dataset.build(dataset.DATASET_SEED, n_users=24, days=dataset.SIM_DAYS)
    dataset.write(raws, labels, root / "data")
    build_features.build(root / "data")
    train.train(root / "data", root / "model")
    return root / "model"


@pytest.fixture()
def ml_on(monkeypatch, trained_ml_model_dir):
    """Bật model bất thường (artifact train tại chỗ) cho test này."""
    from app.detection import ml_runtime

    runtime = ml_runtime.MLRuntime()
    assert runtime.load(trained_ml_model_dir)
    monkeypatch.setattr(ml_runtime, "_runtime", runtime)
    return runtime
