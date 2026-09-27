"""MR12 — app/detection/model_registry.py: tự đăng ký (idempotent), an toàn khi thiếu artifact, không sập khi DB lỗi."""

from app.detection import model_registry
from app.models import ModelRegistryEntry


def test_ensure_registered_creates_an_active_row_pointing_at_the_real_artifacts(db_session):
    entry = model_registry.ensure_registered(db_session)
    assert entry is not None
    assert entry.name == model_registry.HYBRID_NAME and entry.version == model_registry.HYBRID_VERSION
    assert entry.is_active is True and entry.artifact_path == str(model_registry._ARTIFACT_PATH)
    assert entry.feature_signature  # không rỗng


def test_ensure_registered_is_idempotent(db_session):
    first = model_registry.ensure_registered(db_session)
    second = model_registry.ensure_registered(db_session)
    assert first.id == second.id
    assert db_session.query(ModelRegistryEntry).count() == 1


def test_get_active_returns_none_when_nothing_registered(db_session):
    assert model_registry.get_active(db_session) is None


def test_get_active_ignores_inactive_rows(db_session):
    db_session.add(ModelRegistryEntry(name="hybrid_cp2", version="old", artifact_path="/nowhere", is_active=False))
    db_session.commit()
    assert model_registry.get_active(db_session) is None


def test_ensure_registered_returns_none_without_raising_when_the_artifact_is_missing(db_session, monkeypatch, tmp_path):
    monkeypatch.setattr(model_registry, "_ARTIFACT_PATH", tmp_path / "khong_ton_tai.joblib")
    assert model_registry.ensure_registered(db_session) is None
    assert db_session.query(ModelRegistryEntry).count() == 0


def test_ensure_registered_swallows_db_errors(db_session, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("DB hỏng")

    monkeypatch.setattr(model_registry, "get_active", boom)
    assert model_registry.ensure_registered(db_session) is None  # không raise ra ngoài
