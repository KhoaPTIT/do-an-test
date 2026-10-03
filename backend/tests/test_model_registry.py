"""`model_registry` (Phase 4.1): ghi phiên bản model bất thường ĐANG nạp, một hàng active duy nhất, không bao giờ raise."""

from app.detection import ml_runtime, model_registry
from app.models import ModelRegistryEntry


def test_nothing_is_registered_when_no_model_is_loaded(db_session):
    runtime = ml_runtime.MLRuntime()
    runtime.disable("không có artifact")
    assert model_registry.ensure_registered(db_session, runtime) is None
    assert db_session.query(ModelRegistryEntry).count() == 0


def test_the_loaded_model_version_becomes_the_single_active_row(db_session, trained_ml_model_dir):
    runtime = ml_runtime.MLRuntime()
    assert runtime.load(trained_ml_model_dir)
    entry = model_registry.ensure_registered(db_session, runtime)
    assert entry.is_active and entry.name == "isolation_forest" and entry.version == runtime.model.model_version
    assert entry.feature_signature == runtime.model.metadata["feature_signature"]
    assert model_registry.ensure_registered(db_session, runtime).id == entry.id  # idempotent
    assert db_session.query(ModelRegistryEntry).count() == 1


def test_a_new_version_deactivates_the_previous_one(db_session, trained_ml_model_dir):
    db_session.add(ModelRegistryEntry(name="isolation_forest", version="old", artifact_path="/x", is_active=True))
    db_session.commit()
    runtime = ml_runtime.MLRuntime()
    runtime.load(trained_ml_model_dir)
    model_registry.ensure_registered(db_session, runtime)
    rows = {r.version: r.is_active for r in db_session.query(ModelRegistryEntry).all()}
    assert rows["old"] is False and rows[runtime.model.model_version] is True
    assert model_registry.get_active(db_session).version == runtime.model.model_version


def test_db_errors_are_swallowed(db_session, trained_ml_model_dir, monkeypatch):
    runtime = ml_runtime.MLRuntime()
    runtime.load(trained_ml_model_dir)

    def boom():
        raise RuntimeError("db hỏng")

    monkeypatch.setattr(db_session, "commit", boom)
    assert model_registry.ensure_registered(db_session, runtime) is None
