"""Train / nạp / chấm điểm model bất thường (Phase 4.1 — ML3). Dùng dataset NHỎ sinh tại chỗ (cùng mã với dataset thật)."""

import json

import numpy as np
import pytest

from ml import build_features, dataset, evaluate, train
from ml.anomaly_model import AnomalyModel, ModelLoadError
from ml.features import FEATURE_NAMES, feature_signature

REQUIRED_METADATA = {
    "model_name", "model_version", "created_at", "feature_names", "feature_signature", "training_seed", "train_size",
    "validation_size", "test_size", "threshold", "algorithm_parameters",
}


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    root = tmp_path_factory.mktemp("ml")
    data, model_dir, evidence = root / "data", root / "model", root / "evidence"
    raws, labels = dataset.build(dataset.DATASET_SEED, n_users=24, days=dataset.SIM_DAYS)
    dataset.write(raws, labels, data)
    build_features.build(data)
    meta = train.train(data, model_dir)
    return data, model_dir, evidence, meta


def test_metadata_has_every_required_field(trained):
    _, model_dir, _, meta = trained
    assert REQUIRED_METADATA <= set(meta)
    on_disk = json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))
    assert on_disk["feature_names"] == FEATURE_NAMES and on_disk["feature_signature"] == feature_signature()
    assert on_disk["algorithm_parameters"]["contamination"] == "auto"  # không ước lượng từ tỉ lệ nhãn
    assert on_disk["model_name"] == "isolation_forest"


def test_threshold_is_chosen_on_validation_normals_only(trained):
    data, model_dir, _, meta = trained
    model = AnomalyModel.load(model_dir)
    ids, x = build_features.read_split(data / "splits" / "validation.csv")
    labels = dataset.read_labels(data / "labels.csv")
    normal = [s for s, i in zip(model.scores(x), ids) if labels[i] is None]
    assert meta["threshold"] == pytest.approx(float(np.quantile(normal, 1 - train.TARGET_FPR, method="higher")))
    assert meta["validation"]["fpr_at_threshold"] <= train.TARGET_FPR + 1 / len(normal)


def test_training_is_deterministic(trained, tmp_path):
    data, model_dir, _, meta = trained
    again = train.train(data, tmp_path)
    assert again["threshold"] == meta["threshold"] and again["model_version"] == meta["model_version"]
    x = build_features.read_split(data / "splits" / "test.csv")[1][:50]
    assert AnomalyModel.load(tmp_path).scores(x) == AnomalyModel.load(model_dir).scores(x)


def test_score_marks_anomaly_by_the_stored_threshold(trained):
    _, model_dir, _, _ = trained
    model = AnomalyModel.load(model_dir)
    normal = dict.fromkeys(FEATURE_NAMES, 0.0) | {"log_minutes_since_last_success": 6.5, "logins_last_24h": 1.0}
    odd = normal | {"is_new_location": 1.0, "is_new_device": 1.0, "log_distance_km_from_home": 9.4, "log_travel_speed_kmh": 9.0, "hour_deviation": 11.0}
    s_normal, s_odd = model.score(normal), model.score(odd)
    assert s_odd.anomaly_score > s_normal.anomaly_score
    assert s_odd.is_anomaly == (s_odd.anomaly_score >= model.threshold) and s_odd.is_anomaly
    assert s_odd.top_features and {r["feature"] for r in s_odd.top_features} <= set(FEATURE_NAMES)


def test_missing_artifact_raises_a_clear_error(tmp_path):
    with pytest.raises(ModelLoadError, match="chưa có artifact"):
        AnomalyModel.load(tmp_path / "nothing")


def test_feature_signature_mismatch_is_refused(trained, tmp_path):
    import shutil

    _, model_dir, _, _ = trained
    shutil.copytree(model_dir, tmp_path / "m")
    meta_path = tmp_path / "m" / "metadata.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["feature_signature"] = "000000000000"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(ModelLoadError, match="chữ ký đặc trưng"):
        AnomalyModel.load(tmp_path / "m")


def test_evaluate_writes_evidence_with_the_required_metrics(trained):
    data, model_dir, evidence, _ = trained
    result = evaluate.evaluate(data, model_dir, evidence)
    assert {"tp", "fp", "tn", "fn", "precision", "recall", "f1", "fpr"} <= set(result["at_threshold"])
    assert {"roc_auc", "pr_auc_average_precision"} <= set(result)
    for name in ("evaluation.json", "per_anomaly_metrics.json", "confusion_matrix.json", "confusion_matrix.png"):
        assert (evidence / name).is_file()
    a = result["at_threshold"]
    assert a["tp"] + a["fn"] == result["test_anomalies"] and sum((a["tp"], a["fp"], a["tn"], a["fn"])) == result["test_rows"]
