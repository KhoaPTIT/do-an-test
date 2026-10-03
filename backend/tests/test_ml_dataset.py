"""Dataset mô hình bất thường v3 (Phase 4.1C): tất định theo seed, không nhãn trong đặc trưng, chia tập theo thời gian."""

import csv
import hashlib
from pathlib import Path

from ml import build_features, dataset
from ml.features import FEATURE_NAMES


def _make(tmp: Path, seed: int) -> dict[str, str]:
    raws, labels = dataset.build(seed, n_users=8, days=dataset.SIM_DAYS)
    dataset.write(raws, labels, tmp)
    build_features.build(tmp)
    files = ["events.csv", "labels.csv", "features.csv", "splits/train.csv", "splits/validation.csv", "splits/test.csv"]
    return {f: hashlib.sha256((tmp / f).read_bytes()).hexdigest() for f in files}


def test_same_seed_gives_byte_identical_files(tmp_path):
    assert _make(tmp_path / "a", 7) == _make(tmp_path / "b", 7)


def test_different_seed_gives_a_different_dataset(tmp_path):
    assert _make(tmp_path / "a", 7)["events.csv"] != _make(tmp_path / "b", 8)["events.csv"]


def test_generator_does_not_read_the_clock():
    """Không lời gọi now()/today()/utcnow()/time() nào trong bộ sinh (kiểm bằng AST, không tính docstring)."""
    import ast

    tree = ast.parse(Path(dataset.__file__).read_text(encoding="utf-8"))
    calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    assert not calls & {"now", "today", "utcnow", "time"}


def test_labels_are_separate_and_never_in_features(tmp_path):
    _make(tmp_path, 7)
    for name in ("events.csv", "features.csv", "splits/train.csv", "splits/validation.csv", "splits/test.csv"):
        header = next(csv.reader((tmp_path / name).open(encoding="utf-8")))
        assert not {"is_anomaly", "anomaly_type", "label"} & set(header), name
    assert next(csv.reader((tmp_path / "features.csv").open(encoding="utf-8"))) == ["event_id", *FEATURE_NAMES]
    labels = dataset.read_labels(tmp_path / "labels.csv")
    events = {e.event_id: e for e in dataset.read_events(tmp_path / "events.csv")}
    assert labels.keys() == events.keys()
    assert all(events[i].success for i, kind in labels.items() if kind)  # mọi bất thường chèn vào đều là lần THÀNH CÔNG
    assert {k for k in labels.values() if k} <= set(dataset.ANOMALY_PLAN)


def test_splits_are_temporal_and_disjoint(tmp_path):
    _make(tmp_path, 7)
    ts = {e.event_id: e.ts for e in dataset.read_events(tmp_path / "events.csv")}
    ids = {s: build_features.read_split(tmp_path / "splits" / f"{s}.csv")[0] for s in build_features.SPLITS}
    assert all(ids.values())
    assert max(ts[i] for i in ids["train"]) < min(ts[i] for i in ids["validation"])
    assert max(ts[i] for i in ids["validation"]) < min(ts[i] for i in ids["test"])
    assert not (set(ids["train"]) & set(ids["validation"])) and not (set(ids["validation"]) & set(ids["test"]))
