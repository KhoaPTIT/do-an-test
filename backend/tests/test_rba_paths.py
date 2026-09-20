"""MR1 — tìm file zip RBA: biến môi trường được ưu tiên, không thấy thì trả None."""

from ml.rba import paths


def test_env_var_takes_priority(tmp_path, monkeypatch):
    fake_zip = tmp_path / "custom.zip"
    fake_zip.write_bytes(b"x")
    monkeypatch.setenv(paths.RBA_ZIP_ENV_VAR, str(fake_zip))
    assert paths.find_rba_zip() == fake_zip


def test_returns_none_when_nothing_exists(tmp_path, monkeypatch):
    monkeypatch.setenv(paths.RBA_ZIP_ENV_VAR, str(tmp_path / "khong-ton-tai.zip"))
    monkeypatch.setattr(paths, "RBA_DATA_DIR", tmp_path / "rba")
    monkeypatch.setattr(paths.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert paths.find_rba_zip() is None
