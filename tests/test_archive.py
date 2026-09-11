import pytest

from argo.extract.archive import ArchiveError, read_datadog_zip, read_npm_tgz
from tests.helpers import make_datadog_zip, make_pkg, make_tgz, pkg_json


def test_tgz_strips_top_directory(tmp_path):
    p = make_tgz(tmp_path / "a.tgz", {"package.json": pkg_json(), "lib/x.js": "1"})
    pkg = read_npm_tgz(p.read_bytes())
    assert set(pkg.files) == {"package.json", "lib/x.js"}


def test_tgz_with_non_standard_top_dir(tmp_path):
    p = make_tgz(tmp_path / "a.tgz", {"package.json": pkg_json()}, top="node")
    assert "package.json" in read_npm_tgz(p.read_bytes()).files


def test_tgz_without_package_json_raises(tmp_path):
    p = make_tgz(tmp_path / "a.tgz", {"x.js": "1"})
    with pytest.raises(ArchiveError):
        read_npm_tgz(p.read_bytes())


def test_tgz_garbage_raises():
    with pytest.raises(ArchiveError):
        read_npm_tgz(b"not a tarball")


def test_encrypted_datadog_zip(tmp_path):
    z = make_datadog_zip(
        tmp_path / "s.zip",
        {"package.json": pkg_json(), "bundle.js": "x"},
        {"time": {"1.0.0": "2025-01-01T00:00:00Z"}},
    )
    pkg, info = read_datadog_zip(z)
    assert set(pkg.files) == {"package.json", "bundle.js"}
    assert info["time"]["1.0.0"].startswith("2025")


def test_unencrypted_zip_also_reads(tmp_path):
    z = make_datadog_zip(tmp_path / "s.zip", {"package.json": pkg_json()}, {}, password=None)
    pkg, info = read_datadog_zip(z)
    assert "package.json" in pkg.files and info == {}


def test_manifest_parsing():
    assert make_pkg({"package.json": pkg_json(scripts={"a": "b"})}).manifest()["scripts"] == {
        "a": "b"
    }
    assert make_pkg({"package.json": "{broken"}).manifest() == {}
    assert make_pkg({"package.json": "[1]"}).manifest() == {}
    assert make_pkg({"x.js": "1"}).manifest() == {}
