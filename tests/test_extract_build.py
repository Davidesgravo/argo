from argo.extract.build import build_all, dossier_path, load_dossier, safe_name
from argo.schema import Sample
from tests.helpers import make_tgz, pkg_json


def _sample(tmp_path) -> Sample:
    make_tgz(
        tmp_path / "cache/a-1.0.1.tgz",
        {"package.json": pkg_json("@s/a", "1.0.1"), "x.js": "eval(1)"},
    )
    make_tgz(tmp_path / "cache/a-1.0.0.tgz", {"package.json": pkg_json("@s/a", "1.0.0")})
    return Sample(
        id="@s/a@1.0.1",
        name="@s/a",
        version="1.0.1",
        prev_version="1.0.0",
        label="benign",
        subgroup="benigno_popolare",
        date="2025-02-01",
        split="test",
        source="npm",
        archive_path="cache/a-1.0.1.tgz",
        prev_archive_path="cache/a-1.0.0.tgz",
        sha256="0",
        fingerprint="f",
    )


def test_safe_name():
    assert safe_name("@s/a@1.0.1") == "_s_a_1.0.1"


def test_build_all_writes_and_skips_existing(tmp_path):
    s = _sample(tmp_path)
    out = tmp_path / "dossiers"
    assert build_all([s], tmp_path, out, log=lambda _: None) == 1
    assert build_all([s], tmp_path, out, log=lambda _: None) == 0
    d = load_dossier(s.id, out)
    assert dossier_path(s.id, out).exists() and "TYPE: update from 1.0.0" in d.text


def test_build_all_survives_broken_archive(tmp_path):
    s = _sample(tmp_path)
    (tmp_path / s.archive_path).write_bytes(b"garbage")
    assert build_all([s], tmp_path, tmp_path / "d", log=lambda _: None) == 0
