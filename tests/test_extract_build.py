import json

from argo.extract.build import (
    build_all,
    calibrate_baseline,
    dossier_path,
    load_dossier,
    safe_name,
)
from argo.schema import Dossier, Hit, Sample
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


def _hist(i: str, label: str, history_set: str, score_hits: list[str], changed: bool) -> tuple:
    s = Sample(
        id=i,
        name=i,
        version="1",
        prev_version=None,
        label=label,
        subgroup="nato_malevolo" if label == "malicious" else "benigno_popolare",
        date="2024-01-01",
        split="history",
        history_set=history_set,
        source="npm",
        archive_path="x",
        sha256="0",
        fingerprint=i,
    )
    d = Dossier(
        sample_id=i,
        extractor_version="1",
        text="",
        lifecycle={},
        lifecycle_changed=changed,
        dep_changes=[],
        outside_files=[],
        target_profiles=[],
        hits=[Hit(category=c, path="a.js", line=1, snippet="x") for c in score_hits],
        changes=[],
        truncated=False,
        est_tokens=0,
    )
    return s, d


def test_calibrate_baseline_uses_storico_base_only(tmp_path):
    rows = [
        _hist("mal", "malicious", "base", ["credentials"], True),  # score 3.5
        _hist("ben", "benign", "base", ["network"], False),  # score 0.5
        _hist("w1", "malicious", "w1", ["network"], False),  # RQ3 material: ignored
    ]
    samples = [s for s, _ in rows]
    dossiers = {s.id: d for s, d in rows}
    result = calibrate_baseline(samples, dossiers, tmp_path / "baseline.json")
    assert result["n_history"] == 2 and result["recall_history"] == 1.0
    assert result["threshold"] == 3.5
    assert json.loads((tmp_path / "baseline.json").read_text())["n_history"] == 2
