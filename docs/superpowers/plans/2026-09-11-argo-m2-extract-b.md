# Argo — M2 Extractor, part B (Tasks 11-12)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Read the index `2026-09-11-argo-plan.md` first. Depends on Tasks 8-10; Task 12 Step 7+ also needs the corpus from Task 7.

---

### Task 11: Dossier assembly with token budget

**Files:**
- Create: `argo/extract/dossier.py`, `tests/test_dossier.py`

**Interfaces:**
- Consumes: `PackageFiles` (3), `lifecycle_scripts`, `dep_changes`, `outside_files`, `script_targets` (8), `diff_files`, `profile_file` (9), `CATEGORY_ORDER`, `scan_text`, `scan_package` (10), `Dossier` (1)
- Produces:
  - `fmt_size(n: int) -> str`
  - `build_dossier(sample_id: str, name: str, version: str, new: PackageFiles, old: PackageFiles | None, prev_version: str | None, budget_tokens: int = DOSSIER_TOKEN_BUDGET) -> Dossier`
  - `SECTION_TITLES: tuple[str, ...]` — the four `## N.` headings, always present in every dossier (uniform format)

The dossier text (English) always has this shape:

```
PACKAGE: <name>@<version>
TYPE: update from <prev> | update from <prev> (previous version not available: no diff) | new package (no previous version)
FILES: <n> files, <size> total

## 1. Install-time execution vectors
- script postinstall: node bundle.js  [NEW]
- optionalDependencies @x/y: github:x/y#sha  [NON-REGISTRY SOURCE, previously absent]
- added file outside declared `files`: router_init.js (2.2 MB)

## 2. Files run at install time or flagged above
### setup_bun.js (4.8 KB)
<profile line, or inline content if ≤ 2 KB and text>

## 3. Suspicious patterns in added/modified code
- [credentials] bun_environment.js:1  <snippet>

## 4. File changes vs previous version
+ bundle.js (3.6 MB)
~ package.json (1.6 KB)

## Notes
omitted for length: 12 patterns, 40 changes
```

- [ ] **Step 1: Write the failing tests `tests/test_dossier.py`**

```python
from argo.extract.dossier import SECTION_TITLES, build_dossier
from tests.helpers import make_pkg, pkg_json

OLD = make_pkg({"package.json": pkg_json("x", "1.0.0"), "dist/a.js": "module.exports = 1"})


def _w2_like():
    return make_pkg({
        "package.json": pkg_json("x", "1.0.1", scripts={"preinstall": "node setup_bun.js"}),
        "dist/a.js": "module.exports = 1",
        "setup_bun.js": "require('child_process').execSync('curl -fsSL https://bun.sh/install | bash')",
        "bun_environment.js": ";".join(f"var _0x{i:04x}=1" for i in range(40)) + ";process.env.GITHUB_TOKEN",
    })


def test_w2_like_update():
    d = build_dossier("x@1.0.1", "x", "1.0.1", _w2_like(), OLD, "1.0.0")
    assert "TYPE: update from 1.0.0" in d.text
    assert "- script preinstall: node setup_bun.js  [NEW]" in d.text
    assert "curl -fsSL https://bun.sh/install" in d.text  # small target inlined
    cats = {h.category for h in d.hits}
    assert {"runtime_download", "exec", "credentials", "obfuscation"} <= cats
    assert d.lifecycle_changed and not d.truncated
    assert d.hits[0].path in ("package.json#scripts", "setup_bun.js")  # targets first


def test_w3_like_non_registry_dep_and_outside_file():
    new = make_pkg({
        "package.json": pkg_json("x", "1.0.1", files=["dist"],
                                 optionalDependencies={"@x/setup": "github:x/router#79ac"}),
        "dist/a.js": "module.exports = 1",
        "router_init.js": "var a=1;" * 600,
    })
    d = build_dossier("x@1.0.1", "x", "1.0.1", new, OLD, "1.0.0")
    assert "[NON-REGISTRY SOURCE, previously absent]" in d.text
    assert "added file outside declared `files`: router_init.js" in d.text
    assert "### router_init.js" in d.text and "profile: lines=" in d.text
    assert not d.lifecycle_changed and d.outside_files == ["router_init.js"]


def test_benign_update_with_unchanged_install_script():
    scripts = {"postinstall": "node install.js"}
    old = make_pkg({"package.json": pkg_json("e", "1.0.0", scripts=scripts), "install.js": "download()"})
    new = make_pkg({"package.json": pkg_json("e", "1.0.1", scripts=scripts), "install.js": "download()"})
    d = build_dossier("e@1.0.1", "e", "1.0.1", new, old, "1.0.0")
    assert "[unchanged]" in d.text and not d.lifecycle_changed


def test_new_package_and_missing_previous():
    pkg = make_pkg({"package.json": pkg_json("n", "9.9.9")})
    assert "TYPE: new package (no previous version)" in build_dossier("n", "n", "9.9.9", pkg, None, None).text
    t = build_dossier("n", "n", "9.9.9", pkg, None, "9.9.8").text
    assert "previous version not available" in t


def test_uniform_sections_even_when_empty():
    d = build_dossier("n", "n", "1", make_pkg({"package.json": pkg_json("n", "1")}), None, None)
    for title in SECTION_TITLES:
        assert title in d.text
    assert "- none" in d.text


def test_budget_truncates_and_reports():
    files = {"package.json": pkg_json("big", "1.0.0")}
    files |= {f"lib/f{i}.js": f"eval(x{i}); fetch('https://c{i}.evil.xyz')" for i in range(300)}
    d = build_dossier("big", "big", "1.0.0", make_pkg(files), None, None, budget_tokens=500)
    assert d.truncated and "omitted for length" in d.text
    assert d.est_tokens <= 500 + 60
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_dossier.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'argo.extract.dossier'`.

- [ ] **Step 3: Implement `argo/extract/dossier.py`**

```python
from argo.config import DOSSIER_TOKEN_BUDGET, EXTRACTOR_VERSION
from argo.extract.archive import PackageFiles
from argo.extract.diff import diff_files
from argo.extract.indicators import CATEGORY_ORDER, scan_package, scan_text
from argo.extract.manifest import dep_changes, lifecycle_scripts, outside_files, script_targets
from argo.extract.profile import profile_file
from argo.schema import Dossier, FileProfile, Hit

INLINE_MAX_BYTES = 2048
SCRIPTS_PSEUDO_PATH = "package.json#scripts"
SECTION_TITLES: tuple[str, ...] = (
    "## 1. Install-time execution vectors",
    "## 2. Files run at install time or flagged above",
    "## 3. Suspicious patterns in",
    "## 4. File changes",
)


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


class _Writer:
    """Accumulates lines within a character budget, counting what had to be dropped."""

    def __init__(self, budget_chars: int) -> None:
        self.lines: list[str] = []
        self.used = 0
        self.budget = budget_chars
        self.omitted: dict[str, int] = {}

    def force(self, line: str) -> None:
        self.lines.append(line)
        self.used += len(line) + 1

    def add(self, line: str, section: str) -> None:
        if self.used + len(line) + 1 > self.budget:
            self.omitted[section] = self.omitted.get(section, 0) + 1
            return
        self.force(line)


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def _profile_line(p: FileProfile) -> str:
    return (
        f"profile: lines={p.lines}, avg_line_len={p.avg_line_len:.0f}, "
        f"max_line_len={p.max_line_len}, entropy={p.entropy:.2f}, "
        f"_0x_identifiers={p.hex_identifiers}, long_encoded_strings={p.long_encoded_strings}, "
        f"minified={_yes(p.minified)}, obfuscated={_yes(p.obfuscated)}, binary={_yes(p.binary)}"
    )


def build_dossier(
    sample_id: str,
    name: str,
    version: str,
    new: PackageFiles,
    old: PackageFiles | None,
    prev_version: str | None,
    budget_tokens: int = DOSSIER_TOKEN_BUDGET,
) -> Dossier:
    m_new = new.manifest()
    m_old = old.manifest() if old is not None else None
    life = lifecycle_scripts(m_new)
    life_old = lifecycle_scripts(m_old)
    life_changed = any(life_old.get(k) != v for k, v in life.items())
    changes = diff_files(new, old)
    sizes = {c.path: c.size for c in changes}
    added = [c.path for c in changes if c.status == "added"]
    touched = [c.path for c in changes if c.status != "removed"]
    deps = dep_changes(m_new, m_old)
    outside = outside_files(added, m_new)
    targets = script_targets(life, new.files)
    targets += [p for p in outside if p not in targets]
    profiles = [profile_file(p, new.files[p]) for p in targets]

    hits: list[Hit] = []
    if life:
        hits += scan_text(SCRIPTS_PSEUDO_PATH, "\n".join(f"{k}: {v}" for k, v in life.items()))
    hits += scan_package(new, touched)
    first = set(targets) | {SCRIPTS_PSEUDO_PATH}
    hits.sort(key=lambda h: (h.path not in first, CATEGORY_ORDER.index(h.category), h.path, h.line))

    w = _Writer(budget_tokens * 4)
    if old is not None:
        kind = f"update from {prev_version}"
    elif prev_version:
        kind = f"update from {prev_version} (previous version not available: no diff)"
    else:
        kind = "new package (no previous version)"
    w.force(f"PACKAGE: {name}@{version}")
    w.force(f"TYPE: {kind}")
    w.force(f"FILES: {len(new.files)} files, {fmt_size(new.total_size)} total")

    w.force("")
    w.force(SECTION_TITLES[0])
    vectors: list[str] = []
    for k, v in life.items():
        if old is None:
            tag = "new package"
        elif k not in life_old:
            tag = "NEW"
        else:
            tag = "CHANGED" if life_old[k] != v else "unchanged"
        vectors.append(f"- script {k}: {v}  [{tag}]")
    vectors += [f"- script {k} removed (was: {v})" for k, v in life_old.items() if k not in life]
    vectors += [
        f"- {d.field} {d.name}: {d.new}  [NON-REGISTRY SOURCE, previously {d.old or 'absent'}]"
        for d in deps
        if d.non_registry
    ]
    vectors += [
        f"- added file outside declared `files`: {p} ({fmt_size(sizes.get(p, 0))})" for p in outside
    ]
    for line in vectors or ["- none"]:
        w.add(line, "vectors")

    w.force("")
    w.force(SECTION_TITLES[1])
    if not profiles:
        w.add("- none", "files")
    for prof in profiles:
        head = f"### {prof.path} ({fmt_size(prof.size)})"
        if prof.size <= INLINE_MAX_BYTES and not prof.binary:
            body = new.files[prof.path].decode("utf-8", errors="replace")
            w.add(f"{head}\n```\n{body}\n```", "files")
        else:
            w.add(f"{head}\n{_profile_line(prof)}", "files")

    w.force("")
    scope = "added/modified code" if old is not None else "package code"
    w.force(f"{SECTION_TITLES[2]} {scope}")
    for line in [f"- [{h.category}] {h.path}:{h.line}  {h.snippet}" for h in hits] or ["- none"]:
        w.add(line, "patterns")

    w.force("")
    w.force(SECTION_TITLES[3] + (" vs previous version" if old is not None else " (new package)"))
    new_deps = [d.name for d in deps if d.old is None and not d.non_registry]
    if new_deps:
        more = " ..." if len(new_deps) > 10 else ""
        w.add(f"- new dependencies: {', '.join(new_deps[:10])}{more}", "changes")
    symbol = {"added": "+", "modified": "~", "removed": "-"}
    for c in changes:
        w.add(f"{symbol[c.status]} {c.path} ({fmt_size(c.size)})", "changes")

    if w.omitted:
        w.force("")
        w.force("## Notes")
        w.force("omitted for length: " + ", ".join(f"{n} {s}" for s, n in w.omitted.items()))
    text = "\n".join(w.lines)
    return Dossier(
        sample_id=sample_id,
        extractor_version=EXTRACTOR_VERSION,
        text=text,
        lifecycle=life,
        lifecycle_changed=life_changed,
        dep_changes=deps,
        outside_files=outside,
        target_profiles=profiles,
        hits=hits,
        changes=changes,
        truncated=bool(w.omitted),
        est_tokens=len(text) // 4,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_dossier.py -q`
Expected: PASS (6 tests).

- [ ] **Step 5: Gate and commit**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/extract/dossier.py tests/test_dossier.py
git commit -m "Add dossier assembly with priority-ordered token budget"
```

---

### Task 12: Baseline, dossier build for the corpus, calibration

**Files:**
- Create: `argo/extract/baseline.py`, `argo/extract/build.py`, `tests/test_baseline.py`, `tests/test_extract_build.py`
- Modify: `argo/cli.py` (add `dossier build`, `baseline calibrate`)

**Interfaces:**
- Consumes: `build_dossier` (11), `read_datadog_zip`, `read_npm_tgz`, `ArchiveError` (3), `load_corpus` (7), `Sample`, `Dossier` (1)
- Produces:
  - `WEIGHTS: dict[str, float]`, `features(d: Dossier) -> dict[str, bool]`, `score(d: Dossier) -> float`
  - `f1_at(scores: Sequence[float], labels: Sequence[bool], t: float) -> float`
  - `calibrate(scores: Sequence[float], labels: Sequence[bool]) -> float` — threshold maximising F1 (predict malicious when `score >= threshold`; ties → higher threshold)
  - `safe_name(sample_id: str) -> str`, `dossier_path(sample_id: str, dossier_dir: Path = DOSSIER_DIR) -> Path`
  - `load_package(s: Sample, data_dir: Path = DATA_DIR) -> PackageFiles`, `load_previous(s: Sample, data_dir: Path = DATA_DIR) -> PackageFiles | None`
  - `dossier_for_sample(s: Sample, data_dir: Path = DATA_DIR) -> Dossier`
  - `build_all(samples: Sequence[Sample], data_dir: Path = DATA_DIR, dossier_dir: Path = DOSSIER_DIR, log=print) -> int`
  - `load_dossier(sample_id: str, dossier_dir: Path = DOSSIER_DIR) -> Dossier`
  - `load_dossiers(samples: Sequence[Sample], dossier_dir: Path = DOSSIER_DIR) -> dict[str, Dossier]` (missing ones skipped)
  - `calibrate_baseline(samples, dossiers, out_path: Path = BASELINE_PATH) -> dict[str, Any]` → writes `{"threshold", "weights", "n_history", "f1_history"}`
  - `load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]`
  - CLI: `argo dossier build`, `argo baseline calibrate`

Dossiers contain short code snippets of malware as plain text inside JSON under `data/` (gitignored). They are reports, not executable files.

- [ ] **Step 1: Write the failing tests**

`tests/test_baseline.py`:

```python
from argo.extract.baseline import WEIGHTS, calibrate, features, score
from argo.extract.dossier import build_dossier
from tests.helpers import make_pkg, pkg_json


def test_features_and_score_for_install_payload():
    new = make_pkg({
        "package.json": pkg_json("x", "1", scripts={"postinstall": "node bundle.js"}),
        "bundle.js": ";".join(f"var _0x{i:04x}=1" for i in range(40)) + ";process.env.NPM_TOKEN",
    })
    d = build_dossier("x", "x", "1", new, make_pkg({"package.json": pkg_json("x", "0")}), "0")
    f = features(d)
    assert f["lifecycle_changed"] and f["target_obfuscated"] and f["credentials"]
    assert score(d) == sum(WEIGHTS[k] for k, on in f.items() if on)


def test_calibrate_picks_separating_threshold():
    assert calibrate([0.0, 0.5, 3.0, 6.0], [False, False, True, True]) == 3.0


def test_calibrate_prefers_higher_threshold_on_ties():
    # thresholds 4.0 and 1.0 both give F1 = 2/3
    assert calibrate([1.0, 2.0, 3.0, 4.0], [True, False, False, True]) == 4.0
```

`tests/test_extract_build.py`:

```python
from argo.extract.build import build_all, dossier_path, load_dossier, safe_name
from argo.schema import Sample
from tests.helpers import make_tgz, pkg_json


def _sample(tmp_path) -> Sample:
    make_tgz(tmp_path / "cache/a-1.0.1.tgz", {"package.json": pkg_json("@s/a", "1.0.1"), "x.js": "eval(1)"})
    make_tgz(tmp_path / "cache/a-1.0.0.tgz", {"package.json": pkg_json("@s/a", "1.0.0")})
    return Sample(
        id="@s/a@1.0.1", name="@s/a", version="1.0.1", prev_version="1.0.0", label="benign",
        subgroup="benigno_popolare", date="2025-02-01", split="test", source="npm",
        archive_path="cache/a-1.0.1.tgz", prev_archive_path="cache/a-1.0.0.tgz",
        sha256="0", fingerprint="f",
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_baseline.py tests/test_extract_build.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `argo/extract/baseline.py`**

```python
from collections.abc import Sequence

from argo.schema import Dossier

WEIGHTS: dict[str, float] = {
    "lifecycle_changed": 2.0,
    "non_registry_dep": 3.0,
    "outside_files": 1.5,
    "target_obfuscated": 3.0,
    "runtime_download": 2.0,
    "propagation": 2.0,
    "credentials": 1.5,
    "exec": 1.0,
    "obfuscation": 1.0,
    "network": 0.5,
}


def features(d: Dossier) -> dict[str, bool]:
    categories = {h.category for h in d.hits}
    return {
        "lifecycle_changed": d.lifecycle_changed,
        "non_registry_dep": any(c.non_registry for c in d.dep_changes),
        "outside_files": bool(d.outside_files),
        "target_obfuscated": any(p.obfuscated for p in d.target_profiles),
        **{c: c in categories for c in
           ("runtime_download", "propagation", "credentials", "exec", "obfuscation", "network")},
    }


def score(d: Dossier) -> float:
    return sum(WEIGHTS[k] for k, on in features(d).items() if on)


def f1_at(scores: Sequence[float], labels: Sequence[bool], t: float) -> float:
    tp = sum(s >= t and y for s, y in zip(scores, labels, strict=True))
    fp = sum(s >= t and not y for s, y in zip(scores, labels, strict=True))
    fn = sum(s < t and y for s, y in zip(scores, labels, strict=True))
    return 0.0 if tp == 0 else 2 * tp / (2 * tp + fp + fn)


def calibrate(scores: Sequence[float], labels: Sequence[bool]) -> float:
    candidates = sorted(set(scores), reverse=True)  # higher first → wins ties
    return max(candidates, key=lambda t: f1_at(scores, labels, t))
```

Note: `max` returns the first maximal element, and candidates are sorted descending, so ties go to the higher threshold.

- [ ] **Step 4: Implement `argo/extract/build.py`**

```python
import json
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from argo.config import BASELINE_PATH, DATA_DIR, DOSSIER_DIR, EXTRACTOR_VERSION
from argo.extract.archive import ArchiveError, PackageFiles, read_datadog_zip, read_npm_tgz
from argo.extract.baseline import WEIGHTS, calibrate, f1_at, score
from argo.extract.dossier import build_dossier
from argo.schema import Dossier, Sample


def safe_name(sample_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", sample_id)


def dossier_path(sample_id: str, dossier_dir: Path = DOSSIER_DIR) -> Path:
    return dossier_dir / f"{safe_name(sample_id)}.json"


def load_package(s: Sample, data_dir: Path = DATA_DIR) -> PackageFiles:
    path = data_dir / s.archive_path
    if s.source == "datadog":
        return read_datadog_zip(path)[0]
    return read_npm_tgz(path.read_bytes())


def load_previous(s: Sample, data_dir: Path = DATA_DIR) -> PackageFiles | None:
    if not s.prev_archive_path:
        return None
    return read_npm_tgz((data_dir / s.prev_archive_path).read_bytes())


def dossier_for_sample(s: Sample, data_dir: Path = DATA_DIR) -> Dossier:
    return build_dossier(
        s.id, s.name, s.version, load_package(s, data_dir), load_previous(s, data_dir),
        s.prev_version,
    )


def build_all(
    samples: Sequence[Sample],
    data_dir: Path = DATA_DIR,
    dossier_dir: Path = DOSSIER_DIR,
    log: Callable[[str], None] = print,
) -> int:
    dossier_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for s in samples:
        out = dossier_path(s.id, dossier_dir)
        if out.exists() and json.loads(out.read_text()).get("extractor_version") == EXTRACTOR_VERSION:
            continue
        try:
            d = dossier_for_sample(s, data_dir)
        except (ArchiveError, OSError) as e:
            log(f"skip {s.id}: {e}")
            continue
        out.write_text(d.model_dump_json())
        written += 1
        log(f"dossier {s.id}: {d.est_tokens} tokens{' (truncated)' if d.truncated else ''}")
    return written


def load_dossier(sample_id: str, dossier_dir: Path = DOSSIER_DIR) -> Dossier:
    return Dossier.model_validate_json(dossier_path(sample_id, dossier_dir).read_text())


def load_dossiers(samples: Sequence[Sample], dossier_dir: Path = DOSSIER_DIR) -> dict[str, Dossier]:
    return {
        s.id: load_dossier(s.id, dossier_dir)
        for s in samples
        if dossier_path(s.id, dossier_dir).exists()
    }


def calibrate_baseline(
    samples: Sequence[Sample], dossiers: dict[str, Dossier], out_path: Path = BASELINE_PATH
) -> dict[str, Any]:
    hist = [s for s in samples if s.split == "history" and s.id in dossiers]
    scores = [score(dossiers[s.id]) for s in hist]
    labels = [s.label == "malicious" for s in hist]
    threshold = calibrate(scores, labels)
    result = {
        "threshold": threshold,
        "weights": WEIGHTS,
        "n_history": len(hist),
        "f1_history": round(f1_at(scores, labels, threshold), 4),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    return result


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text())
    return data
```


- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_baseline.py tests/test_extract_build.py -q`
Expected: PASS (6 tests).

- [ ] **Step 6: Add CLI commands in `argo/cli.py`**

Inside `build_parser()`:

```python
    dos = sub.add_parser("dossier", help="dossier commands")
    dos_sub = dos.add_subparsers(dest="dossier_command", required=True)
    dos_sub.add_parser("build", help="build a dossier for every corpus sample").set_defaults(
        func=_dossier_build
    )
    bl = sub.add_parser("baseline", help="rule-based baseline")
    bl_sub = bl.add_subparsers(dest="baseline_command", required=True)
    bl_sub.add_parser("calibrate", help="choose the threshold on history").set_defaults(
        func=_baseline_calibrate
    )
```

Handlers:

```python
def _dossier_build(_: argparse.Namespace) -> int:
    from argo.dataset.build import load_corpus
    from argo.extract.build import build_all

    print(f"{build_all(load_corpus())} dossiers written")
    return 0


def _baseline_calibrate(_: argparse.Namespace) -> int:
    from argo.dataset.build import load_corpus
    from argo.extract.build import calibrate_baseline, load_dossiers

    corpus = load_corpus()
    print(calibrate_baseline(corpus, load_dossiers(corpus)))
    return 0
```

- [ ] **Step 7: Gate and commit the code**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/extract tests/test_baseline.py tests/test_extract_build.py argo/cli.py
git commit -m "Add rule baseline, corpus dossier build and calibration"
```

- [ ] **Step 8: Build dossiers and calibrate on the real corpus**

```bash
.venv/bin/argo dossier build | tail -5
.venv/bin/argo baseline calibrate
```

Expected: one dossier per sample (skips are logged and must be ≤ 3; otherwise stop and report), then a dict with `threshold`, `n_history` ≈ 60, `f1_history`.

- [ ] **Step 9: Eyeball check (required — this is the input every model sees)**

```bash
.venv/bin/python - <<'EOF'
from argo.dataset.build import load_corpus
from argo.extract.build import load_dossiers
c = load_corpus(); d = load_dossiers(c)
for sub in ("shai_hulud_w1", "shai_hulud_w2", "shai_hulud_w3", "benigno_difficile"):
    s = next(s for s in c if s.subgroup == sub and s.split == "test")
    print("=" * 30, sub, s.id); print(d[s.id].text[:2500])
import statistics
print("median tokens", statistics.median(x.est_tokens for x in d.values()),
      "truncated", sum(x.truncated for x in d.values()), "/", len(d))
EOF
```

Expected: W1 shows `postinstall: node bundle.js [NEW]` and an obfuscated `bundle.js` profile; W2 shows `preinstall: node setup_bun.js [NEW]` with `setup_bun.js` inlined; W3 shows either the `NON-REGISTRY SOURCE` line (TanStack) or `preinstall: bun run index.js` (AntV); the hard benign shows its install script as `[unchanged]`. If any of these is missing, the extractor has a bug: fix it (with a regression test) before M3.

- [ ] **Step 10: Commit the baseline threshold**

```bash
git add results/baseline.json
git commit -m "Calibrate rule baseline on history set"
```
