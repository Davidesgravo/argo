# Argo — M1 Dataset, part A (Tasks 3-5)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Read the index `2026-09-11-argo-plan.md` (Global Constraints, verified facts) first. Part B is `2026-09-11-argo-m1-dataset-b.md`.

---

### Task 3: In-memory package readers

**Files:**
- Create: `argo/extract/__init__.py` (empty), `argo/extract/archive.py`, `tests/helpers.py`, `tests/test_archive.py`

**Interfaces:**
- Produces:
  - `LIFECYCLE_SCRIPTS: tuple[str, ...] = ("preinstall", "install", "postinstall", "prepare")`
  - `INSTALL_SCRIPTS: tuple[str, ...] = ("preinstall", "install", "postinstall")`
  - `@dataclass(frozen=True) class PackageFiles: files: dict[str, bytes]` with `text(path) -> str`, `total_size -> int` (property), `manifest() -> dict[str, Any]` (parsed `package.json`, `{}` if missing/invalid)
  - `class ArchiveError(Exception)`
  - `read_datadog_zip(path: Path, password: bytes = DATADOG_ZIP_PASSWORD) -> tuple[PackageFiles, dict[str, Any]]` (files, package_info)
  - `read_npm_tgz(data: bytes) -> PackageFiles`
  - test helpers `make_pkg`, `pkg_json`, `make_tgz`, `make_datadog_zip`

- [ ] **Step 1: Write test helpers `tests/helpers.py`**

```python
import io
import json
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from argo.extract.archive import PackageFiles


def _b(content: str | bytes) -> bytes:
    return content.encode() if isinstance(content, str) else content


def make_pkg(files: dict[str, str | bytes]) -> PackageFiles:
    return PackageFiles({k: _b(v) for k, v in files.items()})


def pkg_json(name: str = "demo", version: str = "1.0.0", **fields: Any) -> str:
    return json.dumps({"name": name, "version": version, **fields})


def make_tgz(path: Path, files: dict[str, str | bytes], top: str = "package") -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel, content in files.items():
            data = _b(content)
            info = tarfile.TarInfo(f"{top}/{rel}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())
    return path


def make_datadog_zip(
    path: Path,
    files: dict[str, str | bytes],
    info: dict[str, Any],
    pkgdir: str = "demo",
    password: str | None = "infected",
) -> Path:
    """Fake DataDog sample: tmp/tmpabc/<pkgdir>/package/<files> + package_info json."""
    prefix = f"tmp/tmpabc/{pkgdir}"
    entries = {f"{prefix}/package/{rel}": _b(c) for rel, c in files.items()}
    entries[f"{prefix}/package_info-{pkgdir}.json"] = json.dumps(info).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    if password is None:
        with zipfile.ZipFile(path, "w") as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return path
    zip_cli = shutil.which("zip")
    if zip_cli is None:
        pytest.skip("zip CLI not available for encrypted fixtures")
    stage = path.parent / f"stage-{path.stem}"
    for name, data in entries.items():
        p = stage / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    subprocess.run(
        [zip_cli, "-q", "-r", "-P", password, str(path.resolve()), "tmp"], cwd=stage, check=True
    )
    shutil.rmtree(stage)
    return path
```

- [ ] **Step 2: Write the failing tests `tests/test_archive.py`**

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_archive.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'argo.extract'`.

- [ ] **Step 4: Implement `argo/extract/archive.py`** (and empty `argo/extract/__init__.py`)

```python
import io
import json
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from argo.config import DATADOG_ZIP_PASSWORD

LIFECYCLE_SCRIPTS: tuple[str, ...] = ("preinstall", "install", "postinstall", "prepare")
INSTALL_SCRIPTS: tuple[str, ...] = ("preinstall", "install", "postinstall")
MAX_FILE_BYTES = 64 * 1024 * 1024


class ArchiveError(Exception):
    pass


@dataclass(frozen=True)
class PackageFiles:
    files: dict[str, bytes]

    def text(self, path: str) -> str:
        return self.files[path].decode("utf-8", errors="replace")

    @property
    def total_size(self) -> int:
        return sum(len(b) for b in self.files.values())

    def manifest(self) -> dict[str, Any]:
        raw = self.files.get("package.json")
        if raw is None:
            return {}
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}


def _package_rel(name: str) -> str | None:
    if name.startswith("package/"):
        return name[len("package/") :]
    marker = name.find("/package/")
    return name[marker + len("/package/") :] if marker >= 0 else None


def read_datadog_zip(
    path: Path, password: bytes = DATADOG_ZIP_PASSWORD
) -> tuple[PackageFiles, dict[str, Any]]:
    """Read a DataDog sample fully in memory. Nothing is written to disk."""
    files: dict[str, bytes] = {}
    info: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(path) as zf:
            for zi in zf.infolist():
                if zi.is_dir() or zi.file_size > MAX_FILE_BYTES:
                    continue
                rel = _package_rel(zi.filename)
                if rel:
                    files[rel] = zf.read(zi, pwd=password)
                elif zi.filename.rsplit("/", 1)[-1].startswith("package_info-"):
                    loaded = json.loads(zf.read(zi, pwd=password))
                    info = loaded if isinstance(loaded, dict) else {}
    except (zipfile.BadZipFile, RuntimeError, json.JSONDecodeError, OSError) as e:
        raise ArchiveError(f"{path}: {e}") from e
    if "package.json" not in files:
        raise ArchiveError(f"{path}: no package/package.json")
    return PackageFiles(files), info


def read_npm_tgz(data: bytes) -> PackageFiles:
    """Read an npm tarball in memory; the first path component is stripped."""
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for m in tf.getmembers():
                if not m.isfile() or m.size > MAX_FILE_BYTES:
                    continue
                parts = m.name.split("/", 1)
                rel = parts[1] if len(parts) == 2 else parts[0]
                f = tf.extractfile(m)
                if f is not None:
                    files[rel] = f.read()
    except (tarfile.TarError, OSError, EOFError) as e:
        raise ArchiveError(f"invalid tarball: {e}") from e
    if "package.json" not in files:
        raise ArchiveError("no package.json in tarball")
    return PackageFiles(files)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_archive.py -q`
Expected: PASS (7 tests; the encrypted one is skipped only if `zip` is missing — on macOS it exists).

- [ ] **Step 6: Gate and commit**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/extract tests/helpers.py tests/test_archive.py
git commit -m "Add in-memory readers for DataDog zips and npm tarballs"
```

---

### Task 4: DataDog dataset access

**Files:**
- Create: `argo/dataset/__init__.py` (empty), `argo/dataset/datadog.py`, `tests/test_datadog.py`

**Interfaces:**
- Consumes: `argo.config.DATADOG_GIT_URL`, `DATADOG_RAW_URL`
- Produces:
  - `@dataclass(frozen=True) class SamplePath: category: str; name: str; version: str; date: str; repo_path: str` + property `id -> str` (`"name@version"`)
  - `package_name_from_dir(d: str) -> str`
  - `parse_sample_path(p: str) -> SamplePath | None`
  - `ensure_repo(repo_dir: Path) -> str` (clones if missing, returns HEAD commit sha)
  - `list_sample_paths(repo_dir: Path) -> list[SamplePath]`
  - `raw_url(repo_path: str) -> str`
  - `download_sample(sp: SamplePath, quarantine_dir: Path, client: httpx.Client) -> Path`
  - `load_manifest(client: httpx.Client, cache_dir: Path) -> dict[str, list[str] | None]`

- [ ] **Step 1: Write the failing tests `tests/test_datadog.py`**

```python
import subprocess

import httpx

from argo.dataset.datadog import (
    SamplePath,
    download_sample,
    list_sample_paths,
    package_name_from_dir,
    parse_sample_path,
    raw_url,
)

SCOPED = "samples/npm/compromised_lib/@ctrl@tinycolor/4.1.1/2025-09-15-@ctrl_tinycolor-v4.1.1.zip"


def test_package_name_from_dir():
    assert package_name_from_dir("@ctrl@tinycolor") == "@ctrl/tinycolor"
    assert package_name_from_dir("02-echo") == "02-echo"


def test_parse_sample_path():
    sp = parse_sample_path(SCOPED)
    assert sp == SamplePath("compromised_lib", "@ctrl/tinycolor", "4.1.1", "2025-09-15", SCOPED)
    assert sp.id == "@ctrl/tinycolor@4.1.1"
    assert parse_sample_path("samples/npm/manifest.json") is None
    assert parse_sample_path("samples/pypi/malicious_intent/x/1.0/2025-01-01-x.zip") is None


def test_raw_url_quotes_at_sign():
    assert "%40ctrl%40tinycolor" in raw_url(SCOPED)


def test_download_is_cached(tmp_path):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=b"zipbytes")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sp = parse_sample_path(SCOPED)
    assert sp is not None
    p1 = download_sample(sp, tmp_path, client)
    p2 = download_sample(sp, tmp_path, client)
    assert p1 == p2 and p1.read_bytes() == b"zipbytes" and len(calls) == 1


def test_list_sample_paths_from_git(tmp_path):
    repo = tmp_path / "repo"
    f = repo / "samples/npm/malicious_intent/evil/1.0.0/2025-02-01-evil-v1.0.0.zip"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"x")
    (repo / "samples/npm/manifest.json").write_text("{}")
    git = ["git", "-C", str(repo)]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run(
        [*git, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x"], check=True
    )
    paths = list_sample_paths(repo)
    assert [p.id for p in paths] == ["evil@1.0.0"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_datadog.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'argo.dataset'`.

- [ ] **Step 3: Implement `argo/dataset/datadog.py`**

```python
import json
import re
import subprocess
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import httpx

from argo.config import DATADOG_GIT_URL, DATADOG_RAW_URL

_PATH_RE = re.compile(
    r"^samples/npm/(malicious_intent|compromised_lib)/([^/]+)/([^/]+)/"
    r"(\d{4}-\d{2}-\d{2})-[^/]+\.zip$"
)


@dataclass(frozen=True)
class SamplePath:
    category: str  # "malicious_intent" | "compromised_lib"
    name: str
    version: str
    date: str  # discovery date, YYYY-MM-DD
    repo_path: str

    @property
    def id(self) -> str:
        return f"{self.name}@{self.version}"


def package_name_from_dir(d: str) -> str:
    if d.startswith("@") and "@" in d[1:]:
        scope, rest = d[1:].split("@", 1)
        return f"@{scope}/{rest}"
    return d


def parse_sample_path(p: str) -> SamplePath | None:
    m = _PATH_RE.match(p)
    if not m:
        return None
    category, d, version, date = m.groups()
    return SamplePath(category, package_name_from_dir(d), version, date, p)


def ensure_repo(repo_dir: Path) -> str:
    """Blob-less, no-checkout clone: only trees are fetched, sample zips are not."""
    if not (repo_dir / ".git").exists():
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", "--depth", "1",
             DATADOG_GIT_URL, str(repo_dir)],
            check=True,
        )
    out = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    return out.stdout.strip()


def list_sample_paths(repo_dir: Path) -> list[SamplePath]:
    out = subprocess.run(
        ["git", "-C", str(repo_dir), "ls-tree", "-r", "--name-only", "HEAD", "--", "samples/npm"],
        check=True, capture_output=True, text=True,
    ).stdout
    return [sp for line in out.splitlines() if (sp := parse_sample_path(line)) is not None]


def raw_url(repo_path: str) -> str:
    return f"{DATADOG_RAW_URL}/{urllib.parse.quote(repo_path)}"


def download_sample(sp: SamplePath, quarantine_dir: Path, client: httpx.Client) -> Path:
    """Download the still-encrypted zip into quarantine (cached)."""
    dest = quarantine_dir / sp.repo_path.removeprefix("samples/npm/")
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = client.get(raw_url(sp.repo_path))
    r.raise_for_status()
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(r.content)
    tmp.replace(dest)
    return dest


def load_manifest(client: httpx.Client, cache_dir: Path) -> dict[str, list[str] | None]:
    dest = cache_dir / "datadog-npm-manifest.json"
    if not dest.exists():
        r = client.get(f"{DATADOG_RAW_URL}/samples/npm/manifest.json")
        r.raise_for_status()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(r.content)
    data: dict[str, list[str] | None] = json.loads(dest.read_text())
    return data
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_datadog.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Gate and commit**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/dataset tests/test_datadog.py
git commit -m "Add DataDog dataset listing and download"
```

---

### Task 5: npm registry access and version logic

**Files:**
- Create: `argo/dataset/registry.py`, `tests/test_registry.py`

**Interfaces:**
- Consumes: `argo.config.NPM_REGISTRY_URL`
- Produces:
  - `class RegistryError(Exception)`
  - `class Registry(cache_dir: Path, client: httpx.Client, base_url: str = NPM_REGISTRY_URL)` with `packument(name: str) -> dict[str, Any]` and `tarball(name: str, version: str) -> Path` (both cached on disk under `cache_dir/packuments/` and `cache_dir/tarballs/`)
  - `class RegistryLike(Protocol)` with the same two methods (used by the corpus builder and its fakes)
  - `previous_version(time_map: dict[str, str], version: str, exclude: Iterable[str] = ()) -> str | None` — latest stable version published strictly before `version`, skipping `exclude`
  - `versions_in_window(time_map: dict[str, str], start: str, end: str) -> list[str]` — stable versions with publish date in `[start, end]`, oldest first

- [ ] **Step 1: Write the failing tests `tests/test_registry.py`**

```python
import httpx
import pytest

from argo.dataset.registry import Registry, RegistryError, previous_version, versions_in_window

TIME = {
    "created": "2020-01-01T00:00:00Z",
    "modified": "2025-09-16T00:00:00Z",
    "1.0.0": "2024-06-01T00:00:00Z",
    "1.1.0-beta.1": "2025-01-10T00:00:00Z",
    "1.1.0": "2025-02-01T00:00:00Z",
    "1.1.1": "2025-09-15T00:00:00Z",
    "1.1.2": "2025-09-15T01:00:00Z",
}


def test_previous_version_basic_and_prerelease_skipped():
    assert previous_version(TIME, "1.1.0") == "1.0.0"


def test_previous_version_excludes_malicious():
    assert previous_version(TIME, "1.1.2", exclude=["1.1.1"]) == "1.1.0"


def test_previous_version_none():
    assert previous_version(TIME, "1.0.0") is None
    assert previous_version(TIME, "9.9.9") is None


def test_versions_in_window():
    assert versions_in_window(TIME, "2025-01-01", "2025-12-31") == ["1.1.0", "1.1.1", "1.1.2"]


def _client(routes: dict[str, bytes]) -> tuple[httpx.Client, list[str]]:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        if url in routes:
            return httpx.Response(200, content=routes[url])
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_registry_caches_packument_and_tarball(tmp_path):
    doc = b'{"versions": {"1.0.0": {"dist": {"tarball": "https://r/t/a-1.0.0.tgz"}}}}'
    client, calls = _client(
        {"https://r/@s%2Fa": doc, "https://r/t/a-1.0.0.tgz": b"tgz"}
    )
    reg = Registry(tmp_path, client, base_url="https://r")
    assert reg.tarball("@s/a", "1.0.0").read_bytes() == b"tgz"
    reg.tarball("@s/a", "1.0.0")
    reg.packument("@s/a")
    assert len(calls) == 2


def test_registry_missing_version_raises(tmp_path):
    client, _ = _client({"https://r/a": b'{"versions": {}}'})
    with pytest.raises(RegistryError):
        Registry(tmp_path, client, base_url="https://r").tarball("a", "1.0.0")


def test_registry_missing_package_raises(tmp_path):
    client, _ = _client({})
    with pytest.raises(RegistryError):
        Registry(tmp_path, client, base_url="https://r").packument("nope")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_registry.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'argo.dataset.registry'`.

- [ ] **Step 3: Implement `argo/dataset/registry.py`**

```python
import json
import urllib.parse
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol

import httpx

from argo.config import NPM_REGISTRY_URL

_META_KEYS = {"created", "modified"}


class RegistryError(Exception):
    pass


class RegistryLike(Protocol):
    def packument(self, name: str) -> dict[str, Any]: ...

    def tarball(self, name: str, version: str) -> Path: ...


def _safe(name: str) -> str:
    return urllib.parse.quote(name, safe="")


class Registry:
    def __init__(
        self, cache_dir: Path, client: httpx.Client, base_url: str = NPM_REGISTRY_URL
    ) -> None:
        self.cache_dir = cache_dir
        self.client = client
        self.base_url = base_url.rstrip("/")

    def packument(self, name: str) -> dict[str, Any]:
        dest = self.cache_dir / "packuments" / f"{_safe(name)}.json"
        if dest.exists():
            cached: dict[str, Any] = json.loads(dest.read_text())
            return cached
        r = self.client.get(f"{self.base_url}/{urllib.parse.quote(name, safe='@')}")
        if r.status_code == 404:
            raise RegistryError(f"{name}: not found on registry")
        r.raise_for_status()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(r.content)
        doc: dict[str, Any] = r.json()
        return doc

    def tarball(self, name: str, version: str) -> Path:
        dest = self.cache_dir / "tarballs" / f"{_safe(name)}-{version}.tgz"
        if dest.exists():
            return dest
        meta = self.packument(name).get("versions", {}).get(version)
        if not meta:
            raise RegistryError(f"{name}@{version}: version not on registry")
        r = self.client.get(meta["dist"]["tarball"])
        if r.status_code == 404:
            raise RegistryError(f"{name}@{version}: tarball not found")
        r.raise_for_status()
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        tmp.write_bytes(r.content)
        tmp.replace(dest)
        return dest


def _stable_versions(time_map: dict[str, str]) -> list[tuple[str, str]]:
    return sorted(
        (ts, v) for v, ts in time_map.items() if v not in _META_KEYS and "-" not in v
    )


def previous_version(
    time_map: dict[str, str], version: str, exclude: Iterable[str] = ()
) -> str | None:
    t = time_map.get(version)
    if t is None:
        return None
    skip = set(exclude) | {version}
    earlier = [v for ts, v in _stable_versions(time_map) if ts < t and v not in skip]
    return earlier[-1] if earlier else None


def versions_in_window(time_map: dict[str, str], start: str, end: str) -> list[str]:
    return [v for ts, v in _stable_versions(time_map) if start <= ts[:10] <= end]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_registry.py -q`
Expected: PASS (7 tests).

- [ ] **Step 5: Gate and commit**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/dataset/registry.py tests/test_registry.py
git commit -m "Add npm registry client and previous-version logic"
```
