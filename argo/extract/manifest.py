import fnmatch
import re
from collections.abc import Iterable
from typing import Any

from argo.extract.archive import LIFECYCLE_SCRIPTS
from argo.schema import DepChange

DEP_FIELDS = ("dependencies", "optionalDependencies")
_NON_REGISTRY_PREFIXES = (
    "github:",
    "gitlab:",
    "bitbucket:",
    "git+",
    "git:",
    "git@",
    "http://",
    "https://",
    "file:",
    "link:",
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
        changes.append(
            DepChange(
                field=field, name=name, old=before, new=spec, non_registry=is_non_registry(spec)
            )
        )
    return changes


def _clean_pattern(p: str) -> str:
    return p.strip().removeprefix("./").removeprefix("/").rstrip("/")


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
    # Negated patterns ("!...") only exclude; they are never used as inclusion
    # patterns (full negation semantics are out of scope).
    patterns = [_clean_pattern(str(f)) for f in files if not str(f).strip().startswith("!")]
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
