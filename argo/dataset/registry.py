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
    return sorted((ts, v) for v, ts in time_map.items() if v not in _META_KEYS and "-" not in v)


def _parse_semver(v: str) -> tuple[int, int, int] | None:
    """Parse a strict major.minor.patch version; anything else is unparsable."""
    parts = v.split(".")
    if len(parts) != 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def previous_version(
    time_map: dict[str, str], version: str, exclude: Iterable[str] = ()
) -> str | None:
    """Highest stable version strictly lower than `version` by numeric semver that was
    also published before it. A different, numerically HIGHER release line published
    in between (e.g. a 7.x backport released after 8.x) must never be picked just
    because it is the most recent by publish time."""
    t = time_map.get(version)
    target = _parse_semver(version)
    if t is None or target is None:
        return None
    skip = set(exclude) | {version}
    candidates: list[tuple[tuple[int, int, int], str]] = []
    for ts, v in _stable_versions(time_map):
        if v in skip or ts >= t:
            continue
        parsed = _parse_semver(v)
        if parsed is None or parsed >= target:
            continue
        candidates.append((parsed, v))
    if not candidates:
        return None
    return max(candidates)[1]


def versions_in_window(time_map: dict[str, str], start: str, end: str) -> list[str]:
    return [v for ts, v in _stable_versions(time_map) if start <= ts[:10] <= end]
