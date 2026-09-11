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
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--depth",
                "1",
                DATADOG_GIT_URL,
                str(repo_dir),
            ],
            check=True,
        )
    out = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def list_sample_paths(repo_dir: Path) -> list[SamplePath]:
    out = subprocess.run(
        ["git", "-C", str(repo_dir), "ls-tree", "-r", "--name-only", "HEAD", "--", "samples/npm"],
        check=True,
        capture_output=True,
        text=True,
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
