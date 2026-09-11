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
