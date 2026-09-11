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
