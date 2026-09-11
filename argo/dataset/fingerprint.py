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
    for part in (name, version):
        if part:
            scripts = scripts.replace(part, "")
    h = hashlib.sha256()
    h.update("\n".join(sorted(digests)).encode())
    h.update(scripts.encode())
    return h.hexdigest()
