import re
from dataclasses import dataclass

from argo.dataset.registry import RegistryError, RegistryLike, previous_version
from argo.extract.archive import PackageFiles, read_npm_tgz
from argo.extract.baseline import score
from argo.extract.dossier import build_dossier
from argo.schema import Dossier

_SPEC = re.compile(r"^(@[^/@\s]+/[^@\s/]+|[^@\s/]+)(?:@([^@\s]+))?$")


def parse_spec(spec: str) -> tuple[str, str | None]:
    m = _SPEC.match(spec.strip())
    if not m:
        raise ValueError(f"Specifica non valida: {spec!r}. Usa `nome` oppure `nome@versione`.")
    return m.group(1), m.group(2)


@dataclass(frozen=True)
class Fetched:
    name: str
    version: str
    prev_version: str | None
    new: PackageFiles
    old: PackageFiles | None


def fetch_from_registry(spec: str, registry: RegistryLike) -> Fetched:
    name, version = parse_spec(spec)
    doc = registry.packument(name)
    version = version or (doc.get("dist-tags") or {}).get("latest")
    if not version:
        raise RegistryError(f"{name}: nessuna versione 'latest' sul registry")
    prev = previous_version(doc.get("time") or {}, version)
    new = read_npm_tgz(registry.tarball(name, version).read_bytes())
    old = read_npm_tgz(registry.tarball(name, prev).read_bytes()) if prev else None
    return Fetched(name, version, prev, new, old)


def from_upload(data: bytes, prev_data: bytes | None) -> Fetched:
    new = read_npm_tgz(data)
    old = read_npm_tgz(prev_data) if prev_data else None
    m = new.manifest()
    prev = str(old.manifest().get("version", "?")) if old is not None else None
    return Fetched(str(m.get("name", "upload")), str(m.get("version", "0.0.0")), prev, new, old)


def analyze(f: Fetched, threshold: float | None) -> tuple[Dossier, float, bool | None]:
    d = build_dossier(f"{f.name}@{f.version}", f.name, f.version, f.new, f.old, f.prev_version)
    s = score(d)
    return d, s, (s >= threshold if threshold is not None else None)
