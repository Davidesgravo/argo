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
