from argo.config import DOSSIER_TOKEN_BUDGET, EXTRACTOR_VERSION
from argo.extract.archive import PackageFiles
from argo.extract.diff import diff_files
from argo.extract.indicators import CATEGORY_ORDER, scan_package, scan_text
from argo.extract.manifest import dep_changes, lifecycle_scripts, outside_files, script_targets
from argo.extract.profile import profile_file
from argo.schema import Dossier, FileProfile, Hit

INLINE_MAX_BYTES = 2048
MAX_OUTSIDE_FILES_SHOWN = 10
SCRIPTS_PSEUDO_PATH = "package.json#scripts"
SECTION_TITLES: tuple[str, ...] = (
    "## 1. Install-time execution vectors",
    "## 2. Files run at install time or flagged above",
    "## 3. Suspicious patterns in",
    "## 4. File changes",
)


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


class _Writer:
    """Accumulates lines within a character budget, counting what had to be dropped."""

    def __init__(self, budget_chars: int) -> None:
        self.lines: list[str] = []
        self.used = 0
        self.budget = budget_chars
        self.omitted: dict[str, int] = {}

    def force(self, line: str) -> None:
        self.lines.append(line)
        self.used += len(line) + 1

    def add(self, line: str, section: str) -> None:
        if self.used + len(line) + 1 > self.budget:
            self.omitted[section] = self.omitted.get(section, 0) + 1
            return
        self.force(line)

    def finish_section(self, section: str) -> None:
        """Call after a section's content is written. If lines were dropped for
        budget reasons, force an in-section marker so the section never reads as
        genuinely empty ("- none") when it actually had content that got cut."""
        n = self.omitted.get(section, 0)
        if n:
            self.force(f"- ({n} more lines omitted for length)")


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def _profile_line(p: FileProfile) -> str:
    return (
        f"profile: lines={p.lines}, avg_line_len={p.avg_line_len:.0f}, "
        f"max_line_len={p.max_line_len}, entropy={p.entropy:.2f}, "
        f"_0x_identifiers={p.hex_identifiers}, long_encoded_strings={p.long_encoded_strings}, "
        f"minified={_yes(p.minified)}, obfuscated={_yes(p.obfuscated)}, binary={_yes(p.binary)}"
    )


def build_dossier(
    sample_id: str,
    name: str,
    version: str,
    new: PackageFiles,
    old: PackageFiles | None,
    prev_version: str | None,
    budget_tokens: int = DOSSIER_TOKEN_BUDGET,
) -> Dossier:
    m_new = new.manifest()
    m_old = old.manifest() if old is not None else None
    life = lifecycle_scripts(m_new)
    life_old = lifecycle_scripts(m_old)
    life_changed = any(life_old.get(k) != v for k, v in life.items())
    changes = diff_files(new, old)
    sizes = {c.path: c.size for c in changes}
    added = [c.path for c in changes if c.status == "added"]
    touched = [c.path for c in changes if c.status != "removed"]
    deps = dep_changes(m_new, m_old)
    outside = outside_files(added, m_new)
    # Only the 10 largest outside-declared-`files` are treated as suspicious enough to
    # profile/prioritize; with hundreds of incidental outside files (e.g. W2-like
    # payloads), including all of them would drown the real signal (see MAX_OUTSIDE_
    # FILES_SHOWN). Dossier.outside_files below still keeps the full, uncapped list.
    outside_by_size = sorted(outside, key=lambda p: sizes.get(p, 0), reverse=True)
    shown_outside = outside_by_size[:MAX_OUTSIDE_FILES_SHOWN]
    targets = script_targets(life, new.files)
    targets += [p for p in shown_outside if p not in targets]
    profiles = [profile_file(p, new.files[p]) for p in targets]

    hits: list[Hit] = []
    if life:
        hits += scan_text(SCRIPTS_PSEUDO_PATH, "\n".join(f"{k}: {v}" for k, v in life.items()))
    hits += scan_package(new, touched)
    first = set(targets) | {SCRIPTS_PSEUDO_PATH}
    hits.sort(key=lambda h: (h.path not in first, CATEGORY_ORDER.index(h.category), h.path, h.line))
    seen_hits: set[tuple[str, str, int]] = set()
    deduped_hits: list[Hit] = []
    for h in hits:
        key = (h.category, h.path, h.line)
        if key in seen_hits:
            continue
        seen_hits.add(key)
        deduped_hits.append(h)
    hits = deduped_hits

    w = _Writer(budget_tokens * 4)
    if old is not None:
        kind = f"update from {prev_version}"
    elif prev_version:
        kind = f"update from {prev_version} (previous version not available: no diff)"
    else:
        kind = "new package (no previous version)"
    w.force(f"PACKAGE: {name}@{version}")
    w.force(f"TYPE: {kind}")
    w.force(f"FILES: {len(new.files)} files, {fmt_size(new.total_size)} total")

    w.force("")
    w.force(SECTION_TITLES[0])
    vectors: list[str] = []
    for k, v in life.items():
        if old is None:
            tag = "new package"
        elif k not in life_old:
            tag = "NEW"
        else:
            tag = "CHANGED" if life_old[k] != v else "unchanged"
        vectors.append(f"- script {k}: {v}  [{tag}]")
    vectors += [f"- script {k} removed (was: {v})" for k, v in life_old.items() if k not in life]
    vectors += [
        f"- {d.field} {d.name}: {d.new}  [NON-REGISTRY SOURCE, previously {d.old or 'absent'}]"
        for d in deps
        if d.non_registry
    ]
    vectors += [
        f"- added file outside declared `files`: {p} ({fmt_size(sizes.get(p, 0))})"
        for p in shown_outside
    ]
    if len(outside_by_size) > MAX_OUTSIDE_FILES_SHOWN:
        extra = len(outside_by_size) - MAX_OUTSIDE_FILES_SHOWN
        vectors.append(f"- … and {extra} more files outside declared `files`")
    for line in vectors or ["- none"]:
        w.add(line, "vectors")
    w.finish_section("vectors")

    w.force("")
    w.force(SECTION_TITLES[1])
    if not profiles:
        w.add("- none", "files")
    for prof in profiles:
        head = f"### {prof.path} ({fmt_size(prof.size)})"
        if prof.size <= INLINE_MAX_BYTES and not prof.binary:
            body = new.files[prof.path].decode("utf-8", errors="replace")
            w.add(f"{head}\n```\n{body}\n```", "files")
        else:
            w.add(f"{head}\n{_profile_line(prof)}", "files")
    w.finish_section("files")

    w.force("")
    scope = "added/modified code" if old is not None else "package code"
    w.force(f"{SECTION_TITLES[2]} {scope}")
    for line in [f"- [{h.category}] {h.path}:{h.line}  {h.snippet}" for h in hits] or ["- none"]:
        w.add(line, "patterns")
    w.finish_section("patterns")

    w.force("")
    w.force(SECTION_TITLES[3] + (" vs previous version" if old is not None else " (new package)"))
    new_deps = [d.name for d in deps if d.old is None and not d.non_registry]
    if new_deps:
        more = " ..." if len(new_deps) > 10 else ""
        w.add(f"- new dependencies: {', '.join(new_deps[:10])}{more}", "changes")
    symbol = {"added": "+", "modified": "~", "removed": "-"}
    for c in changes:
        w.add(f"{symbol[c.status]} {c.path} ({fmt_size(c.size)})", "changes")
    w.finish_section("changes")

    if w.omitted:
        w.force("")
        w.force("## Notes")
        w.force("omitted for length: " + ", ".join(f"{n} {s}" for s, n in w.omitted.items()))
    text = "\n".join(w.lines)
    return Dossier(
        sample_id=sample_id,
        extractor_version=EXTRACTOR_VERSION,
        text=text,
        lifecycle=life,
        lifecycle_changed=life_changed,
        dep_changes=deps,
        outside_files=outside,
        target_profiles=profiles,
        hits=hits,
        changes=changes,
        truncated=bool(w.omitted),
        est_tokens=len(text) // 4,
    )
