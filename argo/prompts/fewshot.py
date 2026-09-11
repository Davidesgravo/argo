import json
import re
from collections.abc import Callable, Sequence
from pathlib import Path

from argo.config import DATA_DIR
from argo.extract.baseline import features
from argo.prompts.rag import family
from argo.prompts.render import Example, compress_dossier
from argo.schema import Dossier, Label, Sample, Technique, Verdict

FEWSHOT_PATH = DATA_DIR / "fewshot.json"
MAX_EVIDENCE = 4
_TECHNIQUE_BY_FEATURE: tuple[tuple[str, Technique], ...] = (
    ("non_registry_dep", "lifecycle_script"),
    ("propagation", "self_propagation"),
    ("credentials", "credential_theft"),
    ("target_obfuscated", "obfuscated_payload"),
    ("runtime_download", "lifecycle_script"),
    ("network", "exfiltration"),
    ("lifecycle_changed", "lifecycle_script"),
)
_ACTIVE_HITS = {"network", "credentials", "exec"}
_SCRIPT_LINE = re.compile(r"^script (\w+): .*\[(NEW|CHANGED|unchanged|new package)\]$")
_SCRIPT_TAGS = {
    "NEW": "a new {} script",
    "CHANGED": "a changed {} script",
    "unchanged": "an unchanged {} script",
    "new package": "a {} script",
}


def infer_technique(d: Dossier, label: Label) -> Technique:
    if label == "benign":
        return "none"
    f = features(d)
    return next((t for key, t in _TECHNIQUE_BY_FEATURE if f[key]), "other")


def _section_items(excerpt: str, number: str) -> list[str]:
    """Bullet lines of dossier section `number` ("1", "3", ...), without the "- " prefix.
    Placeholders ("- none") and omission notes ("- (N more ...)", "- … and N more") are skipped."""
    items: list[str] = []
    inside = False
    for line in excerpt.splitlines():
        if line.startswith("## "):
            inside = line.startswith(f"## {number}.")
        elif inside and line.startswith("- ") and line != "- none":
            item = line[2:]
            if not item.startswith(("(", "…", "...")):
                items.append(item)
    return items


def _describe_vector(item: str) -> str:
    if m := _SCRIPT_LINE.match(item):
        return _SCRIPT_TAGS[m.group(2)].format(m.group(1))
    if m := re.match(r"^script (\w+) removed", item):
        return f"a removed {m.group(1)} script"
    if "[NON-REGISTRY SOURCE" in item:
        return "a dependency from a non-registry source"
    if item.startswith("added file outside declared `files`"):
        return "a file added outside the declared `files`"
    return item


def _reasoning(vectors: list[str], patterns: list[str], label: Label) -> str:
    cats = sorted({m.group(1) for p in patterns if (m := re.match(r"^\[(\w+)\]", p))})
    described = list(dict.fromkeys(_describe_vector(v) for v in vectors))
    if described:
        first = f"The install-time vectors show {', '.join(described[:3])}."
    else:
        first = "The excerpt shows no install-time execution vector."
    second = (
        f"The flagged code has {', '.join(cats)} patterns."
        if cats
        else "No suspicious pattern is flagged in the code."
    )
    if label == "malicious":
        third = "Together these match a known npm attack pattern."
    elif all(d.startswith("an unchanged") for d in described):
        third = "Nothing new runs at install time, so this reads as an ordinary release."
    else:
        third = "The install-time behaviour matches an ordinary release."
    return f"{first} {second} {third}"


def auto_answer(d: Dossier, label: Label) -> Verdict:
    """Expected answer for a few-shot example. Evidence lines are copied verbatim from the
    excerpt the model will see (install-time vectors first, then pattern lines), and the
    reasoning only restates what those lines show."""
    excerpt = compress_dossier(d.text)
    vectors = _section_items(excerpt, "1")
    patterns = _section_items(excerpt, "3")
    evidence = (vectors + patterns)[:MAX_EVIDENCE]
    if not evidence:
        evidence = [line for line in excerpt.splitlines() if line.startswith("TYPE: ")][:1]
    return Verdict(
        evidence=evidence,
        reasoning=_reasoning(vectors, patterns, label),
        technique=infer_technique(d, label),
        verdict=label,
        confidence=0.9,
    )


def _family_keys(name: str) -> set[str]:
    """Campaign family (scope, or stem before the first -) and the stem before the first
    - or /, both without a leading @, so `@prisma/client` and `prisma` also collide."""
    return {family(name).lstrip("@"), re.split(r"[-/]", name, maxsplit=1)[0].lstrip("@")}


def _is_update(s: Sample) -> bool:
    return s.prev_version is not None and s.prev_archive_path is not None


def _install_vector(d: Dossier) -> bool:
    f = features(d)
    return f["lifecycle_changed"] or f["non_registry_dep"]


Role = tuple[str, Callable[[Sample, Dossier], bool]]
_ROLES: tuple[Role, ...] = (
    (
        "malicious update with an install-time vector",
        lambda s, d: s.label == "malicious" and _is_update(s) and _install_vector(d),
    ),
    (
        "new malicious package with an install-time vector and a network/credentials/exec hit",
        lambda s, d: (
            s.label == "malicious"
            and s.prev_version is None
            and _install_vector(d)
            and any(h.category in _ACTIVE_HITS for h in d.hits)
        ),
    ),
    (
        "benigno_popolare update",
        lambda s, d: s.subgroup == "benigno_popolare" and _is_update(s),
    ),
    (
        "benigno_difficile update with an unchanged install script",
        lambda s, d: (
            s.subgroup == "benigno_difficile"
            and _is_update(s)
            and bool(d.lifecycle)
            and not d.lifecycle_changed
        ),
    ),
)


def select_fewshot(samples: Sequence[Sample], dossiers: dict[str, Dossier]) -> list[Sample]:
    """One example per role, from storico_base, smallest dossier first (ties by id).
    History samples related to any test sample (same scope or name stem) are never used."""
    test_keys = {k for s in samples if s.split == "test" for k in _family_keys(s.name)}
    pool = [
        s
        for s in samples
        if s.split == "history"
        and s.history_set == "base"
        and s.id in dossiers
        and not _family_keys(s.name) & test_keys
    ]
    picked: list[Sample] = []
    for description, fits in _ROLES:
        candidates = [s for s in pool if s not in picked and fits(s, dossiers[s.id])]
        if not candidates:
            raise ValueError(f"nessun campione dello storico adatto come esempio: {description}")
        picked.append(min(candidates, key=lambda s: (dossiers[s.id].est_tokens, s.id)))
    return picked


def build_fewshot(
    samples: Sequence[Sample],
    dossiers: dict[str, Dossier],
    path: Path = FEWSHOT_PATH,
    force: bool = False,
) -> list[Example]:
    if path.exists() and not force:
        raise FileExistsError(
            f"{path} esiste già e fa parte della configurazione dei run P2: non lo sovrascrivo. "
            "Usa `argo fewshot build --force` per rigenerarlo (i run già avviati andranno "
            "ripetuti con un nuovo ID)."
        )
    examples = [
        Example(
            s.id,
            s.label,
            compress_dossier(dossiers[s.id].text),
            auto_answer(dossiers[s.id], s.label),
        )
        for s in select_fewshot(samples, dossiers)
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            [
                {
                    "sample_id": e.sample_id,
                    "label": e.label,
                    "excerpt": e.excerpt,
                    "answer": e.answer.model_dump() if e.answer else None,
                }
                for e in examples
            ],
            indent=2,
        )
    )
    return examples


def load_fewshot(path: Path = FEWSHOT_PATH) -> list[Example]:
    return [
        Example(
            r["sample_id"],
            r["label"],
            r["excerpt"],
            Verdict.model_validate(r["answer"]) if r["answer"] else None,
        )
        for r in json.loads(path.read_text())
    ]
