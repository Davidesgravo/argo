import json
from collections.abc import Sequence
from pathlib import Path

from argo.config import DATA_DIR
from argo.extract.baseline import features
from argo.prompts.render import Example, compress_dossier
from argo.schema import Dossier, Label, Sample, Technique, Verdict

FEWSHOT_PATH = DATA_DIR / "fewshot.json"
_TECHNIQUE_BY_FEATURE: tuple[tuple[str, Technique], ...] = (
    ("non_registry_dep", "lifecycle_script"),
    ("propagation", "self_propagation"),
    ("credentials", "credential_theft"),
    ("target_obfuscated", "obfuscated_payload"),
    ("runtime_download", "lifecycle_script"),
    ("network", "exfiltration"),
    ("lifecycle_changed", "lifecycle_script"),
)


def infer_technique(d: Dossier, label: Label) -> Technique:
    if label == "benign":
        return "none"
    f = features(d)
    return next((t for key, t in _TECHNIQUE_BY_FEATURE if f[key]), "other")


def auto_answer(d: Dossier, label: Label) -> Verdict:
    evidence = [f"{h.category} in {h.path}: {h.snippet[:80]}" for h in d.hits[:3]]
    if label == "malicious":
        reasoning = (
            "The version introduces install-time behaviour matching a known attack pattern "
            "that the package's purpose does not justify."
        )
    else:
        reasoning = (
            "The changes look like an ordinary update; any install-time behaviour is unchanged "
            "and consistent with the package's purpose."
        )
    return Verdict(
        evidence=evidence or ["no suspicious indicator in the changed files"],
        reasoning=reasoning,
        technique=infer_technique(d, label),
        verdict=label,
        confidence=0.9,
    )


def select_fewshot(samples: Sequence[Sample], dossiers: dict[str, Dossier]) -> list[Sample]:
    pool = sorted(
        (
            s
            for s in samples
            if s.split == "history" and s.history_set == "base" and s.id in dossiers
        ),
        key=lambda s: s.id,
    )
    picked: list[Sample] = []
    techniques: set[str] = set()
    for s in pool:
        if s.label == "malicious" and len(picked) < 2:
            t = infer_technique(dossiers[s.id], "malicious")
            if t not in techniques:
                picked.append(s)
                techniques.add(t)
    for sub in ("benigno_popolare", "benigno_difficile"):
        picked += [next(s for s in pool if s.subgroup == sub)]
    return picked


def build_fewshot(
    samples: Sequence[Sample], dossiers: dict[str, Dossier], path: Path = FEWSHOT_PATH
) -> list[Example]:
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
