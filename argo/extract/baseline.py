from collections.abc import Sequence

from argo.schema import Dossier

WEIGHTS: dict[str, float] = {
    "lifecycle_changed": 2.0,
    "non_registry_dep": 3.0,
    "outside_files": 1.5,
    "target_obfuscated": 3.0,
    "runtime_download": 2.0,
    "propagation": 2.0,
    "credentials": 1.5,
    "exec": 1.0,
    "obfuscation": 1.0,
    "network": 0.5,
}


def features(d: Dossier) -> dict[str, bool]:
    categories = {h.category for h in d.hits}
    return {
        "lifecycle_changed": d.lifecycle_changed,
        "non_registry_dep": any(c.non_registry for c in d.dep_changes),
        "outside_files": bool(d.outside_files),
        "target_obfuscated": any(p.obfuscated for p in d.target_profiles),
        **{
            c: c in categories
            for c in (
                "runtime_download",
                "propagation",
                "credentials",
                "exec",
                "obfuscation",
                "network",
            )
        },
    }


def score(d: Dossier) -> float:
    return sum(WEIGHTS[k] for k, on in features(d).items() if on)


def f1_at(scores: Sequence[float], labels: Sequence[bool], t: float) -> float:
    tp = sum(s >= t and y for s, y in zip(scores, labels, strict=True))
    fp = sum(s >= t and not y for s, y in zip(scores, labels, strict=True))
    fn = sum(s < t and y for s, y in zip(scores, labels, strict=True))
    return 0.0 if tp == 0 else 2 * tp / (2 * tp + fp + fn)


def youden_at(scores: Sequence[float], labels: Sequence[bool], t: float) -> float:
    tp = sum(s >= t and y for s, y in zip(scores, labels, strict=True))
    fp = sum(s >= t and not y for s, y in zip(scores, labels, strict=True))
    fn = sum(s < t and y for s, y in zip(scores, labels, strict=True))
    tn = sum(s < t and not y for s, y in zip(scores, labels, strict=True))
    recall = 0.0 if tp + fn == 0 else tp / (tp + fn)
    fpr = 0.0 if fp + tn == 0 else fp / (fp + tn)
    return recall - fpr


def calibrate(scores: Sequence[float], labels: Sequence[bool]) -> float:
    if not any(labels) or all(labels):  # no positives or no negatives: J is undefined
        return max(scores)
    candidates = sorted(set(scores), reverse=True)  # higher first → wins ties
    return max(candidates, key=lambda t: youden_at(scores, labels, t))
