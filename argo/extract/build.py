import json
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from argo.config import BASELINE_PATH, DATA_DIR, DOSSIER_DIR, EXTRACTOR_VERSION
from argo.extract.archive import ArchiveError, PackageFiles, read_datadog_zip, read_npm_tgz
from argo.extract.baseline import WEIGHTS, calibrate, rates_at, score
from argo.extract.dossier import build_dossier
from argo.schema import Dossier, Sample


def safe_name(sample_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", sample_id)


def dossier_path(sample_id: str, dossier_dir: Path = DOSSIER_DIR) -> Path:
    return dossier_dir / f"{safe_name(sample_id)}.json"


def load_package(s: Sample, data_dir: Path = DATA_DIR) -> PackageFiles:
    path = data_dir / s.archive_path
    if s.source == "datadog":
        return read_datadog_zip(path)[0]
    return read_npm_tgz(path.read_bytes())


def load_previous(s: Sample, data_dir: Path = DATA_DIR) -> PackageFiles | None:
    if not s.prev_archive_path:
        return None
    return read_npm_tgz((data_dir / s.prev_archive_path).read_bytes())


def dossier_for_sample(s: Sample, data_dir: Path = DATA_DIR) -> Dossier:
    return build_dossier(
        s.id,
        s.name,
        s.version,
        load_package(s, data_dir),
        load_previous(s, data_dir),
        s.prev_version,
    )


def build_all(
    samples: Sequence[Sample],
    data_dir: Path = DATA_DIR,
    dossier_dir: Path = DOSSIER_DIR,
    log: Callable[[str], None] = print,
) -> int:
    dossier_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for s in samples:
        out = dossier_path(s.id, dossier_dir)
        if (
            out.exists()
            and json.loads(out.read_text()).get("extractor_version") == EXTRACTOR_VERSION
        ):
            continue
        try:
            d = dossier_for_sample(s, data_dir)
        except (ArchiveError, OSError) as e:
            log(f"skip {s.id}: {e}")
            continue
        out.write_text(d.model_dump_json())
        written += 1
        log(f"dossier {s.id}: {d.est_tokens} tokens{' (truncated)' if d.truncated else ''}")
    return written


def load_dossier(sample_id: str, dossier_dir: Path = DOSSIER_DIR) -> Dossier:
    return Dossier.model_validate_json(dossier_path(sample_id, dossier_dir).read_text())


def load_dossiers(samples: Sequence[Sample], dossier_dir: Path = DOSSIER_DIR) -> dict[str, Dossier]:
    return {
        s.id: load_dossier(s.id, dossier_dir)
        for s in samples
        if dossier_path(s.id, dossier_dir).exists()
    }


def calibrate_baseline(
    samples: Sequence[Sample], dossiers: dict[str, Dossier], out_path: Path = BASELINE_PATH
) -> dict[str, Any]:
    hist = [s for s in samples if s.split == "history" and s.id in dossiers]
    scores = [score(dossiers[s.id]) for s in hist]
    labels = [s.label == "malicious" for s in hist]
    threshold = calibrate(scores, labels)
    rates = rates_at(scores, labels, threshold)
    result = {
        "threshold": threshold,
        "weights": WEIGHTS,
        "n_history": len(hist),
        "f1_history": round(rates["f1"], 4),
        "recall_history": round(rates["recall"], 4),
        "fpr_history": round(rates["fpr"], 4),
        "youden_history": round(rates["youden"], 4),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    return result


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text())
    return data
