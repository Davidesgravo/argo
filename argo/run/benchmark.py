import json
import math
import os
import statistics
from collections.abc import Sequence
from pathlib import Path

from argo.config import BENCH_PATH
from argo.run.runner import Job, Predictor
from argo.schema import Dossier, Sample

P2_FACTOR = 1.3


def bench_samples(samples: Sequence[Sample], n: int) -> list[Sample]:
    test = sorted((s for s in samples if s.split == "test"), key=lambda s: s.id)
    mal = [s for s in test if s.label == "malicious"]
    ben = [s for s in test if s.label == "benign"]
    mixed = [s for pair in zip(mal, ben, strict=False) for s in pair]
    return mixed[:n]


def _write_atomic(path: Path, data: dict[str, dict[str, float]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, path)


def bench(
    models: Sequence[str],
    samples: Sequence[Sample],
    dossiers: dict[str, Dossier],
    predictor: Predictor,
    n: int = 10,
    prompts: Sequence[str] = ("p1", "p3"),
    out_path: Path = BENCH_PATH,
) -> dict[str, dict[str, float]]:
    data: dict[str, dict[str, float]] = (
        json.loads(out_path.read_text()) if out_path.exists() else {}
    )
    chosen = [s for s in bench_samples(samples, n) if s.id in dossiers]
    for model in models:
        for p in prompts:
            preds = [
                predictor.predict(
                    "bench", s.id, dossiers[s.id], model, p, "storico_base" if p == "p3" else None
                )
                for s in chosen
            ]
            lat = [x.latency_s for x in preds]
            data[f"{model}|{p}"] = {
                "mean_s": round(statistics.mean(lat), 2),
                "median_s": round(statistics.median(lat), 2),
                "invalid_rate": round(sum(not x.valid for x in preds) / len(preds), 3),
                "n": len(preds),
            }
            print(f"{model} {p}: {data[f'{model}|{p}']}")
            _write_atomic(out_path, data)
    return data


def estimate_seconds(jobs: Sequence[Job], bench_data: dict[str, dict[str, float]]) -> float | None:
    total = 0.0
    for j in jobs:
        key = f"{j.model}|{'p3' if j.prompt_id == 'p3' else 'p1'}"
        if key not in bench_data:
            return None
        mean = bench_data[key]["mean_s"]
        total += mean * (P2_FACTOR if j.prompt_id == "p2" else 1.0)
    return total


def fmt_duration(seconds: float) -> str:
    minutes = math.ceil(seconds / 60)
    return f"{minutes // 60}h {minutes % 60:02d}m"
