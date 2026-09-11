import hashlib
import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from argo.config import (
    CORPUS_PATH,
    EMBED_MODEL,
    EXTRACTOR_VERSION,
    LLM_OPTIONS,
    RAG_DIR,
    RETRY_NUM_PREDICT,
    ROOT,
    RUNS_DIR,
    THINKING_MODELS,
)
from argo.jsonl import append_jsonl
from argo.llm.ollama import LLMClient
from argo.prompts.fewshot import FEWSHOT_PATH
from argo.prompts.rag import QUERY_PREFIX, QueryCache, RagIndex, ollama_embedder
from argo.prompts.render import TEMPLATE_DIR, Example, compress_dossier, render
from argo.schema import Dossier, Prediction, Sample, Verdict

_RQ3_INDEX = {"shai_hulud_w2": "storico_w1", "shai_hulud_w3": "storico_w1w2"}


@dataclass(frozen=True)
class Job:
    sample_id: str
    model: str
    prompt_id: str
    rag_index: str | None

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.sample_id, self.model, self.prompt_id, self.rag_index or "")


@dataclass
class RunConfig:
    run_id: str
    models: list[str]
    prompts: list[str]
    mode: str = "standard"  # "standard" | "rq3"
    rag_index: str = "storico_base"
    subgroups: list[str] | None = None
    limit: int | None = None


def rq3_index(s: Sample, by_id: dict[str, Sample]) -> str | None:
    subgroup = s.subgroup
    if subgroup == "pulito_accoppiato" and s.pair_id in by_id:
        subgroup = by_id[s.pair_id].subgroup
    return _RQ3_INDEX.get(subgroup)


def plan_jobs(cfg: RunConfig, samples: Sequence[Sample]) -> list[Job]:
    test = [s for s in samples if s.split == "test"]
    if cfg.subgroups is not None:
        test = [s for s in test if s.subgroup in cfg.subgroups]
    if cfg.limit is not None:
        test = test[: cfg.limit]
    by_id = {s.id: s for s in samples}
    jobs: list[Job] = []
    for model in cfg.models:
        for s in test:
            for p in cfg.prompts:
                if cfg.mode == "rq3":
                    idx = rq3_index(s, by_id)  # RQ3 compares retrieval indexes: P3 only
                    if p == "p3" and idx is not None:
                        jobs.append(Job(s.id, model, p, idx))
                else:
                    jobs.append(Job(s.id, model, p, cfg.rag_index if p == "p3" else None))
    return jobs


def _parse(content: str) -> Verdict | None:
    try:
        return Verdict.model_validate_json(content)
    except ValidationError:
        return None


class Predictor:
    def __init__(
        self,
        client: LLMClient,
        fewshot: list[Example],
        rag_dir: Path = RAG_DIR,
        query_cache_path: Path | None = None,
    ) -> None:
        self.client = client
        self.fewshot = fewshot
        self.rag_dir = rag_dir
        self._indexes: dict[str, RagIndex] = {}
        self._digests: dict[str, str] = {}
        self._queries = QueryCache(query_cache_path or rag_dir / "query_cache.json", EMBED_MODEL)
        self._embed = ollama_embedder(client, EMBED_MODEL, QUERY_PREFIX)

    def _digest(self, model: str) -> str:
        if model not in self._digests:
            self._digests[model] = self.client.model_digest(model)
        return self._digests[model]

    def _neighbors(self, dossier: Dossier, index_name: str) -> list[Example]:
        if index_name not in self._indexes:
            self._indexes[index_name] = RagIndex.load(index_name, self.rag_dir)
        vector = self._queries.get(compress_dossier(dossier.text), self._embed)
        return [n.example for n in self._indexes[index_name].query(vector)]

    def predict(
        self,
        run_id: str,
        sample_id: str,
        dossier: Dossier,
        model: str,
        prompt_id: str,
        rag_index: str | None,
    ) -> Prediction:
        examples: list[Example] = []
        if prompt_id == "p2":
            examples = self.fewshot
        elif prompt_id == "p3":
            examples = self._neighbors(dossier, rag_index or "storico_base")
        rp = render(prompt_id, dossier.text, examples)
        options = dict(LLM_OPTIONS)
        think = False if model in THINKING_MODELS else None
        schema = Verdict.model_json_schema()
        res = self.client.chat(model, rp.system, rp.user, schema, options, think)
        attempts, latency, t_out = 1, res.latency_s, res.tokens_out
        output = _parse(res.content)
        if output is None:
            options["num_predict"] = RETRY_NUM_PREDICT
            res = self.client.chat(model, rp.system, rp.user, schema, options, think)
            attempts, latency, t_out = 2, latency + res.latency_s, t_out + res.tokens_out
            output = _parse(res.content)
        return Prediction(
            run_id=run_id,
            sample_id=sample_id,
            model=model,
            model_digest=self._digest(model),
            prompt_id=prompt_id,
            prompt_hash=rp.prompt_hash,
            rag_index=rag_index if prompt_id == "p3" else None,
            rag_neighbors=[e.sample_id for e in examples] if prompt_id == "p3" else None,
            rag_neighbor_labels=[e.label for e in examples] if prompt_id == "p3" else None,
            extractor_version=dossier.extractor_version,
            temperature=float(options["temperature"]),
            seed=int(options["seed"]),
            num_ctx=int(options["num_ctx"]),
            num_predict=int(options["num_predict"]),  # value used on the final attempt
            attempts=attempts,
            raw_output=res.content,
            valid=output is not None,
            output=output,
            latency_s=round(latency, 3),
            tokens_in=res.tokens_in,  # prompt of the final attempt (a retry re-sends it)
            tokens_out=t_out,
            timestamp=datetime.now(UTC).isoformat(),
        )


def completed_keys(pred_path: Path) -> set[tuple[str, str, str, str]]:
    # Reads records directly (rather than via jsonl.read_jsonl) so that a truncated
    # last line — left behind when a run is killed mid-write — is skipped instead of
    # raising, letting a resumed run recompute that one job instead of crashing.
    if not pred_path.exists():
        return set()
    lines = [line for line in pred_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    keys: set[tuple[str, str, str, str]] = set()
    for i, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            if i == len(lines) - 1:
                continue
            raise
        keys.add(
            (
                record["sample_id"],
                record["model"],
                record["prompt_id"],
                record.get("rag_index") or "",
            )
        )
    return keys


def repair_tail(pred_path: Path, tail_path: Path) -> None:
    """Make predictions.jsonl safe to append to after a crash.

    A run killed mid-write leaves a partial last line; appending would glue the next
    record onto it. The fragment is cut off (and kept in `tail_path` for inspection);
    a valid last line that merely lacks its newline gets one.
    """
    if not pred_path.exists():
        return
    data = pred_path.read_bytes()
    body = data.rstrip(b"\n")
    if not body:
        return
    start = body.rfind(b"\n") + 1  # start of the last non-empty line
    try:
        json.loads(body[start:])
    except ValueError:
        with tail_path.open("ab") as f:
            f.write(data[start:])
        with pred_path.open("r+b") as f:
            f.truncate(start)
        return
    if not data.endswith(b"\n"):
        with pred_path.open("ab") as f:
            f.write(b"\n")


class RunMismatchError(RuntimeError):
    pass


def _sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def run_fingerprint(
    predictor: Predictor, jobs: Sequence[Job], fewshot_path: Path, corpus_path: Path
) -> dict[str, Any]:
    """Everything outside the prediction records that determines them (run provenance)."""
    indexes = sorted({j.rag_index for j in jobs if j.rag_index})
    return {
        "templates": {p.name: _sha256(p) for p in sorted(TEMPLATE_DIR.iterdir()) if p.is_file()},
        "fewshot_sha256": _sha256(fewshot_path),
        "extractor_version": EXTRACTOR_VERSION,
        "corpus_sha256": _sha256(corpus_path),
        "rag_index_files": {
            f"{name}{ext}": _sha256(predictor.rag_dir / f"{name}{ext}")
            for name in indexes
            for ext in (".json", ".npy")
        },
        "embed_model": EMBED_MODEL,
        "embed_model_digest": predictor.client.model_digest(EMBED_MODEL) if indexes else None,
        "ollama_version": predictor.client.version(),
        "git_commit": _git_commit(),
    }


def _check_resume(run_id: str, cfg_path: Path, pred_path: Path, fp: dict[str, Any]) -> None:
    if not cfg_path.exists() or not pred_path.exists() or pred_path.stat().st_size == 0:
        return
    old = json.loads(cfg_path.read_text()).get("fingerprint") or {}
    changed = sorted(k for k in fp.keys() | old.keys() if old.get(k) != fp.get(k))
    if changed:
        raise RunMismatchError(
            f"Il run {run_id!r} esiste già ma è stato prodotto in condizioni diverse "
            f"({', '.join(changed)}). Per non mescolare predizioni vecchie e nuove "
            "usa un nuovo ID del run."
        )


def run(
    cfg: RunConfig,
    samples: Sequence[Sample],
    dossiers: dict[str, Dossier],
    predictor: Predictor,
    runs_dir: Path = RUNS_DIR,
    log: Callable[[str], None] = print,
    fewshot_path: Path = FEWSHOT_PATH,
    corpus_path: Path = CORPUS_PATH,
) -> Path:
    out_dir = runs_dir / cfg.run_id
    pred_path = out_dir / "predictions.jsonl"
    cfg_path = out_dir / "config.json"
    jobs = [j for j in plan_jobs(cfg, samples) if j.sample_id in dossiers]
    fp = run_fingerprint(predictor, jobs, fewshot_path, corpus_path)
    _check_resume(cfg.run_id, cfg_path, pred_path, fp)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(
        json.dumps({**asdict(cfg), "n_jobs": len(jobs), "fingerprint": fp}, indent=2)
    )
    repair_tail(pred_path, out_dir / "truncated_tail.txt")
    done = completed_keys(pred_path)
    todo = [j for j in jobs if j.key not in done]
    log(f"run {cfg.run_id}: {len(jobs)} jobs, {len(jobs) - len(todo)} already done")
    for i, j in enumerate(todo, 1):
        p = predictor.predict(
            cfg.run_id, j.sample_id, dossiers[j.sample_id], j.model, j.prompt_id, j.rag_index
        )
        append_jsonl(pred_path, p.model_dump())
        verdict = p.output.verdict if p.output else "INVALID"
        log(
            f"[{len(jobs) - len(todo) + i}/{len(jobs)}] {j.model} {j.prompt_id} "
            f"{j.sample_id} -> {verdict} ({p.latency_s:.1f}s)"
        )
    return pred_path
