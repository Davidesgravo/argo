import json
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from argo.config import (
    EMBED_MODEL,
    LLM_OPTIONS,
    RAG_DIR,
    RETRY_NUM_PREDICT,
    RUNS_DIR,
    THINKING_MODELS,
)
from argo.jsonl import append_jsonl
from argo.llm.ollama import LLMClient
from argo.prompts.rag import QUERY_PREFIX, QueryCache, RagIndex, ollama_embedder
from argo.prompts.render import Example, compress_dossier, render
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
        return [n.example for n in self._indexes[index_name].query(vector, k=3)]

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
        latency, t_in, t_out = res.latency_s, res.tokens_in, res.tokens_out
        output = _parse(res.content)
        if output is None:
            options["num_predict"] = RETRY_NUM_PREDICT
            res = self.client.chat(model, rp.system, rp.user, schema, options, think)
            latency, t_in, t_out = (
                latency + res.latency_s,
                t_in + res.tokens_in,
                t_out + res.tokens_out,
            )
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
            extractor_version=dossier.extractor_version,
            temperature=float(options["temperature"]),
            seed=int(options["seed"]),
            num_ctx=int(options["num_ctx"]),
            raw_output=res.content,
            valid=output is not None,
            output=output,
            latency_s=round(latency, 3),
            tokens_in=t_in,
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


def run(
    cfg: RunConfig,
    samples: Sequence[Sample],
    dossiers: dict[str, Dossier],
    predictor: Predictor,
    runs_dir: Path = RUNS_DIR,
    log: Callable[[str], None] = print,
) -> Path:
    out_dir = runs_dir / cfg.run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    pred_path = out_dir / "predictions.jsonl"
    jobs = [j for j in plan_jobs(cfg, samples) if j.sample_id in dossiers]
    (out_dir / "config.json").write_text(json.dumps({**asdict(cfg), "n_jobs": len(jobs)}, indent=2))
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
