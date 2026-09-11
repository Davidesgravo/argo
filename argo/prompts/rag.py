import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from argo.config import EMBED_MODEL, RAG_DIR
from argo.llm.ollama import LLMClient
from argo.prompts.render import Example, compress_dossier
from argo.schema import Dossier, Sample

INDEX_SETS: dict[str, set[str]] = {
    "storico_base": {"base"},
    "storico_w1": {"base", "w1"},
    "storico_w1w2": {"base", "w1", "w2"},
}
DOC_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "
Embedder = Callable[[list[str]], list[list[float]]]


@dataclass(frozen=True)
class Neighbor:
    example: Example
    similarity: float


def _normalize(m: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(m, axis=-1, keepdims=True)
    return m / np.where(norms == 0, 1.0, norms)


@dataclass
class RagIndex:
    name: str
    examples: list[Example]
    vectors: np.ndarray  # (n, dim), L2-normalised

    def save(self, rag_dir: Path) -> None:
        rag_dir.mkdir(parents=True, exist_ok=True)
        np.save(rag_dir / f"{self.name}.npy", self.vectors)
        meta = [
            {"sample_id": e.sample_id, "label": e.label, "excerpt": e.excerpt}
            for e in self.examples
        ]
        (rag_dir / f"{self.name}.json").write_text(json.dumps(meta, indent=1))

    @classmethod
    def load(cls, name: str, rag_dir: Path) -> "RagIndex":
        meta = json.loads((rag_dir / f"{name}.json").read_text())
        examples = [Example(m["sample_id"], m["label"], m["excerpt"]) for m in meta]
        return cls(name, examples, np.load(rag_dir / f"{name}.npy"))

    def query(self, vector: Sequence[float], k: int = 3) -> list[Neighbor]:
        q = _normalize(np.asarray(vector, dtype=float))
        sims = self.vectors @ q
        order = np.argsort(-sims)[:k]
        return [Neighbor(self.examples[int(i)], float(sims[int(i)])) for i in order]


def build_index(
    name: str, samples: Sequence[Sample], dossiers: dict[str, Dossier], embed: Embedder
) -> RagIndex:
    members = [
        s
        for s in samples
        if s.split == "history" and s.history_set in INDEX_SETS[name] and s.id in dossiers
    ]
    examples = [Example(s.id, s.label, compress_dossier(dossiers[s.id].text)) for s in members]
    vectors: list[list[float]] = []
    for i in range(0, len(examples), 16):
        vectors += embed([e.excerpt for e in examples[i : i + 16]])
    return RagIndex(name, examples, _normalize(np.asarray(vectors, dtype=float)))


class QueryCache:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, list[float]] = json.loads(path.read_text()) if path.exists() else {}

    def get(self, key: str, text: str, embed: Embedder) -> list[float]:
        if key not in self.data:
            self.data[key] = embed([text])[0]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data))
        return self.data[key]


def ollama_embedder(
    client: LLMClient, model: str = EMBED_MODEL, prefix: str = DOC_PREFIX
) -> Embedder:
    return lambda texts: client.embed(model, [prefix + t for t in texts])


def build_all_indexes(
    samples: Sequence[Sample],
    dossiers: dict[str, Dossier],
    client: LLMClient,
    rag_dir: Path = RAG_DIR,
) -> dict[str, int]:
    embed = ollama_embedder(client)
    sizes: dict[str, int] = {}
    for name in INDEX_SETS:
        idx = build_index(name, samples, dossiers, embed)
        idx.save(rag_dir)
        sizes[name] = len(idx.examples)
    return sizes
