import hashlib
import json
import os
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


def package_name(sample_id: str) -> str:
    """`name@version` -> `name` (scoped names keep their leading `@`)."""
    head, sep, _ = sample_id.rpartition("@")
    return head if sep and head else sample_id


def family(name: str) -> str:
    """Campaign family: the npm scope for scoped names, else the name stem before the first -."""
    return name.split("/", 1)[0] if name.startswith("@") else name.split("-", 1)[0]


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

    def query(self, vector: Sequence[float], per_label: int = 2) -> list[Neighbor]:
        """The `per_label` most similar malicious and benign cases, at most one per campaign
        family, ordered by similarity (descending). A short class contributes what it has."""
        q = _normalize(np.asarray(vector, dtype=float))
        sims = self.vectors @ q
        order = sorted(range(len(self.examples)), key=lambda i: (-sims[i], i))
        taken = {"malicious": 0, "benign": 0}
        families: set[str] = set()
        out: list[Neighbor] = []
        for i in order:
            ex = self.examples[i]
            fam = family(package_name(ex.sample_id))
            if taken[ex.label] >= per_label or fam in families:
                continue
            out.append(Neighbor(ex, float(sims[i])))
            taken[ex.label] += 1
            families.add(fam)
            if all(n >= per_label for n in taken.values()):
                break
        return out


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
    """Query embeddings keyed by sha256(embed model + "\n" + query text).

    The key depends only on what is embedded, so different callers (experiment, UI) can
    never collide on a package name. The file is read lazily and written atomically.
    """

    def __init__(self, path: Path, model: str = EMBED_MODEL) -> None:
        self.path = path
        self.model = model
        self._data: dict[str, list[float]] | None = None

    def _load(self) -> dict[str, list[float]]:
        if self._data is None:
            try:
                self._data = json.loads(self.path.read_text()) if self.path.exists() else {}
            except json.JSONDecodeError:  # a cache: a corrupt file is just rebuilt
                self._data = {}
        return self._data

    def key(self, text: str) -> str:
        return hashlib.sha256(f"{self.model}\n{text}".encode()).hexdigest()

    def get(self, text: str, embed: Embedder) -> list[float]:
        data = self._load()
        key = self.key(text)
        if key not in data:
            data[key] = embed([text])[0]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(data))
            os.replace(tmp, self.path)
        return data[key]


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
