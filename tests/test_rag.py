from argo.prompts.rag import QueryCache, RagIndex, build_index
from argo.schema import Dossier, Sample


def fake_embed(texts: list[str]) -> list[list[float]]:
    # 3-dim bag of keywords: "bun", "token", "react"
    return [
        [t.count("bun") + 0.01, t.count("token") + 0.01, t.count("react") + 0.01] for t in texts
    ]


def _s(i: str, label: str, hs: str | None, split: str = "history") -> Sample:
    return Sample(
        id=i,
        name=i,
        version="1",
        prev_version=None,
        label=label,
        subgroup="nato_malevolo",
        date="2024-01-01",
        split=split,
        history_set=hs,
        source="npm",
        archive_path="x",
        sha256="0",
        fingerprint=i,
    )


def _d(i: str, text: str) -> Dossier:
    return Dossier(
        sample_id=i,
        extractor_version="1",
        text=text,
        lifecycle={},
        lifecycle_changed=False,
        dep_changes=[],
        outside_files=[],
        target_profiles=[],
        hits=[],
        changes=[],
        truncated=False,
        est_tokens=1,
    )


SAMPLES = [
    _s("a", "malicious", "base"),
    _s("b", "malicious", "w1"),
    _s("c", "benign", "base"),
    _s("t", "malicious", None, split="test"),
]
DOSSIERS = {
    "a": _d("a", "token token"),
    "b": _d("b", "bun bun bun"),
    "c": _d("c", "react"),
    "t": _d("t", "bun"),
}


def test_index_membership_follows_history_sets():
    assert {
        e.sample_id for e in build_index("storico_base", SAMPLES, DOSSIERS, fake_embed).examples
    } == {"a", "c"}
    assert {
        e.sample_id for e in build_index("storico_w1", SAMPLES, DOSSIERS, fake_embed).examples
    } == {"a", "b", "c"}


def test_query_returns_most_similar_first(tmp_path):
    idx = build_index("storico_w1", SAMPLES, DOSSIERS, fake_embed)
    idx.save(tmp_path)
    loaded = RagIndex.load("storico_w1", tmp_path)
    [first, *_] = loaded.query(fake_embed(["bun"])[0], k=2)
    assert first.example.sample_id == "b" and first.example.label == "malicious"
    assert len(loaded.query(fake_embed(["x"])[0], k=2)) == 2


def test_query_cache_persists(tmp_path):
    calls = []

    def counting(texts):
        calls.append(texts)
        return fake_embed(texts)

    c = QueryCache(tmp_path / "q.json")
    v1 = c.get("k", "bun", counting)
    v2 = QueryCache(tmp_path / "q.json").get("k", "bun", counting)
    assert v1 == v2 and len(calls) == 1
