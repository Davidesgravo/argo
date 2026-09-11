import json

from argo.llm.ollama import ChatResult
from argo.prompts.render import Example
from argo.run.runner import Predictor, RunConfig, completed_keys, plan_jobs, rq3_index, run
from argo.schema import Dossier, Sample, Verdict

GOOD = Verdict(evidence=["x"], reasoning="r", technique="none", verdict="benign", confidence=0.8)


class FakeClient:
    def __init__(self, replies: list[str]) -> None:
        self.replies = replies
        self.calls: list[dict] = []

    def chat(self, model, system, user, schema, options, think=None):
        self.calls.append({"model": model, "user": user, "options": dict(options), "think": think})
        return ChatResult(self.replies[min(len(self.calls), len(self.replies)) - 1], 100, 10, 0.5)

    def model_digest(self, model):
        return "sha256:" + model

    def embed(self, model, texts):
        return [[1.0, 0.0] for _ in texts]


def _s(i, sub, split="test", pair=None, label="malicious"):
    return Sample(
        id=i,
        name=i,
        version="1",
        prev_version=None,
        label=label,
        subgroup=sub,
        date="2025-06-01",
        split=split,
        source="npm",
        archive_path="x",
        sha256="0",
        fingerprint=i,
        pair_id=pair,
    )


def _d(i):
    return Dossier(
        sample_id=i,
        extractor_version="1",
        text=f"PACKAGE: {i}",
        lifecycle={},
        lifecycle_changed=False,
        dep_changes=[],
        outside_files=[],
        target_profiles=[],
        hits=[],
        changes=[],
        truncated=False,
        est_tokens=3,
    )


SAMPLES = [
    _s("a", "nato_malevolo"),
    _s("w2", "shai_hulud_w2", pair="c2"),
    _s("c2", "pulito_accoppiato", pair="w2", label="benign"),
    _s("w3", "shai_hulud_w3"),
    _s("h", "nato_malevolo", split="history"),
]


def test_rq3_index_follows_pairs():
    by_id = {s.id: s for s in SAMPLES}
    assert [rq3_index(by_id[i], by_id) for i in ("a", "w2", "c2", "w3")] == [
        None,
        "storico_w1",
        "storico_w1",
        "storico_w1w2",
    ]


def test_plan_standard_is_model_major_and_test_only():
    jobs = plan_jobs(RunConfig("r", ["m1", "m2"], ["p0", "p3"]), SAMPLES)
    assert len(jobs) == 2 * 4 * 2 and {j.model for j in jobs[:8]} == {"m1"}
    assert all(j.sample_id != "h" for j in jobs)
    assert {j.rag_index for j in jobs if j.prompt_id == "p3"} == {"storico_base"}
    assert {j.rag_index for j in jobs if j.prompt_id == "p0"} == {None}


def test_plan_rq3_only_wave_samples():
    jobs = plan_jobs(RunConfig("r", ["m"], ["p3"], mode="rq3"), SAMPLES)
    assert {(j.sample_id, j.rag_index) for j in jobs} == {
        ("w2", "storico_w1"),
        ("c2", "storico_w1"),
        ("w3", "storico_w1w2"),
    }


def test_predict_valid_and_thinking_flag():
    client = FakeClient([GOOD.model_dump_json()])
    p = Predictor(client, fewshot=[]).predict("r", "a", _d("a"), "qwen3:4b", "p1", None)
    assert p.valid and p.output == GOOD and p.model_digest == "sha256:qwen3:4b"
    assert client.calls[0]["think"] is False and client.calls[0]["options"]["num_ctx"] == 8192


def test_predict_retries_once_with_more_tokens_then_gives_up():
    client = FakeClient(["{truncated", "{still bad"])
    p = Predictor(client, fewshot=[]).predict("r", "a", _d("a"), "llama3.2:3b", "p0", None)
    assert not p.valid and p.output is None and len(client.calls) == 2
    assert client.calls[1]["options"]["num_predict"] == 600 and client.calls[0]["think"] is None
    assert p.tokens_in == 200 and p.latency_s == 1.0


def test_p2_uses_fewshot_examples():
    client = FakeClient([GOOD.model_dump_json()])
    ex = [Example("h", "malicious", "PACKAGE: h")]
    Predictor(client, fewshot=ex).predict("r", "a", _d("a"), "m", "p2", None)
    assert "PACKAGE: h" in client.calls[0]["user"]


def test_run_resumes(tmp_path):
    cfg = RunConfig("r1", ["m"], ["p0"])
    dossiers = {s.id: _d(s.id) for s in SAMPLES}
    client = FakeClient([GOOD.model_dump_json()])
    pred = run(cfg, SAMPLES[:2], dossiers, Predictor(client, []), tmp_path, log=lambda _: None)
    assert len(client.calls) == 2
    run(cfg, SAMPLES[:3], dossiers, Predictor(client, []), tmp_path, log=lambda _: None)
    assert len(client.calls) == 3 and len(completed_keys(pred)) == 3
    assert json.loads((tmp_path / "r1" / "config.json").read_text())["n_jobs"] == 3


def test_completed_keys_skips_truncated_last_line(tmp_path):
    path = tmp_path / "predictions.jsonl"
    good = {"sample_id": "a", "model": "m", "prompt_id": "p0", "rag_index": None}
    path.write_text(json.dumps(good) + "\n" + '{"sample_id": "b", "model": "m", "prompt_')
    assert completed_keys(path) == {("a", "m", "p0", "")}
