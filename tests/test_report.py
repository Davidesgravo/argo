import json

import pandas as pd
import pytest

from argo.eval.report import (
    df_to_markdown,
    load_predictions,
    mcnemar_table,
    metrics_table,
    rq3_table,
)
from argo.schema import Sample


def _s(i, label, sub, pair=None):
    return Sample(
        id=i,
        name=i,
        version="1",
        prev_version=None,
        label=label,
        subgroup=sub,
        date="2025-06-01",
        split="test",
        source="npm",
        archive_path="x",
        sha256="0",
        fingerprint=i,
        pair_id=pair,
    )


SAMPLES = [
    _s("m1", "malicious", "nato_malevolo"),
    _s("m2", "malicious", "shai_hulud_w2", "c2"),
    _s("b1", "benign", "benigno_difficile"),
    _s("c2", "benign", "pulito_accoppiato", "m2"),
]


def _row(run, model, prompt, sid, verdict, rag=None):
    return {
        "run_id": run,
        "sample_id": sid,
        "model": model,
        "prompt_id": prompt,
        "rag_index": rag,
        "prompt_hash": f"hash-{prompt}",
        "extractor_version": "1",
        "valid": verdict is not None,
        "verdict": verdict,
        "technique": "none",
        "confidence": 0.9,
        "evidence": [],
        "reasoning": "",
        "latency_s": 1.0,
        "tokens_in": 100,
        "tokens_out": 10,
    }


def _preds():
    rows = []
    for sid, v0, v1 in [
        ("m1", "benign", "malicious"),
        ("m2", "benign", "malicious"),
        ("b1", "malicious", "benign"),
        ("c2", "benign", "benign"),
    ]:
        rows.append(_row("main", "m", "p0", sid, v0))
        rows.append(_row("main", "m", "p1", sid, v1))
        rows.append(_row("main", "m", "p3", sid, v1, "storico_base"))
    rows.append(_row("rq3", "m", "p3", "m2", "malicious", "storico_w1"))
    rows.append(_row("rq3", "m", "p3", "c2", "malicious", "storico_w1"))
    return pd.DataFrame(rows)


def test_metrics_table_scopes():
    t = metrics_table(_preds(), SAMPLES)
    p1_all = t[(t.prompt_id == "p1") & (t.scope == "all")].iloc[0]
    assert (p1_all.recall, p1_all.fpr, p1_all.f1) == (1.0, 0.0, 1.0)
    p0_hard = t[(t.prompt_id == "p0") & (t.scope == "benigno_difficile")].iloc[0]
    assert p0_hard.fpr == 1.0 and pd.isna(p0_hard.recall)
    assert set(t.scope) >= {"all", "shai_hulud", "nato_malevolo", "pulito_accoppiato"}


def test_mcnemar_table():
    t = mcnemar_table(_preds(), SAMPLES)
    row = t[(t.a == "p0") & (t.b == "p1")].iloc[0]
    assert (row.b_count, row.c_count) == (0, 3)


def test_rq3_table():
    t = rq3_table(_preds(), SAMPLES)
    row = t[t.wave == "shai_hulud_w2"].iloc[0]
    assert (row.recall_base, row.recall_grown, row.fpr_pairs_base, row.fpr_pairs_grown) == (
        1.0,
        1.0,
        0.0,
        1.0,
    )


def test_markdown():
    md = df_to_markdown(pd.DataFrame({"a": [1.23456], "b": ["x"]}))
    assert md.splitlines()[0] == "| a | b |" and "1.235" in md


def test_metrics_table_rejects_duplicate_predictions():
    preds = _preds()
    with pytest.raises(ValueError, match="duplicat"):
        metrics_table(pd.concat([preds, preds.iloc[[0]]], ignore_index=True), SAMPLES)


@pytest.mark.parametrize("column", ["prompt_hash", "extractor_version"])
def test_metrics_table_rejects_mixed_provenance_in_a_group(column):
    preds = _preds()
    preds.loc[0, column] = "other"
    with pytest.raises(ValueError, match=column):
        metrics_table(preds, SAMPLES)


def _record(sid, rag=None):
    return {
        "run_id": "r",
        "sample_id": sid,
        "model": "m",
        "prompt_id": "p3" if rag else "p0",
        "rag_index": rag,
        "prompt_hash": "h",
        "extractor_version": "1",
        "valid": True,
        "output": {"verdict": "benign"},
        "latency_s": 1.0,
        "tokens_in": 1,
        "tokens_out": 1,
    }


def test_load_predictions_rejects_duplicate_keys(tmp_path):
    run_dir = tmp_path / "r"
    run_dir.mkdir()
    lines = [_record("m1"), _record("m1", "storico_base"), _record("b1")]
    (run_dir / "predictions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in lines))
    assert len(load_predictions(tmp_path)) == 3  # same sample, different rag_index: fine
    with (run_dir / "predictions.jsonl").open("a") as f:
        f.write(json.dumps(_record("m1")) + "\n")
    with pytest.raises(ValueError, match="duplicat"):
        load_predictions(tmp_path)
