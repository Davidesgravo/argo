import json
import os

from argo.eval.report import load_predictions
from argo.ui.views.risultati import _predictions_key, predictions_or_error


def test_predictions_key_changes_when_file_is_appended(tmp_path):
    run_dir = tmp_path / "main"
    run_dir.mkdir()
    preds = run_dir / "predictions.jsonl"
    preds.write_text('{"sample_id": "a"}\n')

    key1 = _predictions_key(tmp_path)

    with preds.open("a") as f:
        f.write('{"sample_id": "b"}\n')
    later = preds.stat().st_mtime + 5
    os.utime(preds, (later, later))

    key2 = _predictions_key(tmp_path)

    assert key1 != key2
    assert key1[0] == key2[0] == 1  # same file count, resumed run only appended


def test_predictions_key_changes_when_a_run_is_added(tmp_path):
    run_dir = tmp_path / "main"
    run_dir.mkdir()
    (run_dir / "predictions.jsonl").write_text('{"sample_id": "a"}\n')
    key1 = _predictions_key(tmp_path)

    other_dir = tmp_path / "other"
    other_dir.mkdir()
    (other_dir / "predictions.jsonl").write_text('{"sample_id": "b"}\n')
    key2 = _predictions_key(tmp_path)

    assert key1[0] == 1 and key2[0] == 2


def test_predictions_key_empty_runs_dir(tmp_path):
    assert _predictions_key(tmp_path) == (0, 0.0)


def test_inconsistent_predictions_become_an_error_message(tmp_path):
    run_dir = tmp_path / "main"
    run_dir.mkdir()
    record = {
        "run_id": "main",
        "sample_id": "a",
        "model": "m",
        "prompt_id": "p0",
        "rag_index": None,
        "prompt_hash": "h",
        "extractor_version": "2",
        "valid": True,
        "output": {"verdict": "benign"},
        "latency_s": 1.0,
        "tokens_in": 1,
        "tokens_out": 1,
    }
    (run_dir / "predictions.jsonl").write_text(json.dumps(record) + "\n")
    preds, error = predictions_or_error(lambda: load_predictions(tmp_path))
    assert preds is not None and len(preds) == 1 and error is None
    with (run_dir / "predictions.jsonl").open("a") as f:
        f.write(json.dumps(record) + "\n")
    preds, error = predictions_or_error(lambda: load_predictions(tmp_path))
    assert preds is None and error is not None and "duplicate" in error
