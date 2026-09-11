import os

from argo.ui.views.risultati import _predictions_key


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
