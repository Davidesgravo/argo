import json
import os
import subprocess

import pytest

from argo.run.launch import (
    is_running,
    is_valid_run_id,
    list_runs,
    run_command,
    run_progress,
    start_run,
)
from argo.run.runner import RunConfig


def test_run_command_flags():
    cmd = run_command(
        RunConfig("r1", ["m1", "m2"], ["p3"], mode="rq3", subgroups=["shai_hulud_w2"])
    )
    i = cmd.index("run")
    assert cmd[i - 2 : i] == ["-m", "argo.cli"]
    assert cmd[i + 1 :] == [
        "--run-id",
        "r1",
        "--models",
        "m1",
        "m2",
        "--prompts",
        "p3",
        "--mode",
        "rq3",
        "--yes",
        "--subgroups",
        "shai_hulud_w2",
    ]


def test_progress_and_listing(tmp_path):
    d = tmp_path / "r1"
    d.mkdir()
    (d / "config.json").write_text(json.dumps({"n_jobs": 10}))
    (d / "predictions.jsonl").write_text('{"a": 1}\n{"a": 2}\n')
    assert run_progress(d) == (2, 10)
    (d / "pid").write_text(str(os.getpid()))
    assert is_running(d)
    assert list_runs(tmp_path) == [{"run_id": "r1", "done": 2, "total": 10, "running": True}]


def test_finished_process_is_not_running(tmp_path):
    p = subprocess.Popen(["true"])
    p.wait()
    (tmp_path / "pid").write_text(str(p.pid))
    assert not is_running(tmp_path)
    assert not is_running(tmp_path / "missing")


@pytest.mark.parametrize(
    "run_id",
    ["r1", "run-2026_09.11", "A", "a" * 64],
)
def test_is_valid_run_id_accepts(run_id):
    assert is_valid_run_id(run_id)


@pytest.mark.parametrize(
    "run_id",
    ["", " x", "a/b", "../x", ".", "..", "-x", "_x", ".x", "a" * 65],
)
def test_is_valid_run_id_rejects(run_id):
    assert not is_valid_run_id(run_id)


@pytest.mark.parametrize("run_id", ["", "../x"])
def test_start_run_rejects_invalid_run_id_without_touching_filesystem(tmp_path, run_id):
    cfg = RunConfig(run_id, ["m1"], ["p0"])
    with pytest.raises(ValueError):
        start_run(cfg, runs_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []
