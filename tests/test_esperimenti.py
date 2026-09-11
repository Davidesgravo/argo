import os

from argo.ui.views.esperimenti import start_problem


def test_start_blocked_while_run_is_running(tmp_path):
    run_dir = tmp_path / "r1"
    run_dir.mkdir()
    (run_dir / "pid").write_text(str(os.getpid()))  # this test process: alive
    assert "in corso" in (start_problem(run_dir, n_jobs=5) or "")


def test_start_allowed_when_not_running(tmp_path):
    assert start_problem(tmp_path / "new", n_jobs=5) is None
    assert start_problem(tmp_path / "new", n_jobs=0) is not None
