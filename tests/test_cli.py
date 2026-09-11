import pytest

from argo.cli import _ui, build_parser


def test_ui_command_registered():
    args = build_parser().parse_args(["ui"])
    assert args.func is _ui


def test_run_rejects_invalid_run_id():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["run", "--run-id", ""])


def test_run_rejects_run_id_with_trailing_newline():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["run", "--run-id", "abc\n"])


def test_run_reports_fingerprint_mismatch(monkeypatch, tmp_path, capsys):
    from argo.cli import main
    from argo.run.runner import RunMismatchError

    def mismatch(*args, **kwargs):
        raise RunMismatchError("usa un nuovo ID del run")

    monkeypatch.setattr("argo.config.BENCH_PATH", tmp_path / "bench.json")
    monkeypatch.setattr("argo.dataset.build.load_corpus", lambda: [])
    monkeypatch.setattr("argo.extract.build.load_dossiers", lambda corpus: {})
    monkeypatch.setattr("argo.cli._predictor", lambda: None)
    monkeypatch.setattr("argo.run.runner.run", mismatch)
    assert main(["run", "--run-id", "r1", "--yes"]) == 1
    assert "nuovo ID" in capsys.readouterr().out


def test_fewshot_build_refuses_overwrite_without_force(monkeypatch, capsys):
    from argo.cli import main

    seen = {}

    def fake_build(corpus, dossiers, path=None, force=False):
        seen["force"] = force
        if not force:
            raise FileExistsError("esiste già: usa --force")
        return []

    monkeypatch.setattr("argo.dataset.build.load_corpus", lambda: [])
    monkeypatch.setattr("argo.extract.build.load_dossiers", lambda corpus: {})
    monkeypatch.setattr("argo.prompts.fewshot.build_fewshot", fake_build)
    assert main(["fewshot", "build"]) == 1 and "--force" in capsys.readouterr().out
    assert main(["fewshot", "build", "--force"]) == 0 and seen["force"] is True
