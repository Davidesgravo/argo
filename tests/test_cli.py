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
