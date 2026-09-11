from argo.cli import _ui, build_parser


def test_ui_command_registered():
    args = build_parser().parse_args(["ui"])
    assert args.func is _ui
