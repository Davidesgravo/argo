import argparse
from collections.abc import Callable

Handler = Callable[[argparse.Namespace], int]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argo", description="Argo supply-chain defender PoC")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="print version").set_defaults(func=_version)
    return parser


def _version(_: argparse.Namespace) -> int:
    print("argo 0.1.0")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Handler = args.func
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
