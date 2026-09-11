import argparse
from collections.abc import Callable

Handler = Callable[[argparse.Namespace], int]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argo", description="Argo supply-chain defender PoC")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="print version").set_defaults(func=_version)

    ds = sub.add_parser("dataset", help="dataset commands")
    ds_sub = ds.add_subparsers(dest="dataset_command", required=True)
    ds_sub.add_parser("build", help="select samples and write data/corpus.jsonl").set_defaults(
        func=_dataset_build
    )
    return parser


def _version(_: argparse.Namespace) -> int:
    print("argo 0.1.0")
    return 0


def _dataset_build(_: argparse.Namespace) -> int:
    from argo.dataset.build import build_corpus, summarize

    samples = build_corpus()
    for key, n in summarize(samples).items():
        print(f"{key:40s} {n}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Handler = args.func
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
