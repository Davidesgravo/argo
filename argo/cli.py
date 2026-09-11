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

    dos = sub.add_parser("dossier", help="dossier commands")
    dos_sub = dos.add_subparsers(dest="dossier_command", required=True)
    dos_sub.add_parser("build", help="build a dossier for every corpus sample").set_defaults(
        func=_dossier_build
    )
    bl = sub.add_parser("baseline", help="rule-based baseline")
    bl_sub = bl.add_subparsers(dest="baseline_command", required=True)
    bl_sub.add_parser("calibrate", help="choose the threshold on history").set_defaults(
        func=_baseline_calibrate
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


def _dossier_build(_: argparse.Namespace) -> int:
    from argo.dataset.build import load_corpus
    from argo.extract.build import build_all

    print(f"{build_all(load_corpus())} dossiers written")
    return 0


def _baseline_calibrate(_: argparse.Namespace) -> int:
    from argo.dataset.build import load_corpus
    from argo.extract.build import calibrate_baseline, load_dossiers

    corpus = load_corpus()
    print(calibrate_baseline(corpus, load_dossiers(corpus)))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Handler = args.func
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
