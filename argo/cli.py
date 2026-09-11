import argparse
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argo.run.runner import Predictor

Handler = Callable[[argparse.Namespace], int]


def _run_id_type(value: str) -> str:
    from argo.run.launch import is_valid_run_id

    if not is_valid_run_id(value):
        raise argparse.ArgumentTypeError(
            "ID del run non valido: usa lettere, cifre, '-', '_' o '.' (max 64 caratteri)."
        )
    return value


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
    ev = sub.add_parser("eval", help="metrics, tables and figures into results/")
    ev.add_argument("--main-run", default="main", type=_run_id_type, help="main run id")
    ev.add_argument("--rq3-run", default="rq3", type=_run_id_type, help="RQ3 run id")
    ev.set_defaults(func=_eval)

    fs = sub.add_parser("fewshot", help="few-shot examples for P2")
    fsb = fs.add_subparsers(dest="fewshot_command", required=True).add_parser(
        "build", help="select 4 history examples into data/fewshot.json"
    )
    fsb.add_argument("--force", action="store_true", help="overwrite an existing fewshot.json")
    fsb.set_defaults(func=_fewshot_build)

    rag = sub.add_parser("rag", help="RAG indexes for P3")
    rag.add_subparsers(dest="rag_command", required=True).add_parser(
        "index", help="embed history dossiers into the three indexes"
    ).set_defaults(func=_rag_index)

    b = sub.add_parser("bench", help="measure per-model latency")
    b.add_argument("--models", nargs="+", default=None)
    b.add_argument("--n", type=int, default=10)
    b.set_defaults(func=_bench)

    r = sub.add_parser("run", help="run an experiment (resumable)")
    r.add_argument("--run-id", required=True, type=_run_id_type)
    r.add_argument("--models", nargs="+", default=None)
    r.add_argument("--prompts", nargs="+", default=None)
    r.add_argument("--mode", choices=["standard", "rq3"], default="standard")
    r.add_argument("--subgroups", nargs="+", default=None)
    r.add_argument("--limit", type=int, default=None)
    r.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    r.set_defaults(func=_run)

    sub.add_parser("ui", help="start the Streamlit interface").set_defaults(func=_ui)
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


def _eval(args: argparse.Namespace) -> int:
    from argo.eval.report import write_report

    for p in write_report(main_run=args.main_run, rq3_run=args.rq3_run):
        print(p)
    return 0


def _fewshot_build(args: argparse.Namespace) -> int:
    from argo.dataset.build import load_corpus
    from argo.extract.build import load_dossiers
    from argo.prompts.fewshot import FEWSHOT_PATH, build_fewshot

    corpus = load_corpus()
    try:
        examples = build_fewshot(corpus, load_dossiers(corpus), FEWSHOT_PATH, force=args.force)
    except (FileExistsError, ValueError) as err:
        print(err)
        return 1
    for e in examples:
        print(f"{e.label:9s} {e.sample_id}  technique={e.answer.technique if e.answer else '-'}")
    print(f"written {FEWSHOT_PATH} — review the 'reasoning' texts before running P2")
    return 0


def _rag_index(_: argparse.Namespace) -> int:
    from argo.dataset.build import load_corpus
    from argo.extract.build import load_dossiers
    from argo.llm.ollama import OllamaClient
    from argo.prompts.rag import build_all_indexes

    corpus = load_corpus()
    print(build_all_indexes(corpus, load_dossiers(corpus), OllamaClient()))
    return 0


def _predictor() -> "Predictor":
    from argo.llm.ollama import OllamaClient
    from argo.prompts.fewshot import load_fewshot
    from argo.run.runner import Predictor

    return Predictor(OllamaClient(), load_fewshot())


def _bench(args: argparse.Namespace) -> int:
    from argo.config import MODELS
    from argo.dataset.build import load_corpus
    from argo.extract.build import load_dossiers
    from argo.run.benchmark import bench

    corpus = load_corpus()
    bench(args.models or MODELS, corpus, load_dossiers(corpus), _predictor(), n=args.n)
    return 0


def _run(args: argparse.Namespace) -> int:
    import json

    from argo.config import BENCH_PATH, MODELS, PROMPT_IDS
    from argo.dataset.build import load_corpus
    from argo.extract.build import load_dossiers
    from argo.run.benchmark import estimate_seconds, fmt_duration
    from argo.run.runner import RunConfig, RunMismatchError, plan_jobs, run

    cfg = RunConfig(
        run_id=args.run_id,
        models=args.models or MODELS,
        prompts=args.prompts or PROMPT_IDS,
        mode=args.mode,
        subgroups=args.subgroups,
        limit=args.limit,
    )
    corpus = load_corpus()
    dossiers = load_dossiers(corpus)
    jobs = [j for j in plan_jobs(cfg, corpus) if j.sample_id in dossiers]
    bench_data = json.loads(BENCH_PATH.read_text()) if BENCH_PATH.exists() else {}
    est = estimate_seconds(jobs, bench_data)
    print(
        f"{len(jobs)} inferences, estimated {fmt_duration(est) if est is not None else 'unknown (run argo bench)'}"
    )
    if not args.yes and input("Proceed? [y/N] ").strip().lower() != "y":
        return 1
    try:
        run(cfg, corpus, dossiers, _predictor())
    except RunMismatchError as e:
        print(e)
        return 1
    return 0


def _ui(_: argparse.Namespace) -> int:
    import subprocess
    import sys
    from pathlib import Path

    app = Path(__file__).parent / "ui" / "app.py"
    return subprocess.call([sys.executable, "-m", "streamlit", "run", str(app)])


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Handler = args.func
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
