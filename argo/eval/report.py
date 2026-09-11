from collections.abc import Sequence
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from argo.config import RESULTS_DIR, RUNS_DIR, SEED  # noqa: E402
from argo.eval.metrics import RATES, confusion  # noqa: E402
from argo.eval.stats import bootstrap_ci, mcnemar_exact  # noqa: E402
from argo.extract.baseline import score  # noqa: E402
from argo.jsonl import read_jsonl  # noqa: E402
from argo.schema import Dossier, Sample  # noqa: E402

SUBGROUPS = (
    "nato_malevolo",
    "compromesso",
    "shai_hulud_w1",
    "shai_hulud_w2",
    "shai_hulud_w3",
    "benigno_popolare",
    "benigno_difficile",
    "pulito_accoppiato",
)
SCOPES: tuple[str, ...] = ("all", "shai_hulud", *SUBGROUPS)
GROUP_KEYS = ["run_id", "model", "prompt_id", "rag_index"]
PRED_KEY = ["run_id", "sample_id", "model", "prompt_id", "rag_index"]
COLUMNS = [
    "run_id",
    "sample_id",
    "model",
    "prompt_id",
    "rag_index",
    "prompt_hash",
    "extractor_version",
    "valid",
    "verdict",
    "technique",
    "confidence",
    "evidence",
    "reasoning",
    "latency_s",
    "tokens_in",
    "tokens_out",
]


def load_predictions(
    runs_dir: Path = RUNS_DIR, exclude: Sequence[str] = ("smoke", "bench")
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for path in sorted(runs_dir.glob("*/predictions.jsonl")):
        if path.parent.name in exclude:
            continue
        for r in read_jsonl(path):
            out = r.get("output") or {}
            rows.append(
                {
                    "run_id": r["run_id"],
                    "sample_id": r["sample_id"],
                    "model": r["model"],
                    "prompt_id": r["prompt_id"],
                    "rag_index": r.get("rag_index"),
                    "prompt_hash": r.get("prompt_hash"),
                    "extractor_version": r.get("extractor_version"),
                    "valid": r["valid"],
                    "verdict": out.get("verdict"),
                    "technique": out.get("technique"),
                    "confidence": out.get("confidence"),
                    "evidence": out.get("evidence", []),
                    "reasoning": out.get("reasoning", ""),
                    "latency_s": r["latency_s"],
                    "tokens_in": r["tokens_in"],
                    "tokens_out": r["tokens_out"],
                }
            )
    df = pd.DataFrame(rows, columns=COLUMNS)
    check_integrity(df)
    return df


def check_integrity(preds: pd.DataFrame) -> None:
    """Refuse predictions that would silently distort the metrics: a (run, sample, model,
    prompt, index) key seen twice, or a run/model/prompt/index group that mixes prompt
    templates or extractor versions (e.g. a resumed run after a rebuild)."""
    dup = preds[preds.duplicated(PRED_KEY, keep=False)]
    if not dup.empty:
        examples = dup[PRED_KEY].drop_duplicates().head(5).to_dict("records")
        raise ValueError(f"predizioni duplicate ({len(dup)} righe), per esempio: {examples}")
    for keys, g in preds.groupby(GROUP_KEYS, dropna=False, sort=True):
        for col in ("prompt_hash", "extractor_version"):
            if col in g and g[col].nunique(dropna=False) > 1:
                values = sorted(map(str, g[col].unique()))
                raise ValueError(
                    f"il gruppo {dict(zip(GROUP_KEYS, keys, strict=True))} mescola valori "
                    f"diversi di {col}: {values}. Ripeti il run con un nuovo ID."
                )


def baseline_predictions(
    samples: Sequence[Sample], dossiers: dict[str, Dossier], threshold: float
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = [
        {
            "run_id": "baseline",
            "sample_id": s.id,
            "model": "baseline",
            "prompt_id": "rules",
            "rag_index": None,
            "prompt_hash": "rules",
            "extractor_version": dossiers[s.id].extractor_version,
            "valid": True,
            "verdict": "malicious" if score(dossiers[s.id]) >= threshold else "benign",
            "technique": None,
            "confidence": None,
            "evidence": [],
            "reasoning": "",
            "latency_s": 0.0,
            "tokens_in": 0,
            "tokens_out": 0,
        }
        for s in samples
        if s.split == "test" and s.id in dossiers
    ]
    return pd.DataFrame(rows, columns=COLUMNS)


def _in_scope(s: Sample, scope: str) -> bool:
    if scope == "all":
        return True
    if scope == "shai_hulud":
        return s.subgroup.startswith("shai_hulud")
    return s.subgroup == scope


def _group_rows(g: pd.DataFrame, by_id: dict[str, Sample]) -> list[dict[str, Any]]:
    rows = []
    for scope in SCOPES:
        sub = g[g.sample_id.map(lambda i, scope=scope: _in_scope(by_id[i], scope))]
        if sub.empty:
            continue
        truth = [by_id[i].label == "malicious" for i in sub.sample_id]
        pred = [None if v is None or pd.isna(v) else v == "malicious" for v in sub.verdict]
        c = confusion(truth, pred)
        ci = bootstrap_ci(truth, pred)
        row: dict[str, Any] = {
            "scope": scope,
            "n": c.n,
            "tp": c.tp,
            "fp": c.fp,
            "tn": c.tn,
            "fn": c.fn,
            "invalid": c.invalid,
        }
        for name, fn in RATES.items():
            row[name] = fn(c)
            row[f"{name}_lo"], row[f"{name}_hi"] = ci[name]
        row["latency_mean"] = float(sub.latency_s.mean())
        row["latency_median"] = float(sub.latency_s.median())
        row["tokens_in_mean"] = float(sub.tokens_in.mean())
        rows.append(row)
    return rows


def metrics_table(preds: pd.DataFrame, samples: Sequence[Sample]) -> pd.DataFrame:
    check_integrity(preds)
    by_id = {s.id: s for s in samples}
    preds = preds[preds.sample_id.isin(by_id)]
    rows = []
    for keys, g in preds.groupby(GROUP_KEYS, dropna=False, sort=True):
        for r in _group_rows(g, by_id):
            rows.append(dict(zip(GROUP_KEYS, keys, strict=True)) | r)
    return pd.DataFrame(rows)


def _correct(df: pd.DataFrame, by_id: dict[str, Sample]) -> pd.Series:
    return df.apply(lambda r: r.verdict == by_id[r.sample_id].label, axis=1)


def mcnemar_table(
    preds: pd.DataFrame, samples: Sequence[Sample], run_id: str = "main"
) -> pd.DataFrame:
    by_id = {s.id: s for s in samples}
    main = preds[(preds.run_id == run_id) & preds.sample_id.isin(by_id)]
    rows = []
    for model, g in main.groupby("model"):
        wide = g.assign(ok=_correct(g, by_id)).pivot_table(
            index="sample_id", columns="prompt_id", values="ok", aggfunc="first"
        )
        for a, b in (("p0", "p1"), ("p1", "p2"), ("p1", "p3"), ("p0", "p3")):
            if a in wide and b in wide:
                pair = wide[[a, b]].dropna()
                b_count, c_count, p = mcnemar_exact(
                    list(pair[a].astype(bool)), list(pair[b].astype(bool))
                )
                rows.append(
                    {
                        "model": model,
                        "a": a,
                        "b": b,
                        "n": len(pair),
                        "b_count": b_count,
                        "c_count": c_count,
                        "p_value": p,
                    }
                )
    return pd.DataFrame(rows)


GROWN_INDEX = {"shai_hulud_w2": "storico_w1", "shai_hulud_w3": "storico_w1w2"}


def _p3_rate(
    p3: pd.DataFrame, run_id: str, model: str, index: str, ids: list[str], hit: str
) -> float:
    """Share of predictions that are `hit` ("malicious" on infected samples) or, with
    hit="not_benign", anything but "benign" (an invalid output on a clean pair is a FP)."""
    sel = p3[
        (p3.run_id == run_id)
        & (p3.model == model)
        & (p3.rag_index == index)
        & p3.sample_id.isin(ids)
    ]
    if sel.empty:
        return float("nan")
    ok = sel.verdict != "benign" if hit == "not_benign" else sel.verdict == hit
    return float(ok.mean())


def rq3_table(
    preds: pd.DataFrame,
    samples: Sequence[Sample],
    base_run: str = "main",
    grown_run: str = "rq3",
) -> pd.DataFrame:
    """RQ3: P3 with storico_base (from `base_run`) vs the grown index (from `grown_run`)."""
    by_id = {s.id: s for s in samples}
    p3 = preds[(preds.prompt_id == "p3") & preds.run_id.isin([base_run, grown_run])]
    rows = []
    for model in sorted(p3.model.unique()):
        for wave, idx in GROWN_INDEX.items():
            infected = [s.id for s in samples if s.subgroup == wave and s.split == "test"]
            pairs = [p for p in (by_id[i].pair_id for i in infected) if p in by_id]
            rows.append(
                {
                    "model": model,
                    "wave": wave,
                    "n_infected": len(infected),
                    "n_pairs": len(pairs),
                    "recall_base": _p3_rate(
                        p3, base_run, model, "storico_base", infected, "malicious"
                    ),
                    "recall_grown": _p3_rate(p3, grown_run, model, idx, infected, "malicious"),
                    "fpr_pairs_base": _p3_rate(
                        p3, base_run, model, "storico_base", pairs, "not_benign"
                    ),
                    "fpr_pairs_grown": _p3_rate(p3, grown_run, model, idx, pairs, "not_benign"),
                }
            )
    return pd.DataFrame(rows)


def rationale_sample(
    preds: pd.DataFrame, samples: Sequence[Sample], n: int = 20, seed: int = SEED
) -> pd.DataFrame:
    by_id = {s.id: s for s in samples}
    tp = preds[
        preds.sample_id.isin(by_id)
        & (preds.verdict == "malicious")
        & preds.sample_id.map(lambda i: i in by_id and by_id[i].label == "malicious")
        & (preds.model != "baseline")
    ]
    pick = tp.sample(n=min(n, len(tp)), random_state=seed)
    out = pick[
        ["run_id", "model", "prompt_id", "sample_id", "technique", "evidence", "reasoning"]
    ].copy()
    out.insert(4, "subgroup", out.sample_id.map(lambda i: by_id[i].subgroup))
    out["giudizio"] = ""  # corretta | parziale | sbagliata — filled by hand
    return out


def df_to_markdown(df: pd.DataFrame, floatfmt: str = ".3f") -> str:
    def cell(v: Any) -> str:
        return format(v, floatfmt) if isinstance(v, float) else str(v)

    lines = [
        "| " + " | ".join(map(str, df.columns)) + " |",
        "|" + "|".join("---" for _ in df.columns) + "|",
    ]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join(lines)


def heatmap_figure(metrics: pd.DataFrame, run_id: str = "main", metric: str = "f1") -> plt.Figure:
    t = metrics[(metrics.run_id == run_id) & (metrics.scope == "all")]
    grid = t.pivot_table(index="model", columns="prompt_id", values=metric)
    fig, ax = plt.subplots(figsize=(6, 0.6 * len(grid) + 1.5))
    im = ax.imshow(grid.values, cmap="viridis", vmin=0, vmax=1)
    ax.set_xticks(range(len(grid.columns)), grid.columns)
    ax.set_yticks(range(len(grid.index)), grid.index)
    for i in range(len(grid.index)):
        for j in range(len(grid.columns)):
            ax.text(j, i, f"{grid.values[i, j]:.2f}", ha="center", va="center", color="white")
    fig.colorbar(im, ax=ax, label=metric.upper())
    ax.set_title(f"{metric.upper()} per modello × prompt (test set)")
    fig.tight_layout()
    return fig


def fpr_figure(metrics: pd.DataFrame, run_id: str = "main") -> plt.Figure:
    t = metrics[
        (metrics.run_id.isin([run_id, "baseline"]))
        & metrics.scope.isin(["benigno_popolare", "benigno_difficile", "pulito_accoppiato"])
    ]
    t = t.assign(label=t.model + " " + t.prompt_id)
    grid = t.pivot_table(index="label", columns="scope", values="fpr")
    fig, ax = plt.subplots(figsize=(8, 0.35 * len(grid) + 1.5))
    grid.plot.barh(ax=ax)
    ax.set_xlabel("tasso di falsi positivi")
    ax.set_xlim(0, 1)
    fig.tight_layout()
    return fig


def rq3_figure(rq3: pd.DataFrame) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(7, 4))
    t = rq3.assign(label=rq3.model + " " + rq3.wave.str.replace("shai_hulud_", ""))
    t.set_index("label")[["recall_base", "recall_grown"]].plot.bar(ax=ax)
    ax.set_ylabel("rilevamento (recall)")
    ax.set_ylim(0, 1)
    ax.legend(["storico senza ondate precedenti", "storico con ondate precedenti"])
    fig.tight_layout()
    return fig


MAIN_COLS = [
    "model",
    "prompt_id",
    "n",
    "recall",
    "recall_lo",
    "recall_hi",
    "fpr",
    "fpr_lo",
    "fpr_hi",
    "f1",
    "f1_lo",
    "f1_hi",
    "invalid",
    "latency_mean",
]


def report_tables(
    metrics: pd.DataFrame, mcn: pd.DataFrame, rq3: pd.DataFrame, main_run: str = "main"
) -> dict[str, pd.DataFrame]:
    return {
        "principale.md": metrics[
            (metrics.scope == "all") & metrics.run_id.isin([main_run, "baseline"])
        ][MAIN_COLS],
        "shai_hulud.md": metrics[metrics.scope == "shai_hulud"][
            ["run_id", "model", "prompt_id", "rag_index", *MAIN_COLS[2:]]
        ],
        "mcnemar.md": mcn,
        "rq3.md": rq3,
    }


def write_report(
    results_dir: Path = RESULTS_DIR,
    runs_dir: Path = RUNS_DIR,
    main_run: str = "main",
    rq3_run: str = "rq3",
) -> list[Path]:
    from argo.dataset.build import load_corpus
    from argo.extract.build import load_baseline, load_dossiers

    corpus = load_corpus()
    test = [s for s in corpus if s.split == "test"]
    preds = pd.concat(
        [
            load_predictions(runs_dir),
            baseline_predictions(test, load_dossiers(test), load_baseline()["threshold"]),
        ],
        ignore_index=True,
    )
    metrics = metrics_table(preds, test)
    mcn = mcnemar_table(preds, test, run_id=main_run)
    rq3 = rq3_table(preds, test, base_run=main_run, grown_run=rq3_run)
    tables, figures = results_dir / "tables", results_dir / "figures"
    tables.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    written = []
    metrics.to_csv(results_dir / "metrics.csv", index=False)
    written.append(results_dir / "metrics.csv")
    for name, df in report_tables(metrics, mcn, rq3, main_run).items():
        (tables / name).write_text(df_to_markdown(df) + "\n")
        written.append(tables / name)
    for name, fig in {
        "heatmap_f1.png": heatmap_figure(metrics, main_run),
        "fpr.png": fpr_figure(metrics, main_run),
        "rq3.png": rq3_figure(rq3),
    }.items():
        fig.savefig(figures / name, dpi=200)
        plt.close(fig)
        written.append(figures / name)
    rationale = results_dir / "motivazioni_da_valutare.csv"
    if not rationale.exists():  # never overwrite manual judgements
        rationale_sample(preds, test).to_csv(rationale, index=False)
        written.append(rationale)
    return written
