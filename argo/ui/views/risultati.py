from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from argo.config import RESULTS_DIR, RUNS_DIR
from argo.eval.report import (
    SCOPES,
    fpr_figure,
    heatmap_figure,
    load_predictions,
    rq3_figure,
    rq3_table,
)
from argo.extract.build import dossier_path, load_dossier
from argo.ui.common import corpus_or_warn, show_dossier

COLS = [
    "model",
    "prompt_id",
    "rag_index",
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
FILTERS = {"Falsi negativi": ("malicious", "benign"), "Falsi positivi": ("benign", "malicious")}


@st.cache_data(show_spinner=False)
def _metrics(mtime: float) -> pd.DataFrame:
    return pd.read_csv(RESULTS_DIR / "metrics.csv")


def _predictions_key(runs_dir: Path) -> tuple[int, float]:
    files = list(runs_dir.glob("*/predictions.jsonl"))
    return len(files), max((p.stat().st_mtime for p in files), default=0.0)


@st.cache_data(show_spinner=False)
def _predictions(key: tuple[int, float]) -> pd.DataFrame:
    return load_predictions(RUNS_DIR)


def render() -> None:
    st.title("Risultati")
    path = RESULTS_DIR / "metrics.csv"
    corpus = corpus_or_warn()
    if not path.exists() or corpus is None:
        st.info("Nessun risultato: esegui gli esperimenti e poi `argo eval`.")
        return
    m = _metrics(path.stat().st_mtime)
    runs = [r for r in sorted(m.run_id.unique()) if r != "baseline"]
    run = st.selectbox("Run", runs, index=runs.index("main") if "main" in runs else 0)
    scope = st.selectbox("Sottogruppo", SCOPES)
    table = m[m.run_id.isin([run, "baseline"]) & (m.scope == scope)][COLS]
    st.dataframe(table, hide_index=True, use_container_width=True)
    c1, c2 = st.columns(2)
    with c1:
        fig = heatmap_figure(m, run)
        st.pyplot(fig)
        plt.close(fig)
    with c2:
        fig = fpr_figure(m, run)
        st.pyplot(fig)
        plt.close(fig)

    preds = _predictions(_predictions_key(RUNS_DIR))
    test = [s for s in corpus if s.split == "test"]
    rq3 = rq3_table(preds, test)
    if not rq3.empty and rq3.recall_grown.notna().any():
        st.subheader("RQ3 · lo storico delle ondate precedenti aiuta?")
        st.dataframe(rq3, hide_index=True)
        fig = rq3_figure(rq3)
        st.pyplot(fig)
        plt.close(fig)

    st.subheader("Dettaglio errori")
    by_id = {s.id: s for s in test}
    sel = preds[(preds.run_id == run) & preds.sample_id.isin(by_id)]
    c1, c2, c3 = st.columns(3)
    model = c1.selectbox("Modello", sorted(sel.model.unique()))
    prompt = c2.selectbox("Prompt", sorted(sel[sel.model == model].prompt_id.unique()))
    kind = c3.radio("Mostra", [*FILTERS, "Non validi", "Tutti"], horizontal=True)
    rows = sel[(sel.model == model) & (sel.prompt_id == prompt)].copy()
    rows["label"] = rows.sample_id.map(lambda i: by_id[i].label)
    rows["subgroup"] = rows.sample_id.map(lambda i: by_id[i].subgroup)
    if kind in FILTERS:
        truth, verdict = FILTERS[kind]
        rows = rows[(rows.label == truth) & (rows.verdict == verdict)]
    elif kind == "Non validi":
        rows = rows[~rows.valid]
    st.dataframe(
        rows[["sample_id", "subgroup", "label", "verdict", "confidence", "technique"]],
        hide_index=True,
        use_container_width=True,
    )
    if rows.empty:
        return
    sid = st.selectbox("Apri campione", rows.sample_id)
    r = rows[rows.sample_id == sid].iloc[0]
    left, right = st.columns([3, 2])
    with left:
        if dossier_path(sid).exists():
            show_dossier(load_dossier(sid))
    with right:
        st.markdown(f"**Etichetta vera:** {r.label} · **verdetto:** {r.verdict}")
        st.write(r.reasoning)
        for e in r.evidence:
            st.markdown(f"- {e}")
