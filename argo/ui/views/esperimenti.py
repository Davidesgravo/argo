import json
from datetime import datetime, timedelta

import streamlit as st

from argo.config import BENCH_PATH, MODELS, PROMPT_IDS, RUNS_DIR
from argo.eval.report import SUBGROUPS
from argo.run.benchmark import estimate_seconds, fmt_duration
from argo.run.launch import list_runs, start_run
from argo.run.runner import RunConfig, plan_jobs
from argo.ui.common import PROMPT_LABELS, corpus_or_warn, model_choices

MODES = {"standard": "Standard", "rq3": "RQ3 · storico crescente (solo P3, ondate W2/W3)"}


@st.fragment(run_every=5)
def _progress() -> None:
    runs = list_runs(RUNS_DIR)
    if not runs:
        st.caption("Nessun run ancora.")
    for r in runs:
        frac = r["done"] / r["total"] if r["total"] else 0.0
        state = "in corso" if r["running"] else ("completato" if frac >= 1 else "fermo")
        st.progress(min(frac, 1.0), text=f"{r['run_id']} · {r['done']}/{r['total']} · {state}")


def render() -> None:
    st.title("Esperimenti")
    corpus = corpus_or_warn()
    if corpus is None:
        return
    with st.form("nuovo_run"):
        run_id = st.text_input("ID del run", value=f"run-{datetime.now():%Y%m%d-%H%M}")
        models = st.multiselect("Modelli", model_choices(), default=MODELS)
        mode = st.radio("Modalità", list(MODES), format_func=lambda m: MODES[m], horizontal=True)
        prompts = st.multiselect(
            "Prompt", PROMPT_IDS, default=PROMPT_IDS, format_func=lambda p: PROMPT_LABELS[p]
        )
        subgroups = st.multiselect("Sottogruppi (vuoto = tutti)", list(SUBGROUPS))
        submitted = st.form_submit_button("Calcola stima")
    if submitted:
        st.session_state["cfg"] = RunConfig(
            run_id=run_id.strip(),
            models=models,
            prompts=["p3"] if mode == "rq3" else prompts,
            mode=mode,
            subgroups=subgroups or None,
        )
    cfg = st.session_state.get("cfg")
    if cfg is not None:
        jobs = plan_jobs(cfg, corpus)
        bench = json.loads(BENCH_PATH.read_text()) if BENCH_PATH.exists() else {}
        est = estimate_seconds(jobs, bench)
        if est is None:
            st.info(
                f"{len(jobs)} inferenze · durata sconosciuta (esegui `argo bench` per questi modelli)"
            )
        else:
            end = datetime.now() + timedelta(seconds=est)
            st.info(
                f"{len(jobs)} inferenze · durata stimata {fmt_duration(est)} · fine prevista alle {end:%H:%M}"
            )
        if (RUNS_DIR / cfg.run_id).exists():
            st.warning("Esiste già un run con questo ID: verrà ripreso da dove si era fermato.")
        if st.button("Avvia run", type="primary", disabled=not jobs):
            pid = start_run(cfg)
            st.success(
                f"Run avviato in background (pid {pid}). Log: results/runs/{cfg.run_id}/run.log"
            )
            del st.session_state["cfg"]
    st.subheader("Run")
    _progress()
