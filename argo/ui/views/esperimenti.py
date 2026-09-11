import json
from datetime import datetime, timedelta
from pathlib import Path

import streamlit as st

from argo.config import BENCH_PATH, MODELS, PROMPT_IDS, RUNS_DIR
from argo.eval.report import SUBGROUPS
from argo.run.benchmark import estimate_seconds, fmt_duration
from argo.run.launch import is_running, is_valid_run_id, list_runs, start_run
from argo.run.runner import RunConfig, plan_jobs
from argo.ui.common import PROMPT_LABELS, corpus_or_warn, model_choices

MODES = {"standard": "Standard", "rq3": "RQ3 · storico crescente (solo P3, ondate W2/W3)"}


def start_problem(run_dir: Path, n_jobs: int) -> str | None:
    """Why the run cannot be started now, or None."""
    if n_jobs == 0:
        return "Nessuna inferenza da eseguire con questa selezione."
    if is_running(run_dir):
        return "Un run con questo ID è già in corso: attendi che finisca oppure scegli un altro ID."
    return None


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
        run_id = run_id.strip()
        if not is_valid_run_id(run_id):
            st.error(
                "ID del run non valido: usa lettere, cifre, '-', '_' o '.' (max 64 caratteri)."
            )
            st.session_state.pop("cfg", None)
        else:
            st.session_state["cfg"] = RunConfig(
                run_id=run_id,
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
        problem = start_problem(RUNS_DIR / cfg.run_id, len(jobs))
        if problem:
            st.warning(problem)
        elif (RUNS_DIR / cfg.run_id).exists():
            st.warning(
                "Esiste già un run con questo ID: verrà ripreso da dove si era fermato. "
                "Se template, esempi few-shot, corpus, indici RAG, estrattore o codice della "
                "pipeline sono cambiati il run verrà rifiutato: in quel caso usa un nuovo ID."
            )
        if st.button("Avvia run", type="primary", disabled=problem is not None):
            pid = start_run(cfg)
            st.success(
                f"Run avviato in background (pid {pid}). Log: results/runs/{cfg.run_id}/run.log"
            )
            del st.session_state["cfg"]
    st.subheader("Run")
    _progress()
