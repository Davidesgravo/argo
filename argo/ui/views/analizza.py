import httpx
import streamlit as st

from argo.analyze import Fetched, analyze, fetch_from_registry, from_upload
from argo.config import CACHE_DIR, PROMPT_IDS
from argo.dataset.registry import Registry, RegistryError
from argo.extract.archive import ArchiveError
from argo.extract.baseline import score
from argo.extract.build import dossier_path, load_dossier
from argo.schema import Dossier
from argo.ui.common import (
    PROMPT_LABELS,
    baseline_threshold,
    corpus_or_warn,
    model_choices,
    ollama_problem,
    run_prediction,
    show_dossier,
    show_prediction,
)

SOURCES = ["Registry npm", "File .tgz", "Campione del dataset"]


def _obtain(source: str) -> tuple[str, Dossier] | None:
    """Returns (sample_id, dossier) after the user presses the button, else None."""
    if source == "Registry npm":
        spec = st.text_input("Pacchetto", placeholder="es. esbuild@0.25.0 oppure @scope/nome")
        if st.button("Scarica e analizza", type="primary", disabled=not spec):
            try:
                with httpx.Client(timeout=60, follow_redirects=True) as client:
                    f: Fetched = fetch_from_registry(spec, Registry(CACHE_DIR, client))
            except (ValueError, RegistryError, ArchiveError, httpx.HTTPError) as e:
                st.error(str(e))
                return None
            d, _, _ = analyze(f, baseline_threshold())
            return f"{f.name}@{f.version}", d
    elif source == "File .tgz":
        new = st.file_uploader("Versione da analizzare (.tgz)", type=["tgz"])
        old = st.file_uploader("Versione precedente (facoltativa)", type=["tgz"])
        if st.button("Analizza", type="primary", disabled=new is None) and new is not None:
            try:
                f = from_upload(new.getvalue(), old.getvalue() if old else None)
            except ArchiveError as e:
                st.error(f"Archivio non valido: {e}")
                return None
            d, _, _ = analyze(f, baseline_threshold())
            return f"{f.name}@{f.version}", d
    else:
        corpus = corpus_or_warn()
        if corpus:
            ids = [s.id for s in corpus if s.split == "test" and dossier_path(s.id).exists()]
            sid = st.selectbox("Campione", ids, format_func=lambda i: i)
            if st.button("Carica", type="primary", disabled=not sid):
                return sid, load_dossier(sid)
    return None


def render() -> None:
    st.title("Analizza pacchetto")
    st.caption("Il pacchetto viene letto in memoria: nulla viene installato o eseguito.")
    got = _obtain(st.radio("Sorgente", SOURCES, horizontal=True))
    if got is not None:
        st.session_state["analisi"] = got
    if "analisi" not in st.session_state:
        return
    sample_id, dossier = st.session_state["analisi"]
    left, right = st.columns([3, 2])
    with left:
        st.subheader(sample_id)
        show_dossier(dossier)
    with right:
        s = score(dossier)
        t = baseline_threshold()
        verdict = (
            "n/d (calibra con `argo baseline calibrate`)"
            if t is None
            else (":red[sospetto]" if s >= t else ":green[non sospetto]")
        )
        st.markdown(f"**Baseline a regole:** score {s:.1f} → {verdict}")
        models = model_choices()
        model = st.selectbox("Modello", models)
        prompt = st.selectbox("Prompt", PROMPT_IDS, format_func=lambda p: PROMPT_LABELS[p])
        compare = st.checkbox("Confronta tutti i modelli (circa 1 minuto)")
        if st.button("Chiedi al modello", type="primary"):
            problem = ollama_problem()
            if problem:
                st.error(problem)
                return
            for m in models if compare else [model]:
                with st.spinner(f"{m} sta analizzando…"):
                    p = run_prediction(sample_id, dossier, m, prompt)
                if p is not None:
                    show_prediction(p)
                    st.divider()
