import httpx
import streamlit as st

from argo.config import BASELINE_PATH, CONTROL_MODEL, CORPUS_PATH, MODELS, RAG_DIR
from argo.dataset.build import load_corpus
from argo.extract.build import load_baseline
from argo.llm.ollama import OllamaClient, OllamaError
from argo.prompts.fewshot import FEWSHOT_PATH, load_fewshot
from argo.run.runner import Predictor
from argo.schema import Dossier, Prediction, Sample

PROMPT_LABELS = {
    "p0": "P0 · zero-shot",
    "p1": "P1 · checklist",
    "p2": "P2 · few-shot",
    "p3": "P3 · RAG sullo storico",
}


def model_choices() -> list[str]:
    return MODELS + ([CONTROL_MODEL] if CONTROL_MODEL else [])


@st.cache_data(show_spinner=False)
def load_corpus_cached() -> list[Sample]:
    return load_corpus()


def corpus_or_warn() -> list[Sample] | None:
    if not CORPUS_PATH.exists():
        st.warning("Corpus non trovato: esegui `argo dataset build`.")
        return None
    return load_corpus_cached()


_CLIENT = OllamaClient()  # no connection is opened until the first request


@st.cache_resource(show_spinner=False)
def get_predictor() -> Predictor:
    fewshot = load_fewshot() if FEWSHOT_PATH.exists() else []
    # The UI keeps its own query-embedding cache so it never writes the experiment's file.
    return Predictor(_CLIENT, fewshot, query_cache_path=RAG_DIR / "query_cache_ui.json")


def ollama_problem() -> str | None:
    try:
        _CLIENT.http.get("/api/version", timeout=3).raise_for_status()
    except httpx.HTTPError:
        return (
            "Ollama non raggiungibile: avvia `ollama serve` (oppure `brew services start ollama`)."
        )
    return None


def baseline_threshold() -> float | None:
    return float(load_baseline()["threshold"]) if BASELINE_PATH.exists() else None


def show_dossier(d: Dossier) -> None:
    st.caption(f"~{d.est_tokens} token" + (" · troncato" if d.truncated else ""))
    st.code(d.text, language="markdown")


def show_prediction(p: Prediction) -> None:
    st.markdown(f"**{p.model}** · {PROMPT_LABELS.get(p.prompt_id, p.prompt_id)}")
    if p.output is None:
        st.error("Output non valido rispetto allo schema")
        st.code(p.raw_output)
        return
    o = p.output
    badge = ":red[**MALEVOLO**]" if o.verdict == "malicious" else ":green[**BENIGNO**]"
    st.markdown(f"{badge} · confidenza {o.confidence:.2f} · tecnica `{o.technique}`")
    st.write(o.reasoning)
    for e in o.evidence:
        st.markdown(f"- {e}")
    extra = f" · vicini RAG: {', '.join(p.rag_neighbors)}" if p.rag_neighbors else ""
    st.caption(f"{p.latency_s:.1f} s · {p.tokens_in} token in / {p.tokens_out} out{extra}")


def run_prediction(
    sample_id: str, dossier: Dossier, model: str, prompt_id: str
) -> Prediction | None:
    try:
        return get_predictor().predict(
            "ui",
            sample_id,
            dossier,
            model,
            prompt_id,
            "storico_base" if prompt_id == "p3" else None,
        )
    except OllamaError as e:
        st.error(str(e))
    except FileNotFoundError:
        st.error("Indice RAG mancante: esegui `argo rag index`.")
    except ValueError:
        st.error("Esempi few-shot mancanti: esegui `argo fewshot build`.")
    return None
