import pandas as pd
import streamlit as st

from argo.extract.build import dossier_path, load_dossier
from argo.ui.common import corpus_or_warn, show_dossier


def render() -> None:
    st.title("Dataset")
    corpus = corpus_or_warn()
    if corpus is None:
        return
    df = pd.DataFrame([s.model_dump() for s in corpus])
    c1, c2 = st.columns(2)
    splits = c1.multiselect("Split", ["test", "history"], default=["test", "history"])
    subgroups = sorted(df.subgroup.unique())
    chosen = c2.multiselect("Sottogruppo", subgroups, default=subgroups)
    view = df[df.split.isin(splits) & df.subgroup.isin(chosen)]
    k1, k2, k3 = st.columns(3)
    k1.metric("Campioni", len(view))
    k2.metric("Malevoli", int((view.label == "malicious").sum()))
    k3.metric("Benigni", int((view.label == "benign").sum()))
    st.dataframe(pd.crosstab(view.subgroup, view.split), use_container_width=True)
    cols = [
        "id",
        "label",
        "subgroup",
        "split",
        "history_set",
        "date",
        "prev_version",
        "source",
        "pair_id",
    ]
    st.dataframe(view[cols], hide_index=True, use_container_width=True)
    sid: str | None = st.selectbox("Dossier del campione", view.id)
    if sid and dossier_path(sid).exists():
        show_dossier(load_dossier(sid))
    elif sid:
        st.info("Dossier non ancora generato: esegui `argo dossier build`.")
