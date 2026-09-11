import streamlit as st

from argo.ui.views import analizza, dataset, esperimenti, risultati

st.set_page_config(page_title="Argo", page_icon="🛡️", layout="wide")
page = st.navigation(
    [
        st.Page(
            analizza.render,
            title="Analizza pacchetto",
            icon="🔍",
            url_path="analizza",
            default=True,
        ),
        st.Page(risultati.render, title="Risultati", icon="📊", url_path="risultati"),
        st.Page(dataset.render, title="Dataset", icon="🗂️", url_path="dataset"),
        st.Page(esperimenti.render, title="Esperimenti", icon="🧪", url_path="esperimenti"),
    ]
)
page.run()
