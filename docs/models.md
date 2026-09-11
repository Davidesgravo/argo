# Modelli usati

| Tag Ollama | Digest | Rilascio | Cutoff dichiarato | Fonte |
|---|---|---|---|---|
| llama3.2:3b | a80c4f17acd5 | 2024-09 (25/09/2024) | Dicembre 2023 ("The pretraining data has a cutoff of December 2023.") | [Meta Llama 3.2 Model Card](https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/MODEL_CARD.md); [Meta AI blog, 25/09/2024](https://ai.meta.com/blog/llama-3-2-connect-2024-vision-edge-mobile-devices/) |
| gemma3:4b | a2af6cc3eb7f | 2025-03 (12/03/2025) | Agosto 2024 ("The knowledge cutoff date for the training data was August 2024.") | [Gemma 3 Model Card — Google AI for Developers](https://ai.google.dev/gemma/docs/core/model_card_3); [Hugging Face — Gemma 3 launch](https://huggingface.co/blog/gemma3) |
| qwen3:4b | 359d7dd4bcda | 2025-04 (29/04/2025) | non dichiarato | [Qwen Team blog — Qwen3: Think Deeper, Act Faster, 29/04/2025](https://qwenlm.github.io/blog/qwen3/); [Qwen3-4B — Hugging Face](https://huggingface.co/Qwen/Qwen3-4B) |
| qwen2.5-coder:7b | dae161e27b0e | 2024-09 (19/09/2024) | non dichiarato | [Qwen Team blog — Qwen2.5-Coder: Code More, Learn More!, 19/09/2024](https://qwenlm.github.io/blog/qwen2.5-coder/); [Qwen2.5-Coder-7B-Instruct — Hugging Face](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct) |
| nomic-embed-text | 0a109f422b47 | — | — (embedding) | [ollama.com/library/nomic-embed-text](https://ollama.com/library/nomic-embed-text); [Introducing Nomic Embed — Nomic AI blog, 01/02/2024](https://home.nomic.ai/blog/posts/local-nomic-embed) |

Nessun modello in MODELS è rilasciato dopo il 2025-09-01.

## Note sulle fonti

- **llama3.2:3b**: la data di rilascio (25/09/2024, Meta Connect 2024) e il cutoff (dicembre 2023) sono dichiarati esplicitamente nel model card ufficiale di Meta, valido per tutte le taglie 1B/3B della famiglia Llama 3.2.
- **gemma3:4b**: rilascio confermato dal blog Hugging Face (12/03/2025). Il cutoff di agosto 2024 è dichiarato nel model card ufficiale Google ("Gemma 3 model card", ultimo aggiornamento 14/08/2025), valido per l'intera famiglia Gemma 3.
- **qwen3:4b**: rilascio annunciato nel blog ufficiale Qwen (29/04/2025). Né il blog di lancio né la scheda Hugging Face dichiarano un cutoff esplicito per la famiglia Qwen3; una discussione ufficiale su GitHub (QwenLM/Qwen3#1093) conferma che il team non ha pubblicato una data di cutoff certa, quindi si riporta "non dichiarato" e si usa la data di rilascio come limite superiore.
- **qwen2.5-coder:7b**: il blog di lancio (19/09/2024) conferma che le taglie 1.5B e 7B erano disponibili al lancio (32B "coming soon"). Nessuna fonte ufficiale (blog o scheda Hugging Face) dichiara un cutoff esplicito, quindi "non dichiarato"; la data di rilascio è il limite superiore.
- **nomic-embed-text**: modello di embedding, non ha un "cutoff" nel senso di conoscenza fattuale interrogabile; non applicabile (annotato come nel template del brief). Rilasciato inizialmente il 01/02/2024 da Nomic AI (versione usata in Ollama: v1.5).
