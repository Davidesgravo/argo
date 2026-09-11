## Controllo di contaminazione: sottogruppo Shai-Hulud (P1 e P3 base)

| model | prompt_id | recall_shai_hulud | n_shai | fpr_pulito_accoppiato | n_pairs |
|---|---|---|---|---|---|
| gemma3:4b | p1 | 1.000 | 15.000 | 0.500 | 14.000 |
| gemma3:4b | p3 | 1.000 | 15.000 | 0.286 | 14.000 |
| granite4.2:8b | p1 | 1.000 | 15.000 | 0.214 | 14.000 |
| granite4.2:8b | p3 | 0.933 | 15.000 | 0.214 | 14.000 |
| llama3.2:3b | p1 | 0.933 | 15.000 | 0.214 | 14.000 |
| llama3.2:3b | p3 | 0.867 | 15.000 | 0.071 | 14.000 |
| qwen2.5-coder:7b | p1 | 0.933 | 15.000 | 0.357 | 14.000 |
| qwen2.5-coder:7b | p3 | 0.933 | 15.000 | 0.357 | 14.000 |
| qwen3:4b | p1 | 0.933 | 15.000 | 0.286 | 14.000 |
| qwen3:4b | p3 | 0.933 | 15.000 | 0.286 | 14.000 |

## Controllo di contaminazione: RQ3 (storico crescente)

| model | wave | n_infected | n_pairs | recall_base | recall_grown | fpr_pairs_base | fpr_pairs_grown |
|---|---|---|---|---|---|---|---|
| granite4.2:8b | shai_hulud_w2 | 5 | 4 | 1.000 | 1.000 | 0.250 | 0.250 |
| granite4.2:8b | shai_hulud_w3 | 5 | 5 | 0.800 | 0.800 | 0.200 | 0.200 |
