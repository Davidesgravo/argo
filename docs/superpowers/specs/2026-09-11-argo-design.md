# Argo — Design del proof of concept

**Data:** 2026-09-11
**Contesto:** caso di studio per la tesi magistrale LM-32 (sicurezza informatica, ciclo di vita del software e impatto dell'AI).
**Tempo disponibile:** 2-3 settimane, esperimenti inclusi, esclusa la scrittura del capitolo.

---

## 1. Obiettivo e domande di ricerca

Argo è un difensore sperimentale della supply chain npm: dato un pacchetto (o l'aggiornamento di una dipendenza), modelli linguistici piccoli, open source ed eseguiti in locale decidono se è malevolo. Il prodotto finale è un **esperimento misurabile e riproducibile** più una **interfaccia** per mostrarlo; non è uno strumento di produzione.

- **RQ1** — Modelli piccoli locali (3-7B) rilevano pacchetti npm malevoli con un tasso di falsi positivi accettabile? Fanno meglio di una baseline a regole?
- **RQ2** — Quanto incide il prompt? Scala P0 → P3 (sez. 7).
- **RQ3** — Alimentare i modelli con lo storico degli attacchi aiuta a riconoscere un attacco nuovo? Caso di studio Shai-Hulud con storico crescente per ondata.
- **Controllo** — Un modello rilasciato dopo Shai-Hulud va meglio perché lo conosce dall'addestramento? (contaminazione)

## 2. Perimetro

**Dentro:** solo ecosistema npm; analisi statica del contenuto del pacchetto; 4 modelli + 1 di controllo via Ollama; 4 varianti di prompt; metriche con intervalli di confidenza; UI Streamlit.

**Fuori:** PyPI e altri ecosistemi; esecuzione o installazione dei pacchetti (analisi dinamica); fine-tuning; blocco reale in CI; analisi di metadati del maintainer o del registry oltre versioni e date.

## 3. Architettura

Nessun database né servizio: ogni passo è un comando CLI che legge e scrive file. CLI e UI condividono gli stessi file.

```
fonti (DataDog, registry npm) ──► dataset ──► data/corpus.jsonl
                                                   │
                            extract ◄──────────────┘
                            (dossier + score baseline) ──► data/dossiers/
                                                   │
          prompts (P0-P3) + indici RAG ──► run ────┴──► results/runs/<run_id>/predictions.jsonl
                                                   │
                                          eval ────┴──► results/metrics.csv, tables/, figures/
                                                   │
                                          ui (Streamlit) legge data/ e results/
```

### Struttura del progetto

```
argo/
  pyproject.toml
  argo/
    config.py            percorsi, costanti, versione estrattore
    cli.py               entrypoint `argo`
    dataset/             datadog.py · npm_registry.py · select.py · corpus.py
    extract/             archive.py · diff.py · indicators.py · profile.py · dossier.py · baseline.py
    llm/                 ollama.py
    prompts/             templates/p0..p3 · examples/ (few-shot P2) · render.py · rag.py
    run/                 runner.py · benchmark.py
    eval/                metrics.py · stats.py · report.py
    ui/                  app.py · pages/
  data/                  corpus.jsonl · quarantine/ (zip DataDog cifrati) · cache/ (tgz dal registry) · dossiers/ · rag/
  results/               runs/ · metrics.csv · tables/ · figures/
  tests/
```

### Comandi CLI

| Comando | Effetto |
|---|---|
| `argo dataset build` | scarica e seleziona i campioni, scrive `corpus.jsonl` |
| `argo dossier build` | genera il dossier e lo score baseline di ogni campione |
| `argo baseline calibrate` | sceglie la soglia della baseline sullo storico |
| `argo rag index` | costruisce gli indici di embedding (sez. 7) |
| `argo bench` | 20 pacchetti per modello, registra la velocità reale |
| `argo run --models … --prompts … [--index …] [--subset …]` | esegue un run, riprendibile |
| `argo eval` | metriche, tabelle, grafici |
| `argo ui` | avvia Streamlit |

## 4. Dataset

### Fonti
- **Malevoli:** [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset), `samples/npm/`, categorie `malicious_intent` e `compromised_lib`. Ogni campione è uno zip cifrato (password `infected`) che contiene `package/` (i file del pacchetto) e `package_info-*.json` (metadati del registry). Il nome del file riporta la data di scoperta. Licenza Apache-2.0.
- **Benigni e versioni pulite:** registry npm (`registry.npmjs.org`).

### Composizione del test set (110 pacchetti)

| Sottogruppo | N | Criterio |
|---|---|---|
| `nato_malevolo` | ~28 | `malicious_intent`, scoperti dal 2025-01-01, deduplicati |
| `compromesso` | ~12 | `compromised_lib` non Shai-Hulud, scoperti dal 2025-01-01 |
| `shai_hulud_w1` | 5 | ondata del 2025-09 (es. `@ctrl/tinycolor`, `ngx-bootstrap`) |
| `shai_hulud_w2` | 5 | ondata del 2025-11 (es. `@posthog/*`, `@asyncapi/*`, `@zapier/*`) |
| `shai_hulud_w3` | 5 | Mini Shai-Hulud, 2026-05 (`@tanstack/*`, `@antv/*`) |
| `benigno_popolare` | 20 | pacchetti molto usati con release nel 2025-26 |
| `benigno_difficile` | 20 | pacchetti legittimi con hook di installazione (es. `esbuild`, `sharp`, `puppeteer`, `husky`, `core-js`, `@swc/core`, `protobufjs`) |
| `pulito_accoppiato` | 15 | versione immediatamente precedente di ciascun pacchetto Shai-Hulud del test |

Totale: 55 malevoli, 55 benigni. Il rapporto fra `nato_malevolo` e `compromesso` dipende dalla disponibilità dopo la deduplicazione ed è riportato nel capitolo.

I 5 campioni per ondata vengono da **pacchetti ospite diversi**. Il limite di 5 impedisce che i cloni del worm dominino le metriche complessive.

### Storico
- **`storico_base`**: ~40 malevoli npm scoperti **prima del 2025-01-01**, deduplicati e con tecniche varie, più ~10 benigni che non compaiono nel test. È la fonte degli esempi di P2 e dell'indice RAG di P3.
- **Estensioni per RQ3:** `storico_w1` = base + 5 campioni W1 **diversi** da quelli di test (altri pacchetti ospite della stessa ondata); `storico_w1w2` = `storico_w1` + 5 campioni W2 diversi da quelli di test.

### Regole
- **Deduplicazione:** l'impronta di un campione è lo sha256 dell'elenco ordinato degli hash dei file, esclusi `package.json`, README e licenze, più gli `scripts` normalizzati di `package.json`. Per ogni impronta si tiene un solo campione.
- **Aggiornamento dove possibile:** ogni campione con una versione precedente sul registry (malevolo o benigno) viene analizzato come diff rispetto a quella. I pacchetti senza versione precedente sono marcati "pacchetto nuovo".
- **Metadati neutri:** da `package_info-*.json` si usano solo versioni e date. Nessun altro campo entra nel dossier.

### Record di `corpus.jsonl`

```
id, name, version, prev_version | null, label (malicious|benign), subgroup,
discovered_at | published_at, split (history|test), history_set (base|w1|w2|null),
source (datadog|npm), archive_path, sha256, fingerprint, pair_id | null
```

## 5. Estrattore, dossier e baseline

### Input
Il contenuto dell'archivio della versione in esame e, se esiste, di quella precedente. È **letto in memoria**: nessun file viene estratto su disco e nulla viene eseguito o installato.

### Dossier
Testo strutturato, formato identico per tutti i campioni, budget di **~2.000 token** (stima: caratteri / 4). Si riempie in ordine di priorità; se il budget si esaurisce, si tronca dal fondo e si annota cosa è stato omesso.

1. **Script di lifecycle** (`preinstall`, `install`, `postinstall`, `prepare`): testo completo e diff rispetto alla versione precedente.
2. **File invocati da quegli script:** contenuto integrale se sotto ~2 KB, altrimenti un profilo (dimensione, lunghezza media e massima delle righe, entropia di Shannon, identificatori `_0x…`, stringhe base64 o hex lunghe, esito "offuscato sì/no").
3. **Indicatori** nei file nuovi o modificati (tutti i file, se è un pacchetto nuovo), con `file:riga` e un frammento di ≤200 caratteri, raggruppati per categoria:
   - `network`: URL verso host diversi dal registry, `fetch`/`https.request`/`axios`, webhook, IP letterali
   - `exec`: `child_process`, `eval`, `new Function`, `vm.run*`
   - `credentials`: `process.env`, `.npmrc`, `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`, `~/.ssh`, `trufflehog`
   - `obfuscation`: identificatori `_0x`, stringhe lunghe ad alta entropia
   - `propagation`: `npm publish`, `PUT` sul registry, API GitHub per creare repo o workflow, scrittura di `.github/workflows`
   - `runtime_download`: download di runtime o binari (`bun.sh`, `curl | sh`)
4. **Cambiamenti di file** rispetto alla versione precedente (aggiunti, rimossi, modificati), con le dimensioni.
5. **Metadati:** nome, versione, versione precedente, "aggiornamento" o "pacchetto nuovo", numero di file, dimensione totale.

I file sopra una soglia di qualche MB non vengono letti per intero: vengono solo profilati. I file binari compaiono solo con nome e dimensione.

### Baseline a regole
Score = somma pesata delle categorie di indicatori presenti. Pesi fissati a mano e documentati, per esempio uno script di lifecycle nuovo che invoca un file offuscato pesa molto. La **soglia** si sceglie massimizzando F1 **sullo storico**, mai sul test.

## 6. Modelli

Tutti via **Ollama**, quantizzazione Q4, un modello alla volta in memoria (M1 Pro, 16 GB).

| Modello (tag Ollama) | Ruolo |
|---|---|
| `qwen2.5-coder:7b` | specialista del codice, il più grande |
| `qwen3:4b` | generalista recente, modalità "thinking" disattivata |
| `gemma3:4b` | seconda famiglia |
| `llama3.2:3b` | limite inferiore |
| *modello recente, da scegliere* | controllo di contaminazione, solo sul sottogruppo Shai-Hulud |

- I primi quattro sono rilasciati prima di settembre 2025. **La data di cutoff di ciascuno va verificata** e riportata nel capitolo.
- Il modello di controllo deve essere rilasciato dopo novembre 2025; lo si sceglie in M3 fra quelli disponibili su Ollama.
- Parametri fissi: `temperature=0`, `seed=2026`, **`num_ctx=8192` esplicito** (il default di Ollama tronca l'input in silenzio), `num_predict` limitato a ~300.
- Embedding per RAG: un modello di embedding locale via Ollama (es. `nomic-embed-text`), da confermare in M3.

## 7. Prompt e output

### Output
JSON vincolato da schema tramite il parametro `format` di Ollama. L'ordine dei campi è voluto (prima le prove, per ultimo il verdetto):

```json
{
  "evidence":   ["string"],
  "reasoning":  "string, max 3 frasi",
  "technique":  "lifecycle_script | credential_theft | obfuscated_payload | exfiltration | self_propagation | dependency_confusion | typosquatting | none | other",
  "verdict":    "malicious | benign",
  "confidence": 0.0
}
```

### Varianti

| ID | Contenuto |
|---|---|
| **P0** zero-shot | ruolo minimo, dossier, domanda, schema |
| **P1** checklist | P0 + tassonomia degli attacchi npm (scritta a mano dallo storico e dalla letteratura) + avvertenze sui falsi positivi (hook legittimi per compilare o scaricare binari) |
| **P2** few-shot | P1 + 4 esempi fissi da `storico_base` (2 malevoli di tecniche diverse, 1 benigno comune, 1 benigno difficile), ciascuno con il dossier compresso e la risposta JSON attesa scritta a mano |
| **P3** RAG | P1 + i 3 campioni più simili dell'indice scelto (similarità coseno sugli embedding del dossier), ciascuno con il dossier compresso (sezioni 1-3, ≤500 token) e la sua etichetta |

- I prompt sono in **inglese**.
- Le parti fisse (istruzioni, tassonomia, esempi P2) stanno in testa, così Ollama può riusarne l'elaborazione.
- I template sono file versionati; l'hash del template entra in ogni predizione.
- Nessun adattamento per singolo modello.

### Indici RAG
`storico_base`, `storico_w1`, `storico_w1w2` (sez. 4). P3 standard usa `storico_base`.

## 8. Esecuzione e riproducibilità

### Piano dei run

| Run | Modelli | Prompt | Campioni | Inferenze |
|---|---|---|---|---|
| Principale | 4 | P0-P3 (P3 con `storico_base`) | 110 | 1.760 |
| RQ3 storico crescente | 4 | P3 con `storico_w1` su W2, `storico_w1w2` su W3 | 10 infetti + 10 puliti accoppiati | 80 |
| Controllo contaminazione | modello recente | P1, P3 base, P3 crescente | 30 (sottogruppo Shai-Hulud) | ~90 |

Totale ~1.930 inferenze. Stima, da verificare con `argo bench`: **4-5 ore**, eseguibili a blocchi per modello.

### Runner
- Ogni modello si carica una volta sola e processa tutti i suoi campioni.
- Ogni predizione viene aggiunta a `predictions.jsonl` appena calcolata. Al riavvio, il run salta le coppie (campione, modello, prompt, indice) già presenti.
- Prima di partire mostra la stima di durata, basata sui dati di `argo bench`.

### Record di predizione

```
run_id, sample_id, model, model_digest, prompt_id, prompt_hash, rag_index | null,
rag_neighbors | null, extractor_version, temperature, seed, num_ctx,
raw_output, valid, evidence, reasoning, technique, verdict, confidence,
latency_s, tokens_in, tokens_out, timestamp
```

## 9. Metriche e report

**Per modello × prompt**, sul totale e per sottogruppo:
- recall, tasso di falsi positivi (FPR), precision, F1
- FPR separato su `benigno_difficile` e su `pulito_accoppiato`
- recall su `nato_malevolo`, `compromesso` e ciascuna ondata Shai-Hulud
- latenza media e mediana, token in e out
- tasso di output non validi; nelle metriche principali un output non valido conta come risposta sbagliata, qualunque sia la classe

**Statistica:**
- intervalli di confidenza al 95% (bootstrap, 1.000 ricampionamenti) su recall, FPR, F1
- test di McNemar esatto per confronti appaiati fra prompt sullo stesso modello

**RQ3:** tasso di rilevamento su W2 e W3 con `storico_base` contro storico crescente, e FPR sui puliti accoppiati. Con 5 campioni per ondata è un **caso di studio qualitativo**, e il capitolo lo dichiara.

**Validità delle motivazioni:** un CSV con 20 veri positivi estratti a caso, da etichettare a mano come motivazione corretta, parziale o sbagliata.

**Output:**
- `results/metrics.csv`
- tabelle Markdown in `results/tables/`
- grafici PNG per Word in `results/figures/`: heatmap F1 modello × prompt, barre FPR, rilevamento per ondata

## 10. Interfaccia (Streamlit)

Legge `data/` e `results/`. Le pagine sono in ordine di priorità: se il tempo manca si taglia dalla quarta.

1. **Analizza pacchetto.** Input: `nome@versione` (dal registry), un `.tgz` caricato, oppure un campione del dataset. Si scelgono modello e prompt. Mostra il dossier con gli indicatori evidenziati, lo score della baseline, il verdetto (badge, confidenza, prove, motivazione) e la latenza. Il pulsante "confronta tutti i modelli" li esegue in sequenza.
2. **Risultati.** Heatmap, tabella con intervalli di confidenza, FPR, latenze, grafico per ondata, filtro per sottogruppo (incluso Shai-Hulud). Drill-down su falsi positivi e falsi negativi, con dossier e risposta del modello affiancati.
3. **Dataset.** Tabella del corpus con filtri (split, sottogruppo, ondata), conteggi, dossier di ogni campione.
4. **Esperimenti** *(tagliabile)*. Scelta di modelli, prompt e indice, stima di durata, avvio del run come processo separato (`argo run` in background), avanzamento letto da `predictions.jsonl`.

## 11. Sicurezza

- Gli zip DataDog restano cifrati in `data/quarantine/`. Il contenuto viene letto in memoria con la password e non viene mai scritto su disco in chiaro.
- Nessun pacchetto viene installato o eseguito, né nel runner né nella UI.
- I test automatici usano solo pacchetti finti costruiti nel test.
- `data/` è escluso da git.

## 12. Gestione degli errori

- Archivio corrotto, versione precedente assente dal registry, file binari: il dossier si produce comunque, con il campo interessato annotato. Un campione problematico non ferma il run.
- Output del modello non valido rispetto allo schema: un nuovo tentativo, poi `valid=false`.
- Ollama non raggiungibile o modello mancante: errore esplicito con il comando da eseguire (`ollama serve`, `ollama pull <tag>`), sia da CLI sia in UI.
- Rete verso GitHub o npm assente durante `dataset build`: i download già fatti restano in cache, il comando è ripetibile.

## 13. Test e qualità

- **Test unitari:** estrattore (pacchetti finti con `postinstall` innocuo, file ad alta entropia e righe lunghe, stringhe `NPM_TOKEN`), diff, deduplicazione e split, calibrazione della baseline, metriche e statistica (su matrici di confusione note), rendering dei prompt, recupero RAG (embedding simulati), client Ollama (HTTP simulato), ripresa del runner.
- **Gate prima di dichiarare "fatto":** `pytest`, `mypy`, `ruff` verdi.
- **UI:** verifica manuale.

## 14. Milestone

| # | Contenuto | Stima |
|---|---|---|
| M0 | Python 3.11, venv, Ollama, pull dei modelli, scheletro, gate di qualità | 0,5 g |
| M1 | Dataset: selezione DataDog, registry, deduplicazione, `corpus.jsonl` | 3 g |
| M2 | Estrattore, dossier, baseline e calibrazione | 3-4 g |
| M3 | Client Ollama, prompt P0-P3, indici RAG, runner, benchmark, scelta del modello di controllo | 3 g |
| M4 | Esecuzione dei run (notturna), metriche, tabelle, grafici | 2 g |
| M5 | UI, pagine 1-3, poi la 4 se c'è tempo | 3 g |

Ogni milestone produce qualcosa di utilizzabile da CLI prima della successiva.

## 15. Rischi e limiti noti

- **Elenco dei campioni:** l'API di GitHub tronca l'albero del repository DataDog. In M1 serve un clone parziale (`--filter=blob:none --sparse`) oppure il download mirato dei file scelti.
- **Disponibilità dopo la deduplicazione:** i `compromesso` non Shai-Hulud del 2025-26 potrebbero essere meno di 12; in quel caso si completa con `nato_malevolo` e si dichiara.
- **Confondente "pacchetto nuovo":** i nati malevoli spesso non hanno versione precedente, mentre i benigni sì. Il segnale è realistico ma va discusso; le metriche per sottogruppo (`compromesso` e Shai-Hulud contro benigni) lo neutralizzano.
- **Cutoff dei modelli:** se un modello si rivelasse addestrato su dati successivi al 2025, le sue metriche vanno interpretate come potenzialmente contaminate.
- **Numerosità:** 110 campioni danno intervalli di circa ±7-10 punti; RQ3 ha 5 campioni per ondata ed è qualitativo.
- **Velocità reale:** le stime di durata vanno confermate con `argo bench` in M3; se sono peggiori si riduce il numero di modelli nel run principale, non il test set.
