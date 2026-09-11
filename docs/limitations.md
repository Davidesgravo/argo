# Limiti noti (per il capitolo della tesi)

Limiti metodologici e tecnici emersi nella revisione finale del PoC. Vanno dichiarati nel
capitolo accanto ai risultati. I numeri che dipendono dal corpus vanno riverificati dopo
l'ultima ricostruzione (`argo dataset build`, `argo dossier build`).

## Dataset

- **Confondente "pacchetto nuovo" contro "aggiornamento".** Nel test set solo i campioni
  malevoli sono "pacchetto nuovo" (tutti i `nato_malevolo` e un `compromesso`) oppure
  "versione precedente non disponibile" (un campione W2, che infatti non ha una coppia
  pulita); tutti i benigni sono aggiornamenti con diff. Un
  modello può quindi separare le classi guardando solo la riga `TYPE:` del dossier. Le
  metriche per sottogruppo (`compromesso` e Shai-Hulud, che sono aggiornamenti, contro i
  benigni) servono a neutralizzarlo e vanno messe in primo piano.
- **Coppie pulite vecchie.** Al momento della revisione 5 versioni `pulito_accoppiato` sono
  state pubblicate nel 2023-24 (`react-jsonschema-form-conditionals` 0.3.17,
  `@postman/postman-collection-fork` 4.3.2, `@kvytech/cli` 0.0.6, `@antv/l7-draw` 3.1.5,
  `@antv/lite-insight` 2.1.1): sono precedenti al cutoff 2025-01-01 e potrebbero comparire
  nei dati di addestramento dei modelli. Sono comunque la versione immediatamente precedente
  a quella infetta, quindi il confronto appaiato resta valido.
- **Impronta degenere per pacchetti senza contenuto (M5).** L'impronta di deduplicazione
  ignora `package.json`, README e licenze: due pacchetti che contengono solo quei file e gli
  stessi `scripts` hanno la stessa impronta e uno dei due viene scartato anche se diverso.
- **File oltre 64 MB.** I lettori degli archivi saltano i file più grandi di 64 MB: non
  compaiono né nell'elenco dei file del dossier né nel conteggio della dimensione totale.

## Estrattore e baseline

- **Indicatori sensibili alle maiuscole.** Le espressioni regolari degli indicatori sono
  case-sensitive: varianti come `npm_token` o `Child_Process` non vengono segnalate.
- **W1 minificato, non offuscato.** Il `bundle.js` di Shai-Hulud W1 è un bundle minificato:
  il profilo lo riporta come `minified=yes, obfuscated=no`, quindi la regola "file offuscato
  invocato dallo script" non scatta e la tassonomia ("minified is not the same as
  obfuscated") può spingere i modelli verso il benigno.
- **Calibrazione della baseline.** La soglia è scelta su tutto lo storico, cioè `storico_base`
  più i campioni W1 e W2 usati per RQ3. Con il solo `storico_base` la soglia risulta la stessa
  (3,5), ma il capitolo deve dichiarare su quali campioni è stata calibrata.

## Modelli

- **Taglia del modello di controllo.** `granite4.2:8b` ha 8,8 miliardi di parametri, circa il
  25% in più di `qwen2.5-coder:7b`, il più grande dei modelli principali (vedi
  `docs/models.md`). Un risultato migliore su Shai-Hulud può dipendere anche dalla capacità del
  modello e non solo dall'esposizione all'attacco durante l'addestramento.

## Prompt P3

- **Famiglie di campagna euristiche.** P3 tiene al più un vicino per famiglia, definita come
  scope npm oppure prefisso del nome prima del primo `-`. Cloni della stessa campagna con nomi
  diversi (per esempio `gita-…`, `budi-…`, `andi-…`, oppure i nomi `…_z3n`) restano famiglie
  distinte e possono occupare più posti fra i vicini.
