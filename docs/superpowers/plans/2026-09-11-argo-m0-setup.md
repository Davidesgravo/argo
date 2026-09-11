# Argo — M0 Setup (Tasks 1-2)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Read the index `2026-09-11-argo-plan.md` (Global Constraints) first.

---

### Task 1: Project skeleton, shared schema, JSONL helpers, CLI stub

**Files:**
- Create: `pyproject.toml`, `argo/__init__.py`, `argo/config.py`, `argo/schema.py`, `argo/jsonl.py`, `argo/cli.py`, `tests/__init__.py`, `tests/test_schema.py`, `tests/test_jsonl.py`
- Delete: `argo/llm.py` (empty file left by the editor)

**Interfaces:**
- Produces: every constant in `argo/config.py`; all models in `argo/schema.py`; `read_jsonl`, `append_jsonl`, `write_jsonl`, `read_models`; `argo.cli.main(argv: list[str] | None = None) -> int` with a subparser registry later tasks extend.

- [ ] **Step 1: Branch and environment**

```bash
cd /Users/davidesgravo/Desktop/argo
git checkout -b feat/poc
rm -f argo/llm.py
/opt/homebrew/bin/python3.11 -m venv .venv
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "argo"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
  "httpx>=0.27",
  "pydantic>=2.7",
  "numpy>=1.26",
  "pandas>=2.2",
  "matplotlib>=3.8",
  "streamlit>=1.38",
]

[project.optional-dependencies]
dev = ["pytest>=8", "mypy>=1.10", "ruff>=0.5", "pandas-stubs"]

[project.scripts]
argo = "argo.cli:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["argo*"]

[tool.setuptools.package-data]
"argo.prompts" = ["templates/*.txt", "examples/*.json"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.mypy]
python_version = "3.11"
ignore_missing_imports = true
check_untyped_defs = true

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]
ignore = ["E501"]  # line length is handled by `ruff format`
```

Run: `.venv/bin/pip install -q -e ".[dev]"`
Expected: exits 0.

- [ ] **Step 3: Write `argo/__init__.py` and `argo/config.py`**

`argo/__init__.py`:

```python
"""Argo: small local LLMs as npm supply-chain defenders (thesis PoC)."""
```

`argo/config.py`:

```python
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ARGO_DATA_DIR", ROOT / "data"))
RESULTS_DIR = Path(os.environ.get("ARGO_RESULTS_DIR", ROOT / "results"))

QUARANTINE_DIR = DATA_DIR / "quarantine"
CACHE_DIR = DATA_DIR / "cache"
DOSSIER_DIR = DATA_DIR / "dossiers"
RAG_DIR = DATA_DIR / "rag"
CORPUS_PATH = DATA_DIR / "corpus.jsonl"
RUNS_DIR = RESULTS_DIR / "runs"
BASELINE_PATH = RESULTS_DIR / "baseline.json"
BENCH_PATH = RESULTS_DIR / "bench.json"

DATADOG_GIT_URL = "https://github.com/DataDog/malicious-software-packages-dataset.git"
DATADOG_RAW_URL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main"
DATADOG_REPO_DIR = CACHE_DIR / "datadog-repo"
DATADOG_ZIP_PASSWORD = b"infected"
NPM_REGISTRY_URL = "https://registry.npmjs.org"
OLLAMA_URL = "http://localhost:11434"

CUTOFF_DATE = "2025-01-01"
TEST_END_DATE = "2026-08-31"
SEED = 2026

EXTRACTOR_VERSION = "1"
DOSSIER_TOKEN_BUDGET = 2000

LLM_OPTIONS: dict[str, float | int] = {
    "temperature": 0.0,
    "seed": SEED,
    "num_ctx": 8192,
    "num_predict": 300,
}
RETRY_NUM_PREDICT = 600
MODELS = ["qwen2.5-coder:7b", "qwen3:4b", "gemma3:4b", "llama3.2:3b"]
CONTROL_MODEL: str | None = None  # chosen in Task 17
THINKING_MODELS = {"qwen3:4b"}
EMBED_MODEL = "nomic-embed-text"
PROMPT_IDS = ["p0", "p1", "p2", "p3"]
```

- [ ] **Step 4: Write the failing tests**

`tests/__init__.py`: empty file.

`tests/test_schema.py`:

```python
import pytest
from pydantic import ValidationError

from argo.schema import Sample, Verdict


def test_verdict_accepts_valid_output():
    v = Verdict.model_validate_json(
        '{"evidence": ["new preinstall"], "reasoning": "x", "technique": "lifecycle_script",'
        ' "verdict": "malicious", "confidence": 0.9}'
    )
    assert v.verdict == "malicious"


@pytest.mark.parametrize(
    "patch",
    ['"confidence": 1.5', '"technique": "magic"', '"verdict": "maybe"'],
)
def test_verdict_rejects_out_of_schema(patch):
    base = {
        "confidence": '"confidence": 0.5',
        "technique": '"technique": "none"',
        "verdict": '"verdict": "benign"',
    }
    key = patch.split(":")[0].strip('"')
    base[key] = patch
    raw = '{"evidence": [], "reasoning": "r", ' + ", ".join(base.values()) + "}"
    with pytest.raises(ValidationError):
        Verdict.model_validate_json(raw)


def test_sample_roundtrip():
    s = Sample(
        id="a@1.0.1", name="a", version="1.0.1", prev_version="1.0.0", label="benign",
        subgroup="benigno_popolare", date="2025-03-01", split="test", source="npm",
        archive_path="cache/tarballs/a-1.0.1.tgz", sha256="00", fingerprint="ff",
    )
    assert Sample.model_validate_json(s.model_dump_json()) == s
```

`tests/test_jsonl.py`:

```python
from argo.jsonl import append_jsonl, read_jsonl, read_models, write_jsonl
from argo.schema import Hit


def test_append_then_read(tmp_path):
    p = tmp_path / "sub" / "x.jsonl"
    append_jsonl(p, {"a": 1})
    append_jsonl(p, {"a": 2})
    assert read_jsonl(p) == [{"a": 1}, {"a": 2}]


def test_read_missing_file_is_empty(tmp_path):
    assert read_jsonl(tmp_path / "none.jsonl") == []


def test_write_replaces_and_read_models(tmp_path):
    p = tmp_path / "h.jsonl"
    write_jsonl(p, [{"category": "exec", "path": "a.js", "line": 1, "snippet": "eval("}])
    write_jsonl(p, [{"category": "network", "path": "b.js", "line": 2, "snippet": "fetch("}])
    hits = read_models(p, Hit)
    assert [h.category for h in hits] == ["network"]
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `.venv/bin/pytest -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'argo.schema'`.

- [ ] **Step 6: Write `argo/schema.py`**

```python
from typing import Literal

from pydantic import BaseModel, Field

Label = Literal["malicious", "benign"]
Subgroup = Literal[
    "nato_malevolo",
    "compromesso",
    "shai_hulud_w1",
    "shai_hulud_w2",
    "shai_hulud_w3",
    "benigno_popolare",
    "benigno_difficile",
    "pulito_accoppiato",
]
Split = Literal["history", "test"]
HistorySet = Literal["base", "w1", "w2"]
Technique = Literal[
    "lifecycle_script",
    "credential_theft",
    "obfuscated_payload",
    "exfiltration",
    "self_propagation",
    "dependency_confusion",
    "typosquatting",
    "none",
    "other",
]


class Sample(BaseModel):
    id: str
    name: str
    version: str
    prev_version: str | None
    label: Label
    subgroup: Subgroup
    date: str
    split: Split
    history_set: HistorySet | None = None
    source: Literal["datadog", "npm"]
    archive_path: str  # relative to DATA_DIR
    prev_archive_path: str | None = None  # relative to DATA_DIR
    sha256: str
    fingerprint: str
    pair_id: str | None = None


class Hit(BaseModel):
    category: str
    path: str
    line: int
    snippet: str


class FileChange(BaseModel):
    path: str
    status: Literal["added", "removed", "modified"]
    size: int


class FileProfile(BaseModel):
    path: str
    size: int
    lines: int
    avg_line_len: float
    max_line_len: int
    entropy: float
    hex_identifiers: int
    long_encoded_strings: int
    minified: bool
    obfuscated: bool
    binary: bool


class DepChange(BaseModel):
    field: str
    name: str
    old: str | None
    new: str
    non_registry: bool


class Dossier(BaseModel):
    sample_id: str
    extractor_version: str
    text: str
    lifecycle: dict[str, str]
    lifecycle_changed: bool
    dep_changes: list[DepChange]
    outside_files: list[str]
    target_profiles: list[FileProfile]
    hits: list[Hit]
    changes: list[FileChange]
    truncated: bool
    est_tokens: int


class Verdict(BaseModel):
    evidence: list[str]
    reasoning: str
    technique: Technique
    verdict: Label
    confidence: float = Field(ge=0.0, le=1.0)


class Prediction(BaseModel):
    run_id: str
    sample_id: str
    model: str
    model_digest: str
    prompt_id: str
    prompt_hash: str
    rag_index: str | None
    rag_neighbors: list[str] | None
    extractor_version: str
    temperature: float
    seed: int
    num_ctx: int
    raw_output: str
    valid: bool
    output: Verdict | None
    latency_s: float
    tokens_in: int
    tokens_out: int
    timestamp: str
```

- [ ] **Step 7: Write `argo/jsonl.py`**

```python
import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

M = TypeVar("M", bound=BaseModel)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def read_models(path: Path, cls: type[M]) -> list[M]:
    return [cls.model_validate(r) for r in read_jsonl(path)]


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.replace(path)
```

- [ ] **Step 8: Write `argo/cli.py` (stub other tasks extend)**

```python
import argparse
from collections.abc import Callable

Handler = Callable[[argparse.Namespace], int]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argo", description="Argo supply-chain defender PoC")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="print version").set_defaults(func=_version)
    return parser


def _version(_: argparse.Namespace) -> int:
    print("argo 0.1.0")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Handler = args.func
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
```

Later tasks add subcommands inside `build_parser()` in the same style: `p = sub.add_parser(...)`, arguments, `p.set_defaults(func=_handler)`, with the handler importing its module lazily.

- [ ] **Step 9: Run the gate**

Run: `.venv/bin/ruff format argo tests && .venv/bin/pytest -q && .venv/bin/mypy argo && .venv/bin/ruff check --fix argo tests && .venv/bin/argo version`
Expected: all tests pass, mypy "Success", ruff "All checks passed!", prints `argo 0.1.0`.

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml argo tests
git commit -m "Add project skeleton, shared schema and JSONL helpers"
```

---

### Task 2: Ollama runtime and models

**Files:**
- Create: `docs/models.md`

**Interfaces:**
- Produces: a running Ollama at `http://localhost:11434` with `qwen2.5-coder:7b`, `qwen3:4b`, `gemma3:4b`, `llama3.2:3b`, `nomic-embed-text` pulled; `docs/models.md` with release and training-cutoff dates for the thesis.

- [ ] **Step 1: Install and start Ollama**

```bash
brew install ollama
brew services start ollama
curl -s http://localhost:11434/api/version
```

Expected: JSON with `"version":"0.33.x"`.

- [ ] **Step 2: Pull models (one at a time, ~15 GB total)**

```bash
for m in llama3.2:3b gemma3:4b qwen3:4b qwen2.5-coder:7b nomic-embed-text; do ollama pull "$m" || break; done
ollama list
```

Expected: the five models listed with their digests.

- [ ] **Step 3: Smoke test structured output and `think: false`**

```bash
curl -s http://localhost:11434/api/chat -d '{
  "model": "qwen3:4b", "stream": false, "think": false,
  "messages": [{"role": "user", "content": "Is 2+2=4? Answer JSON."}],
  "format": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
  "options": {"temperature": 0, "seed": 2026, "num_ctx": 8192, "num_predict": 50}
}' | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['message']['content'], d.get('prompt_eval_count'), d.get('eval_count'))"
```

Expected: `{"ok": true}` (or similar valid JSON) followed by two integers. If Ollama rejects `think` for a model, remove that model from `THINKING_MODELS` in `argo/config.py`.

- [ ] **Step 4: Document release and cutoff dates**

For each model, read its model card (ollama.com/library/<name> and the upstream Hugging Face card) and write `docs/models.md`:

```markdown
# Modelli usati

| Tag Ollama | Digest | Rilascio | Cutoff dichiarato | Fonte |
|---|---|---|---|---|
| llama3.2:3b | <from `ollama list`> | 2024-09 | <from card> | <URL> |
| gemma3:4b | ... | 2025-03 | ... | ... |
| qwen3:4b | ... | 2025-04 | ... | ... |
| qwen2.5-coder:7b | ... | 2024-09 | ... | ... |
| nomic-embed-text | ... | — | — (embedding) | ... |
```

Fill every cell from the cards; if a card states no cutoff, write "non dichiarato" and the release date is the upper bound. Flag any model released after 2025-09-01 (it could know Shai-Hulud) — it must not be in `MODELS`.

- [ ] **Step 5: Commit**

```bash
git add docs/models.md
git commit -m "Document local models and training cutoffs"
```
