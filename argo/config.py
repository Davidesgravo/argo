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
DATADOG_RAW_URL = (
    "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main"
)
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
