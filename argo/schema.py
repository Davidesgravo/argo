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
    rag_neighbor_labels: list[str] | None  # P3 only, aligned with rag_neighbors
    extractor_version: str
    temperature: float
    seed: int
    num_ctx: int
    num_predict: int  # value used on the final attempt
    attempts: int
    raw_output: str
    valid: bool
    output: Verdict | None
    latency_s: float  # summed over attempts
    tokens_in: int  # prompt tokens of the final attempt
    tokens_out: int  # summed over attempts
    timestamp: str
