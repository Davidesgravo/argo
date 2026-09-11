import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from argo.config import PROMPT_IDS
from argo.schema import Label, Verdict

TEMPLATE_DIR = Path(__file__).parent / "templates"


@dataclass(frozen=True)
class Example:
    sample_id: str
    label: Label
    excerpt: str
    answer: Verdict | None = None


@dataclass(frozen=True)
class RenderedPrompt:
    system: str
    user: str
    prompt_hash: str


def _read(name: str) -> str:
    return (TEMPLATE_DIR / name).read_text(encoding="utf-8").strip()


def compress_dossier(text: str, max_tokens: int = 500) -> str:
    head = text.split("\n## 4.", 1)[0].rstrip()
    limit = max_tokens * 4
    return head if len(head) <= limit else head[:limit].rstrip() + "\n[...]"


def format_examples(examples: Sequence[Example]) -> str:
    blocks = []
    for i, ex in enumerate(examples, 1):
        block = f"### Example {i} — label: {ex.label.upper()}\n{ex.excerpt}"
        if ex.answer is not None:
            block += f"\nExpected answer: {ex.answer.model_dump_json()}"
        blocks.append(block)
    return "\n\n".join(blocks)


def render(prompt_id: str, dossier_text: str, examples: Sequence[Example] = ()) -> RenderedPrompt:
    if prompt_id not in PROMPT_IDS:
        raise ValueError(f"unknown prompt {prompt_id!r}")
    if prompt_id in ("p2", "p3") and not examples:
        raise ValueError(f"{prompt_id} needs examples")
    system = _read("system.txt")
    template = _read(f"{prompt_id}.txt")
    fields = {
        "instructions": _read("instructions.txt"),
        "taxonomy": _read("taxonomy.txt"),
        "examples": format_examples(examples),
        "dossier": dossier_text,
    }
    user = template.format(**fields)
    # The hash covers every fixed part of the prompt; P3 neighbours vary per sample and are
    # recorded separately in the prediction, so they are excluded.
    fixed = [system, template, fields["instructions"]]
    if prompt_id != "p0":
        fixed.append(fields["taxonomy"])
    if prompt_id == "p2":
        fixed.append(fields["examples"])
    digest = hashlib.sha256("\n".join(fixed).encode()).hexdigest()[:16]
    return RenderedPrompt(system=system, user=user, prompt_hash=digest)
