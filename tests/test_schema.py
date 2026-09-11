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
        id="a@1.0.1",
        name="a",
        version="1.0.1",
        prev_version="1.0.0",
        label="benign",
        subgroup="benigno_popolare",
        date="2025-03-01",
        split="test",
        source="npm",
        archive_path="cache/tarballs/a-1.0.1.tgz",
        sha256="00",
        fingerprint="ff",
    )
    assert Sample.model_validate_json(s.model_dump_json()) == s
