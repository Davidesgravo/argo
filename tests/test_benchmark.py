from argo.run.benchmark import bench_samples, estimate_seconds, fmt_duration
from argo.run.runner import Job
from argo.schema import Sample


def _s(i, label, split="test"):
    return Sample(
        id=i,
        name=i,
        version="1",
        prev_version=None,
        label=label,
        subgroup="nato_malevolo",
        date="2025-01-01",
        split=split,
        source="npm",
        archive_path="x",
        sha256="0",
        fingerprint=i,
    )


def test_bench_samples_alternate_labels():
    samples = [
        _s("m1", "malicious"),
        _s("m2", "malicious"),
        _s("b1", "benign"),
        _s("b2", "benign"),
        _s("h", "benign", split="history"),
    ]
    assert [s.id for s in bench_samples(samples, 3)] == ["m1", "b1", "m2"]


def test_estimate():
    data = {"a|p1": {"mean_s": 10.0}, "a|p3": {"mean_s": 20.0}}
    jobs = [
        Job("x", "a", "p0", None),
        Job("x", "a", "p2", None),
        Job("x", "a", "p3", "storico_base"),
    ]
    assert estimate_seconds(jobs, data) == 10.0 + 13.0 + 20.0
    assert estimate_seconds([Job("x", "b", "p0", None)], data) is None


def test_fmt_duration():
    assert fmt_duration(7500) == "2h 05m" and fmt_duration(59) == "0h 01m"
