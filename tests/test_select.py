import random
from collections import Counter

from argo.dataset.select import diverse_order


def test_cap_applies_to_first_pass_and_keeps_everything():
    cands = [("a", "2025-01-01")] * 5 + [("b", "2025-02-01")] * 5
    cands = [(f"{n}{i}", d) for i, (n, d) in enumerate(cands)]
    out = diverse_order(cands, lambda c: c[1], random.Random(1), max_per_date=2)
    assert sorted(out) == sorted(cands)
    assert Counter(d for _, d in out[:4]) == {"2025-01-01": 2, "2025-02-01": 2}


def test_deterministic_with_seed():
    cands = [(str(i), f"2025-01-{i % 28 + 1:02d}") for i in range(100)]
    a = diverse_order(cands, lambda c: c[1], random.Random(7), 2)
    b = diverse_order(cands, lambda c: c[1], random.Random(7), 2)
    assert a == b
