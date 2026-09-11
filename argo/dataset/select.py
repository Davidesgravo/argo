import random
from collections import Counter
from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")


def diverse_order(
    cands: Sequence[T], date_of: Callable[[T], str], rng: random.Random, max_per_date: int
) -> list[T]:
    """Shuffled order where at most `max_per_date` items per date come first (spreads campaigns);
    the overflow follows, so consumers can keep pulling when items get rejected."""
    shuffled = list(cands)
    rng.shuffle(shuffled)
    first: list[T] = []
    rest: list[T] = []
    per_date: Counter[str] = Counter()
    for c in shuffled:
        d = date_of(c)
        if per_date[d] < max_per_date:
            first.append(c)
            per_date[d] += 1
        else:
            rest.append(c)
    return first + rest
