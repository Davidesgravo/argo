from collections.abc import Callable, Sequence
from dataclasses import dataclass

NAN = float("nan")


@dataclass(frozen=True)
class Counts:
    tp: int
    fp: int
    tn: int
    fn: int
    invalid: int

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


def confusion(truth: Sequence[bool], pred: Sequence[bool | None]) -> Counts:
    tp = fp = tn = fn = invalid = 0
    for t, p in zip(truth, pred, strict=True):
        if p is None:
            invalid += 1
            fn, fp = (fn + 1, fp) if t else (fn, fp + 1)
        elif p and t:
            tp += 1
        elif p:
            fp += 1
        elif t:
            fn += 1
        else:
            tn += 1
    return Counts(tp, fp, tn, fn, invalid)


def _ratio(num: int, den: int) -> float:
    return NAN if den == 0 else num / den


def recall(c: Counts) -> float:
    return _ratio(c.tp, c.tp + c.fn)


def fpr(c: Counts) -> float:
    return _ratio(c.fp, c.fp + c.tn)


def precision(c: Counts) -> float:
    return _ratio(c.tp, c.tp + c.fp)


def f1(c: Counts) -> float:
    return _ratio(2 * c.tp, 2 * c.tp + c.fp + c.fn)


RATES: dict[str, Callable[[Counts], float]] = {
    "recall": recall,
    "fpr": fpr,
    "precision": precision,
    "f1": f1,
}
