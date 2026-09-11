import math
import warnings
from collections.abc import Sequence

import numpy as np

from argo.config import SEED


def bootstrap_ci(
    truth: Sequence[bool],
    pred: Sequence[bool | None],
    n_boot: int = 1000,
    seed: int = SEED,
    alpha: float = 0.05,
) -> dict[str, tuple[float, float]]:
    t_all = np.asarray(truth, dtype=bool)
    p_all = np.array([-1 if p is None else int(p) for p in pred])
    idx = np.random.default_rng(seed).integers(0, len(t_all), size=(n_boot, len(t_all)))
    t, p = t_all[idx], p_all[idx]
    invalid = p < 0
    tp = ((p == 1) & t).sum(axis=1)
    fp = (((p == 1) | invalid) & ~t).sum(axis=1)
    fn = (((p == 0) | invalid) & t).sum(axis=1)
    tn = ((p == 0) & ~t).sum(axis=1)
    with np.errstate(divide="ignore", invalid="ignore"):
        rates = {
            "recall": tp / (tp + fn),
            "fpr": fp / (fp + tn),
            "precision": tp / (tp + fp),
            "f1": 2 * tp / (2 * tp + fp + fn),
        }
    out: dict[str, tuple[float, float]] = {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)  # all-nan slices → nan interval
        for name, values in rates.items():
            out[name] = (
                float(np.nanquantile(values, alpha / 2)),
                float(np.nanquantile(values, 1 - alpha / 2)),
            )
    return out


def mcnemar_exact(correct_a: Sequence[bool], correct_b: Sequence[bool]) -> tuple[int, int, float]:
    b = sum(a and not bb for a, bb in zip(correct_a, correct_b, strict=True))
    c = sum(bb and not a for a, bb in zip(correct_a, correct_b, strict=True))
    n = b + c
    if n == 0:
        return b, c, 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2**n
    return b, c, min(1.0, 2 * tail)
