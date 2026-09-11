import math

from argo.eval.metrics import confusion, f1, fpr, precision, recall
from argo.eval.stats import bootstrap_ci, mcnemar_exact

TRUTH = [True, True, True, False, False, False]


def test_confusion_counts_invalid_as_wrong():
    c = confusion(TRUTH, [True, None, False, False, None, True])
    assert (c.tp, c.fn, c.tn, c.fp, c.invalid) == (1, 2, 1, 2, 2) and c.n == 6


def test_rates():
    c = confusion(TRUTH, [True, True, False, False, False, True])
    assert recall(c) == 2 / 3 and fpr(c) == 1 / 3 and precision(c) == 2 / 3 and f1(c) == 2 / 3


def test_undefined_rates_are_nan():
    c = confusion([False, False], [False, False])
    assert math.isnan(recall(c)) and math.isnan(precision(c)) and fpr(c) == 0.0


def test_bootstrap_perfect_classifier():
    ci = bootstrap_ci(TRUTH * 5, TRUTH * 5, n_boot=200)
    assert ci["f1"] == (1.0, 1.0) and ci["fpr"] == (0.0, 0.0)


def test_bootstrap_interval_contains_point_estimate():
    pred = [True, True, False, False, False, True] * 10
    lo, hi = bootstrap_ci(TRUTH * 10, pred, n_boot=500)["recall"]
    assert lo < 2 / 3 < hi


def test_mcnemar():
    a = [True] * 6 + [False] * 4
    b = [False] * 6 + [False] * 4
    assert mcnemar_exact(a, b) == (6, 0, 2 / 64)
    assert mcnemar_exact(a, a)[2] == 1.0
