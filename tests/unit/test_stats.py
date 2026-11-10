from nymbric.experiments.stats import (
    bonferroni,
    logistic_regression,
    mcnemar_exact,
    paired_delta_ci,
    sign_flip_p,
)


def test_mcnemar_and_sign_flip_match_small_exact_values():
    assert mcnemar_exact(3, 0) == 0.25
    assert mcnemar_exact(0, 0) == 1
    assert mcnemar_exact(8, 0) < 0.05
    assert sign_flip_p([1, 1, 1]) == 0.25


def test_zero_variance_interval_is_reported_as_such():
    summary = paired_delta_ci([0.5, 0.5, 0.5], iters=100, seed=1)
    assert summary["mean"] == 0.5
    assert summary["low"] == summary["high"] == 0.5
    assert "deterministic" in summary["variance_note"]
    assert summary["cohens_d"] is None


def test_logistic_reports_separation_instead_of_a_silent_fit():
    fit = logistic_regression([(0, 0), (0, 0), (1, 1), (1, 1)])
    assert fit["ok"]
    assert fit["separated"]
    assert fit["warning"]
    assert fit["sign"] == 1
    adjusted = bonferroni([0.02, 0.03])
    assert adjusted[0] == 0.04
