"""Paired comparisons and uncertainty. Point estimates are never reported alone when n allows an interval."""

from __future__ import annotations

import math
import random
from typing import Any


def mean(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def bootstrap_mean_ci(values: list[float], *, iters: int = 2000, alpha: float = 0.05, seed: int = 0) -> dict[str, Any]:
    if not values:
        return {"n": 0, "mean": None, "low": None, "high": None}
    rng = random.Random(seed)
    n = len(values)
    if n == 1:
        return {
            "n": 1,
            "mean": values[0],
            "low": values[0],
            "high": values[0],
            "note": "A single trial has no sampling interval.",
        }
    samples = []
    for _ in range(iters):
        draw = [values[rng.randrange(n)] for _ in range(n)]
        samples.append(sum(draw) / n)
    samples.sort()
    low_index = int((alpha / 2) * (iters - 1))
    high_index = int((1 - alpha / 2) * (iters - 1))
    return {"n": n, "mean": sum(values) / n, "low": samples[low_index], "high": samples[high_index]}


def paired_delta_ci(deltas: list[float], *, iters: int = 2000, alpha: float = 0.05, seed: int = 0) -> dict[str, Any]:
    summary = bootstrap_mean_ci(deltas, iters=iters, alpha=alpha, seed=seed)
    summary["p_permutation"] = sign_flip_p(deltas)
    summary["cohens_d"] = cohens_d(deltas)
    if deltas and all(abs(value - deltas[0]) < 1e-12 for value in deltas):
        summary["variance_note"] = (
            "Within-pair variance is zero. A zero-width interval describes this deterministic "
            "policy on these inputs. It does not describe stochastic model sampling or human behavior."
        )
    return summary


def cohens_d(deltas: list[float]) -> float | None:
    if len(deltas) < 2:
        return None
    mu = sum(deltas) / len(deltas)
    var = sum((value - mu) ** 2 for value in deltas) / (len(deltas) - 1)
    if var == 0:
        return None
    return mu / math.sqrt(var)


def sign_flip_p(deltas: list[float]) -> float | None:
    if not deltas:
        return None
    if all(value == 0 for value in deltas):
        return 1.0
    n = len(deltas)
    if n > 16:
        return _sign_flip_monte_carlo(deltas)
    observed = abs(sum(deltas))
    total = 1 << n
    extreme = 0
    for mask in range(total):
        signed = 0.0
        for index, value in enumerate(deltas):
            signed += -value if mask & (1 << index) else value
        if abs(signed) + 1e-9 >= observed:
            extreme += 1
    return extreme / total


def _sign_flip_monte_carlo(deltas: list[float], iters: int = 5000, seed: int = 0) -> float:
    rng = random.Random(seed)
    observed = abs(sum(deltas))
    extreme = 0
    for _ in range(iters):
        signed = sum(value if rng.random() < 0.5 else -value for value in deltas)
        if abs(signed) + 1e-9 >= observed:
            extreme += 1
    return extreme / iters


def mcnemar_exact(discordant_a: int, discordant_b: int) -> float | None:
    """Two-sided exact McNemar p-value from the discordant cell counts."""
    n = discordant_a + discordant_b
    if n == 0:
        return 1.0
    if n > 30:
        return None
    smaller = min(discordant_a, discordant_b)
    larger = max(discordant_a, discordant_b)
    tail = 0
    for k in range(n + 1):
        if k <= smaller or k >= larger:
            tail += math.comb(n, k)
    return min(1.0, tail / (2**n))


def bonferroni(p_values: list[float | None]) -> list[float | None]:
    present = [value for value in p_values if value is not None]
    m = len(present)
    adjusted = []
    for value in p_values:
        if value is None:
            adjusted.append(None)
        else:
            adjusted.append(min(1.0, value * m))
    return adjusted


def logistic_regression(rows: list[tuple[float, int]], *, l2: float = 1.0, steps: int = 40) -> dict[str, Any]:
    """Intercept plus one predictor. `rows` are (x, y) with y in {0, 1}.

    L2 keeps coefficients finite under separation. The warning is part of the result.
    """
    if len(rows) < 4:
        return {"ok": False, "warning": "Too few rows for a logistic model."}
    positives = [y for _x, y in rows if y == 1]
    if len(positives) in {0, len(rows)}:
        return {"ok": False, "warning": "The outcome does not vary. The model was not fit."}
    xs = [row[0] for row in rows]
    ys = [row[1] for row in rows]
    # Standardize x for stable steps.
    mu = sum(xs) / len(xs)
    var = sum((value - mu) ** 2 for value in xs) / len(xs)
    scale = math.sqrt(var) or 1.0
    z = [(value - mu) / scale for value in xs]
    beta0 = 0.0
    beta1 = 0.0
    separated = _separated(z, ys)
    for _ in range(steps):
        grad0 = 0.0
        grad1 = 0.0
        h00 = l2
        h01 = 0.0
        h11 = l2
        for x, y in zip(z, ys):
            prob = 1 / (1 + math.exp(-(beta0 + beta1 * x)))
            prob = min(1 - 1e-8, max(1e-8, prob))
            weight = prob * (1 - prob)
            resid = y - prob
            grad0 += resid
            grad1 += resid * x
            h00 += weight
            h01 += weight * x
            h11 += weight * x * x
        grad0 -= l2 * beta0
        grad1 -= l2 * beta1
        det = h00 * h11 - h01 * h01
        if abs(det) < 1e-12:
            break
        beta0 += (h11 * grad0 - h01 * grad1) / det
        beta1 += (h00 * grad1 - h01 * grad0) / det
    return {
        "ok": True,
        "intercept": beta0,
        "coefficient_standardized": beta1,
        "sign": 0 if abs(beta1) < 1e-8 else (1 if beta1 > 0 else -1),
        "separated": separated,
        "warning": "Predictor and outcome are separated. The coefficient is L2-shrunk and is not a maximum-likelihood estimate."
        if separated
        else None,
    }


def _separated(xs: list[float], ys: list[int]) -> bool:
    positive = [x for x, y in zip(xs, ys) if y == 1]
    negative = [x for x, y in zip(xs, ys) if y == 0]
    if not positive or not negative:
        return True
    return max(negative) < min(positive) or max(positive) < min(negative)


def paired_binary(labels_a: list[int], labels_b: list[int]) -> dict[str, Any]:
    if len(labels_a) != len(labels_b):
        raise ValueError("Paired binary outcomes must have the same length.")
    b = sum(1 for left, right in zip(labels_a, labels_b) if left == 1 and right == 0)
    c = sum(1 for left, right in zip(labels_a, labels_b) if left == 0 and right == 1)
    return {
        "n": len(labels_a),
        "a_only": b,
        "b_only": c,
        "p_mcnemar": mcnemar_exact(b, c),
    }
