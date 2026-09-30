"""CVSS 3.1 base score from a vector string (FIRST specification, section 7)."""

from __future__ import annotations

import math

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    # The specification's Roundup avoids floating-point artefacts such as 4.000001 -> 4.1.
    whole = round(value * 100000)
    return whole / 100000.0 if whole % 10000 == 0 else (math.floor(whole / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError("vector must start with CVSS:3.1/")
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    for key in _REQUIRED:
        valid = _PR["U"] if key == "PR" else {"U": 0, "C": 0} if key == "S" else _WEIGHTS[key]
        if metrics.get(key) not in valid:
            raise ValueError(f"missing or invalid metric {key}")
    return metrics


def base_score(vector: str) -> float:
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - _WEIGHTS["C"][m["C"]]) * (1 - _WEIGHTS["I"][m["I"]]) * (
        1 - _WEIGHTS["A"][m["A"]]
    )
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = (
        8.22
        * _WEIGHTS["AV"][m["AV"]]
        * _WEIGHTS["AC"][m["AC"]]
        * _PR[m["S"]][m["PR"]]
        * _WEIGHTS["UI"][m["UI"]]
    )
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10))


def rating(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"
    return "CRITICAL"
