#!/usr/bin/env python3
"""Coverage gate: line coverage > 90% AND branch coverage == 100%.

Reads a ``coverage.json`` produced by ``coverage json`` and fails the build
when either requirement is unmet. Run order in CI:

    pytest                      # writes .coverage (branch coverage on)
    coverage json -o coverage.json
    python scripts/check_coverage.py coverage.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

LINE_FLOOR = 90.0  # strictly greater than this
BRANCH_REQUIRED = 100.0


def pct(covered: int, total: int) -> float:
    return 100.0 if total == 0 else 100.0 * covered / total


def check(path: Path) -> int:
    data = json.loads(path.read_text())
    totals = data.get("totals", {})
    line = pct(totals.get("covered_lines", 0), totals.get("num_statements", 0))
    branch = pct(totals.get("covered_branches", 0), totals.get("num_branches", 0))

    print(f"line coverage:    {line:.2f}% (require > {LINE_FLOOR:.0f}%)")
    print(f"branch coverage:  {branch:.2f}% (require {BRANCH_REQUIRED:.0f}%)")

    failures = []
    if line <= LINE_FLOOR:
        failures.append(f"line coverage {line:.2f}% is not > {LINE_FLOOR:.0f}%")
    if branch != BRANCH_REQUIRED:
        failures.append(f"branch coverage {branch:.2f}% is not {BRANCH_REQUIRED:.0f}%")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("coverage gate passed")
    return 0


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path("coverage.json")
    if not path.exists():
        print(f"FAIL: {path} not found — run `coverage json -o {path}` first")
        return 2
    return check(path)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
