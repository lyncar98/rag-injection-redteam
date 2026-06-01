"""
CLI: run the red-team suite against a target and gate on a pass-rate threshold.

Usage:
    python -m redteam.run --target vulnerable
    python -m redteam.run --target hardened --threshold 1.0
    python -m redteam.run --target hardened --report report.md

Exit code is non-zero if the pass rate is below the threshold, so this can gate CI.
"""

from __future__ import annotations

import argparse
import sys

from redteam import run_suite
from redteam.corpus.attacks import ATTACKS

TARGETS = {}


def _load_targets():
    from targets.reference import (
        vulnerable_target,
        partially_hardened_target,
        hardened_target,
    )
    TARGETS["vulnerable"] = vulnerable_target
    TARGETS["partial"] = partially_hardened_target
    TARGETS["hardened"] = hardened_target
    # To test your own system, import and register it here:
    # from targets.adapter import my_target
    # TARGETS["mine"] = my_target


def main(argv: list[str] | None = None) -> int:
    _load_targets()
    p = argparse.ArgumentParser(description="Indirect prompt injection red-team harness")
    p.add_argument("--target", choices=sorted(TARGETS), default="hardened")
    p.add_argument("--threshold", type=float, default=1.0,
                   help="Minimum pass rate to exit 0 (default 1.0 = no leaks allowed).")
    p.add_argument("--report", help="Optional path to write the Markdown report.")
    args = p.parse_args(argv)

    report = run_suite(TARGETS[args.target], ATTACKS)
    rendered = report.render()
    print(rendered)

    if args.report:
        with open(args.report, "w") as f:
            f.write(rendered + "\n")

    if report.pass_rate < args.threshold:
        print(f"\nFAIL: pass rate {report.pass_rate:.0%} "
              f"< threshold {args.threshold:.0%}", file=sys.stderr)
        return 1
    print(f"\nPASS: pass rate {report.pass_rate:.0%} "
          f">= threshold {args.threshold:.0%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
