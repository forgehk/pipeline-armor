"""pipeline-armor CLI entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .findings import Finding
from .policy import Policy
from .scanners import PatternsScanner, SecretsScanner

def _scan(root: Path, policy_path: Path) -> int:
    policy = Policy.from_file(policy_path)

    findings: list[Finding] = []
    if "secrets" in policy.enabled_scanners:
        findings.extend(SecretsScanner().scan(root))
    if "patterns" in policy.enabled_scanners:
        findings.extend(PatternsScanner().scan(root))
    # deps scanner intentionally not invoked here — wraps `pip-audit`
    # and lives in `pipeline_armor.scanners.deps` (TODO).

    findings.sort(key=lambda f: (-f.severity, f.scanner, f.path, f.line))

    passed, blocking, allowed = policy.evaluate(findings)

    print(f"pipeline-armor scan: {root}\n")
    if not findings:
        print("  No findings. ✅\n")
        return 0

    for f in findings:
        marker = "  " if f in allowed else " !"
        print(f"{marker}{f.to_row()}")

    print()
    print(f"  {len(blocking)} blocking, {len(allowed)} allowlisted (policy: fail at {policy.fail_at.label}).")
    if passed:
        print("  ✅ PASSED.")
        return 0
    print("  ❌ BLOCKED.")
    return 1

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pipeline-armor",
        description="Security gate for CI: secrets, deps, code patterns.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository tree.")
    scan.add_argument("path", type=Path, help="Repository root.")
    scan.add_argument(
        "--policy",
        type=Path,
        default=Path("pipeline-armor.yaml"),
        help="Policy file (default: ./pipeline-armor.yaml).",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _scan(args.path.resolve(), args.policy)
    return 1

if __name__ == "__main__":
    sys.exit(main())
