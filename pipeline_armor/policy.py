"""Policy engine — reads pipeline-armor.yaml and decides pass/fail."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .findings import Finding, Severity

@dataclass
class AllowlistEntry:
    rule: str
    path: str
    line: int
    reason: str = ""

    def matches(self, f: Finding) -> bool:
        return f.rule == self.rule and f.path == self.path and (
            self.line == 0 or self.line == f.line
        )

@dataclass
class Policy:
    fail_at: Severity = Severity.MEDIUM
    enabled_scanners: set[str] = field(default_factory=lambda: {"secrets", "deps", "patterns"})
    allowlist: list[AllowlistEntry] = field(default_factory=list)

    @classmethod
    def default(cls) -> "Policy":
        return cls()

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        if not path.exists():
            return cls.default()
        with path.open() as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        p = cls.default()
        if "fail_at" in data:
            p.fail_at = Severity.from_name(data["fail_at"])
        scanners = data.get("scanners", {}) or {}
        for name, conf in scanners.items():
            if isinstance(conf, dict) and conf.get("enabled") is False:
                p.enabled_scanners.discard(name)
        for entry in data.get("allowlist", []) or []:
            p.allowlist.append(
                AllowlistEntry(
                    rule=entry["rule"],
                    path=entry["path"],
                    line=int(entry.get("line", 0)),
                    reason=entry.get("reason", ""),
                )
            )
        return p

    def evaluate(self, findings: list[Finding]) -> tuple[bool, list[Finding], list[Finding]]:
        """Return (passed, blocking_findings, allowlisted_findings)."""
        blocking: list[Finding] = []
        allowed: list[Finding] = []
        for f in findings:
            if any(a.matches(f) for a in self.allowlist):
                allowed.append(f)
                continue
            if f.severity >= self.fail_at:
                blocking.append(f)
        return (len(blocking) == 0, blocking, allowed)
