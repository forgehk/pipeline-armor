"""Shared types for scanner findings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

class Severity(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[name.upper()]

    @property
    def label(self) -> str:
        return self.name

@dataclass(frozen=True)
class Finding:
    severity: Severity
    scanner: str           # 'secrets' | 'deps' | 'patterns'
    path: str              # file path relative to repo root
    line: int              # 0 if not applicable (e.g. deps)
    rule: str              # short rule identifier
    message: str           # human-readable description

    def key(self) -> tuple[str, str, int]:
        """Allowlist key — (rule, path, line)."""
        return (self.rule, self.path, self.line)

    def to_row(self) -> str:
        sev = f"[{self.severity.label:<4}]"
        loc = f"{self.path}:{self.line}" if self.line else self.path
        return f"  {sev} {self.scanner:<10} {loc:<30} {self.rule}"
