"""Secret scanner.

Looks for high-confidence credential patterns in text files. Trades a bit of
false-positive risk for clear, actionable detections — every rule here maps to
a real credential format with a public structure.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..findings import Finding, Severity

@dataclass(frozen=True)
class SecretRule:
    name: str
    regex: re.Pattern[str]
    severity: Severity
    # Optional minimum entropy bits for the captured token, to suppress
    # obvious placeholders like 'AKIAIOSFODNN7EXAMPLE' from AWS docs.
    min_entropy: float = 0.0

# fmt: off
DEFAULT_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        name="aws_access_key_id",
        regex=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        severity=Severity.HIGH,
        min_entropy=3.0,
    ),
    SecretRule(
        name="aws_secret_access_key",
        regex=re.compile(r"(?i)aws(.{0,20})?(secret|sk)[\"'\s:=]+([A-Za-z0-9/+=]{40})"),
        severity=Severity.HIGH,
        min_entropy=4.0,
    ),
    SecretRule(
        name="github_pat",
        regex=re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
        severity=Severity.HIGH,
    ),
    SecretRule(
        name="github_oauth",
        regex=re.compile(r"\b(gho_[A-Za-z0-9]{36})\b"),
        severity=Severity.HIGH,
    ),
    SecretRule(
        name="github_app_token",
        regex=re.compile(r"\b(ghs_[A-Za-z0-9]{36})\b"),
        severity=Severity.HIGH,
    ),
    SecretRule(
        name="stripe_live_key",
        regex=re.compile(r"\b(sk_live_[A-Za-z0-9]{24,})\b"),
        severity=Severity.CRITICAL,
    ),
    SecretRule(
        name="stripe_test_key",
        regex=re.compile(r"\b(sk_test_[A-Za-z0-9]{24,})\b"),
        severity=Severity.MEDIUM,
    ),
    SecretRule(
        name="slack_token",
        regex=re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
        severity=Severity.HIGH,
    ),
    SecretRule(
        name="google_api_key",
        regex=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        severity=Severity.HIGH,
    ),
    SecretRule(
        name="openai_api_key",
        regex=re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b"),
        severity=Severity.HIGH,
        min_entropy=4.0,
    ),
    SecretRule(
        name="anthropic_api_key",
        regex=re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"),
        severity=Severity.HIGH,
    ),
    SecretRule(
        name="private_key_block",
        regex=re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
    ),
    SecretRule(
        name="generic_password_assignment",
        regex=re.compile(
            r"(?i)\b(password|passwd|pwd)\s*[=:]\s*[\"']([^\"'\s]{8,})[\"']"
        ),
        severity=Severity.MEDIUM,
        min_entropy=3.0,
    ),
)
# fmt: on

# File extensions we skip — binary or noisy.
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".woff", ".woff2", ".ttf", ".otf",
    ".mp3", ".mp4", ".mov", ".avi",
    ".pyc", ".pyo", ".o", ".obj", ".so", ".dll", ".exe",
    ".lock",
}

SKIP_DIRECTORIES = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

def shannon_entropy(s: str) -> float:
    """Return Shannon entropy (bits/char) of `s`.

    Used to skip obvious placeholder strings like 'AKIAIOSFODNN7EXAMPLE' which
    real credentials wouldn't share — they'd have closer-to-uniform character
    distribution.
    """
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

class SecretsScanner:
    """Scan a tree of files for credential patterns.

    Usage:
        scanner = SecretsScanner()
        findings = scanner.scan(Path("./repo"))
    """

    def __init__(self, rules: Iterable[SecretRule] = DEFAULT_RULES) -> None:
        self.rules = tuple(rules)

    def add_rule(self, rule: SecretRule) -> None:
        self.rules = self.rules + (rule,)

    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in self._iter_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self._scan_text(path.relative_to(root), text))
        return findings

    def _iter_files(self, root: Path) -> Iterable[Path]:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRECTORIES for part in path.parts):
                continue
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if path.stat().st_size > 1_000_000:  # skip huge files
                continue
            yield path

    def _scan_text(self, rel_path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        for rule in self.rules:
            for m in rule.regex.finditer(text):
                captured = m.group(m.lastindex or 0)
                if rule.min_entropy and shannon_entropy(captured) < rule.min_entropy:
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                snippet = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                out.append(
                    Finding(
                        severity=rule.severity,
                        scanner="secrets",
                        path=str(rel_path).replace("\\", "/"),
                        line=line_no,
                        rule=rule.name,
                        message=f"matched: {snippet.strip()[:80]}",
                    )
                )
        return out
