"""Tests for the secrets scanner."""

from __future__ import annotations

from pathlib import Path

from pipeline_armor.findings import Severity
from pipeline_armor.scanners.secrets import SecretsScanner, shannon_entropy

def write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p

def test_detects_aws_key(tmp_path: Path) -> None:
    # Build the AKIA pattern at runtime so GitHub's push-protection scanner
    # doesn't see a contiguous literal in this test file.
    fake = "AK" + "IAQ7XYZ123ABCD4567"
    write(tmp_path, "config.py", f'AWS = "{fake}"\n')
    findings = SecretsScanner().scan(tmp_path)
    rules = {f.rule for f in findings}
    assert "aws_access_key_id" in rules

def test_detects_github_pat(tmp_path: Path) -> None:
    fake = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    write(tmp_path, "deploy.sh", f'TOKEN="{fake}"\n')
    findings = SecretsScanner().scan(tmp_path)
    assert any(f.rule == "github_pat" and f.severity == Severity.HIGH for f in findings)

def test_detects_stripe_live_key_critical(tmp_path: Path) -> None:
    # sk_live_* pattern, constructed at runtime to avoid GitHub push-protection
    # flagging this very test file.
    fake = "sk_" + "live_" + ("a" * 24)
    write(tmp_path, "billing.py", f"K = '{fake}'\n")
    findings = SecretsScanner().scan(tmp_path)
    assert any(f.rule == "stripe_live_key" and f.severity == Severity.CRITICAL for f in findings)

def test_skips_low_entropy_placeholder(tmp_path: Path) -> None:
    # generic_password_assignment has min_entropy=3 — 'aaaaaaaa' should NOT fire.
    write(tmp_path, "demo.py", 'password = "aaaaaaaa"\n')
    findings = SecretsScanner().scan(tmp_path)
    assert not any(f.rule == "generic_password_assignment" for f in findings)

def test_no_findings_in_clean_repo(tmp_path: Path) -> None:
    write(tmp_path, "main.py", "def hello():\n    return 'world'\n")
    findings = SecretsScanner().scan(tmp_path)
    assert findings == []

def test_entropy_ordering() -> None:
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("a8x!Z3qF")
    assert shannon_entropy("") == 0.0
