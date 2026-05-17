"""Tests for the AST-based patterns scanner."""

from __future__ import annotations

from pathlib import Path

from pipeline_armor.scanners.patterns import PatternsScanner

def write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p

def test_detects_eval(tmp_path: Path) -> None:
    write(tmp_path, "a.py", "x = eval(user_input)\n")
    findings = PatternsScanner().scan(tmp_path)
    assert any(f.rule == "eval_call" for f in findings)

def test_detects_pickle_load(tmp_path: Path) -> None:
    write(tmp_path, "a.py", "import pickle\npickle.loads(data)\n")
    findings = PatternsScanner().scan(tmp_path)
    assert any(f.rule == "pickle_load" for f in findings)

def test_detects_shell_true(tmp_path: Path) -> None:
    write(tmp_path, "a.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
    findings = PatternsScanner().scan(tmp_path)
    assert any(f.rule == "subprocess_shell" for f in findings)

def test_detects_verify_false(tmp_path: Path) -> None:
    write(tmp_path, "a.py", "import requests\nrequests.get('x', verify=False)\n")
    findings = PatternsScanner().scan(tmp_path)
    assert any(f.rule == "requests_verify_off" for f in findings)

def test_detects_sql_concat(tmp_path: Path) -> None:
    write(
        tmp_path,
        "a.py",
        "def q(cur, name):\n    return cur.execute('SELECT * FROM u WHERE n=' + name)\n",
    )
    findings = PatternsScanner().scan(tmp_path)
    assert any(f.rule == "sql_string_concat" for f in findings)

def test_clean_code_no_findings(tmp_path: Path) -> None:
    write(tmp_path, "a.py", "def add(a, b):\n    return a + b\n")
    findings = PatternsScanner().scan(tmp_path)
    assert findings == []
