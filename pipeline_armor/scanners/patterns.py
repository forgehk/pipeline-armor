"""AST-based pattern scanner for Python source files.

Flags well-known insecure patterns by walking the AST. AST-based detection is
much harder to fool than regex (an attacker can't break it with whitespace
or comments).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from ..findings import Finding, Severity

@dataclass(frozen=True)
class PatternRule:
    name: str
    severity: Severity
    description: str

RULES: dict[str, PatternRule] = {
    "eval_call":            PatternRule("eval_call",            Severity.HIGH,   "eval() on user input enables RCE"),
    "exec_call":            PatternRule("exec_call",            Severity.HIGH,   "exec() on user input enables RCE"),
    "pickle_load":          PatternRule("pickle_load",          Severity.HIGH,   "pickle.load(s) on untrusted data is RCE"),
    "subprocess_shell":     PatternRule("subprocess_shell",     Severity.HIGH,   "subprocess shell=True enables injection"),
    "requests_verify_off":  PatternRule("requests_verify_off",  Severity.HIGH,   "requests verify=False disables TLS validation"),
    "weak_hash_md5":        PatternRule("weak_hash_md5",        Severity.LOW,    "MD5 is broken; use SHA-256 / bcrypt"),
    "weak_hash_sha1":       PatternRule("weak_hash_sha1",       Severity.LOW,    "SHA-1 is broken; use SHA-256 / bcrypt"),
    "sql_string_concat":    PatternRule("sql_string_concat",    Severity.HIGH,   "SQL built with string concat — SQLi risk"),
    "yaml_unsafe_load":     PatternRule("yaml_unsafe_load",     Severity.HIGH,   "yaml.load without SafeLoader is RCE"),
}

class PatternsScanner:
    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in root.rglob("*.py"):
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in path.parts):
                continue
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(src, filename=str(path))
            except (OSError, SyntaxError):
                continue
            visitor = _PatternVisitor(str(path.relative_to(root)).replace("\\", "/"))
            visitor.visit(tree)
            findings.extend(visitor.findings)
        return findings

class _PatternVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.findings: list[Finding] = []

    def _emit(self, rule_name: str, lineno: int) -> None:
        rule = RULES[rule_name]
        self.findings.append(
            Finding(
                severity=rule.severity,
                scanner="patterns",
                path=self.rel_path,
                line=lineno,
                rule=rule.name,
                message=rule.description,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # eval / exec
        if isinstance(func, ast.Name) and func.id == "eval":
            self._emit("eval_call", node.lineno)
        elif isinstance(func, ast.Name) and func.id == "exec":
            self._emit("exec_call", node.lineno)
        # pickle.load / pickle.loads
        elif isinstance(func, ast.Attribute) and func.attr in {"load", "loads"} \
                and isinstance(func.value, ast.Name) and func.value.id == "pickle":
            self._emit("pickle_load", node.lineno)
        # yaml.load without SafeLoader
        elif isinstance(func, ast.Attribute) and func.attr == "load" \
                and isinstance(func.value, ast.Name) and func.value.id == "yaml":
            if not self._is_safe_loader(node):
                self._emit("yaml_unsafe_load", node.lineno)
        # subprocess.* with shell=True
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                and func.value.id == "subprocess":
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._emit("subprocess_shell", node.lineno)
        # requests.* with verify=False
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                and func.value.id == "requests":
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self._emit("requests_verify_off", node.lineno)
        # hashlib.md5 / hashlib.sha1
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                and func.value.id == "hashlib":
            if func.attr == "md5":
                self._emit("weak_hash_md5", node.lineno)
            elif func.attr == "sha1":
                self._emit("weak_hash_sha1", node.lineno)
        # cursor.execute("SELECT ... " + var)
        elif isinstance(func, ast.Attribute) and func.attr == "execute":
            if node.args and isinstance(node.args[0], ast.BinOp) \
                    and isinstance(node.args[0].op, ast.Add):
                self._emit("sql_string_concat", node.lineno)
        self.generic_visit(node)

    @staticmethod
    def _is_safe_loader(call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg == "Loader" and isinstance(kw.value, ast.Attribute):
                return "Safe" in kw.value.attr
        return False
