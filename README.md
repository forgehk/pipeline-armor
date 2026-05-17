# pipeline-armor

> A drop-in security gate for GitHub Actions. Scans for **leaked secrets**, **vulnerable dependencies**, and **insecure code patterns** — and fails the build before the bad commit lands on `main`.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg)]() [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF.svg)]()

---

## What it does

`pipeline-armor` is a small Python package + GitHub Actions workflow that you bolt onto any repo to enforce a security baseline at PR time. It runs three scanners and decides — based on a policy file — whether the PR is allowed to merge.

| Scanner | Catches |
|---|---|
| **secrets** | AWS keys, GitHub PATs, Stripe keys, Slack tokens, generic high-entropy strings, hard-coded API keys |
| **deps** | Dependencies with known CVEs (wraps `pip-audit`) |
| **patterns** | `eval()`, `exec()`, `pickle.load`, `shell=True`, `verify=False`, SQL string concatenation, weak hashes |

The decision is driven by `pipeline-armor.yaml` in your repo root. You can pin severity thresholds, allowlist specific findings, and require human sign-off on policy changes.

---

## Quick start

### As a GitHub Action

Drop `.github/workflows/security-gate.yml` (in this repo) into your project. On every PR you'll get a checks-tab entry that **fails the build if any high-severity finding fires.**

### From the CLI

```bash
pip install pipeline-armor
pipeline-armor scan ./my-repo
```

Output looks like:

```
pipeline-armor scan: ./my-repo

  [HIGH] secrets       app/config.py:14    aws_access_key_id
  [HIGH] patterns      app/db.py:88        sql_string_concat
  [MED ] deps          requirements.txt    requests==2.20.0 (CVE-2018-18074)
  [LOW ] patterns      utils/hash.py:12    weak_hash_md5

  3 findings >= MEDIUM. Policy: fail at MEDIUM. ❌ BLOCKED.
```

---

## How it works

```
                   ┌──────────────────┐
                   │  pipeline-armor  │
                   │       CLI        │
                   └────────┬─────────┘
                            │
        ┌───────────────────┼────────────────────┐
        ▼                   ▼                    ▼
  ┌──────────┐        ┌──────────┐         ┌──────────┐
  │ secrets  │        │   deps   │         │ patterns │
  │ scanner  │        │ scanner  │         │ scanner  │
  └────┬─────┘        └────┬─────┘         └────┬─────┘
       │                   │                    │
       └───────────┬───────┴────────────────────┘
                   ▼
          ┌─────────────────┐
          │  policy engine  │  ← pipeline-armor.yaml
          │  pass / fail?   │
          └────────┬────────┘
                   ▼
          ┌─────────────────┐
          │  GitHub Actions │
          │   pass / fail   │
          └─────────────────┘
```

Each scanner is independent and returns a list of `Finding(severity, scanner, file, line, rule, message)`. The policy engine collapses them into a single pass/fail decision against your config.

---

## Policy file (`pipeline-armor.yaml`)

```yaml
version: 1

# Fail the build if any finding meets or exceeds this severity.
fail_at: medium

# Per-scanner overrides
scanners:
  secrets:
    enabled: true
    extra_patterns:
      - name: internal_api_key
        regex: 'DARKFORGE_[A-Z0-9]{32}'
        severity: high
  deps:
    enabled: true
    ignore_cves:
      - CVE-2019-11324    # documented, mitigated downstream
  patterns:
    enabled: true

# Allowlist specific findings (by rule + path + line)
allowlist:
  - rule: weak_hash_md5
    path: legacy/checksum.py
    line: 42
    reason: "Legacy checksum, not used for security"
    expires: 2026-12-31
```

---

## Demo: the vulnerable app this catches

The `demo/` directory contains `vulnerable_app.py` — a tiny Flask app that intentionally tripwires every scanner:

- A hard-coded AWS key
- A `pickle.loads` on user input
- A SQL query built with string concat
- An MD5 password hash
- `requests` pinned to a known-vulnerable version

Run `pipeline-armor scan demo/` and watch all three scanners light up.

---

## Why this is interesting

Most teams pay for SaaS tools (Snyk, Semgrep Cloud, GitGuardian) to do exactly this. `pipeline-armor` is a learning project that shows the **anatomy** of those tools — pluggable scanners, a policy engine, severity thresholds, allowlists, and CI integration — in ~600 lines of Python you can read in a sitting.

For my own purposes, it's the security half of a DevSecOps toolkit I'm building out as I level up for AppSec / DevSecOps roles.

---

## Roadmap

- [x] Regex secret scanner with 12+ rule patterns
- [x] `pip-audit` wrapper for dependency CVEs
- [x] AST-based pattern scanner (Python)
- [x] YAML policy engine with allowlist
- [x] GitHub Actions integration
- [ ] Semgrep rule pack integration
- [ ] Container scan (Trivy wrapper)
- [ ] SARIF output for GitHub code scanning tab
- [ ] JS/TS pattern scanner

---

## License

[MIT](LICENSE)

---

*Built by [@forgehk](https://github.com/forgehk) — [DarkForge AI](https://darkforgeai.com)*
