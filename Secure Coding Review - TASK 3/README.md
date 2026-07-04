# Secure Coding Review — Flask Notes & Login App

Internship Project 3: Secure Coding Review, performed as part of a
Cybersecurity & Networking internship. This repo contains a small,
intentionally vulnerable Flask application, the security findings from
auditing it, and a fully remediated version.

## What's in this repo

| Path | Description |
|---|---|
| `vulnerable_app/app.py` | Original sample app containing 8 intentional vulnerabilities |
| `fixed_app/app.py` | Remediated version — Bandit-clean |
| `bandit_report.txt` | Raw Bandit static analysis output (before fixes) |
| `SECURITY_REPORT.md` / `.docx` | Full audit report: methodology, findings, CWE references, remediation, recommendations |

## Methodology

- **Manual review** of every route against the OWASP Top 10 (2021)
- **Static analysis** with [Bandit](https://bandit.readthedocs.io/)
- **Dependency review** of `requirements.txt`

## Key findings (see full report for details)

1. Hardcoded secret key
2. Weak password hashing (MD5, unsalted)
3. SQL Injection (string-built queries)
4. Broken access control / IDOR
5. Reflected XSS (unescaped output)
6. Unrestricted file upload
7. Debug mode enabled + bound to all interfaces
8. Outdated dependency pin

All 8 were fixed in `fixed_app/`. Re-running Bandit against the fixed code
returns **zero issues**.

## Running the scan yourself

```bash
pip install bandit
bandit -r vulnerable_app/app.py -f txt
bandit -r fixed_app/app.py -f txt
```

## Tech stack

Python 3 · Flask · SQLite · Bandit (static analysis) · Werkzeug security
utilities (password hashing, secure filenames)

---
*Educational sample project — the vulnerable app is intentionally insecure
and must never be deployed or exposed to a network.*
