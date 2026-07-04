# Secure Coding Review Report

**Project:** Notes & Login Flask Web Application (Sample Audit Target)
**Language:** Python 3 (Flask)
**Auditor:** Akash — Cybersecurity & Networking Intern
**Date:** July 2026
**Tools Used:** Manual code review (OWASP Top 10 methodology), Bandit v1.9.4 (static analysis)

---

## 1. Executive Summary

This report documents a secure code review conducted on a sample Flask-based
web application ("Notes & Login") that provides user registration, login,
note-taking, and file upload functionality. The review combined manual
line-by-line inspection against the OWASP Top 10 with automated static
analysis using Bandit.

**8 vulnerabilities** were identified across 7 categories, including 3 rated
**High**, 4 rated **Medium**, and 1 rated **Low** severity. All findings were
remediated in a corrected version of the application. A follow-up Bandit scan
of the remediated code returned **zero issues**, confirming the fixes.

| Metric | Value |
|---|---|
| Total findings | 8 |
| High severity | 3 |
| Medium severity | 4 |
| Low severity | 1 |
| Findings remediated | 8 / 8 |

---

## 2. Methodology

1. **Manual review** — Each route handler was read line by line and checked
   against the OWASP Top 10 (2021) categories: Injection, Broken Authentication,
   Sensitive Data Exposure, Security Misconfiguration, XSS, Broken Access
   Control, and Vulnerable Components.
2. **Static analysis** — Bandit was run against the source file to
   independently confirm and classify issues by CWE ID and severity.
3. **Dependency check** — `requirements.txt` was reviewed for outdated,
   vulnerable package pins.
4. **Remediation** — Each finding was fixed in a separate `fixed_app/`
   version, then re-scanned to confirm resolution.

---

## 3. Findings Summary Table

| # | Vulnerability | OWASP Category | File / Location | Severity | Tool |
|---|---|---|---|---|---|
| 1 | Hardcoded secret key in source | A05 Security Misconfiguration | `app.py:16` | Low | Bandit + Manual |
| 2 | Weak password hashing (MD5, no salt) | A02 Cryptographic Failures | `app.py:42, 57` | High | Bandit + Manual |
| 3 | SQL Injection (string concat/format) | A03 Injection | `app.py:46, 61, 76` | Medium | Bandit + Manual |
| 4 | Broken access control / IDOR | A01 Broken Access Control | `app.py:73-77` | High | Manual |
| 5 | Reflected/stored XSS (unescaped output) | A03 Injection (XSS) | `app.py:92-93` | Medium | Manual |
| 6 | Unrestricted file upload | A04 Insecure Design | `app.py:98-102` | Medium | Manual |
| 7 | Debug mode enabled, bound to 0.0.0.0 | A05 Security Misconfiguration | `app.py:114` | High | Bandit + Manual |
| 8 | Outdated dependency (Flask 2.0.1) | A06 Vulnerable Components | `requirements.txt` | Medium | Manual |

---

## 4. Detailed Findings & Remediation

### Finding 1: Hardcoded Secret Key
**Severity:** Low | **CWE-259**

The Flask `secret_key`, used to sign session cookies, was hardcoded directly
in source code. Anyone with repo access (or a leaked copy of the file) could
forge session cookies.

**Vulnerable code:**
```python
app.secret_key = "sk_live_9a8f7d6e5c4b3a2919283746abcdef0"
```

**Fix:** Load the key from an environment variable, with a random fallback
for local dev:
```python
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```

---

### Finding 2: Weak Password Hashing (MD5, No Salt)
**Severity:** High | **CWE-327**

Passwords were hashed with unsalted MD5, which is cryptographically broken
and crackable via rainbow tables/GPU brute force in seconds.

**Vulnerable code:**
```python
hashed = hashlib.md5(password.encode()).hexdigest()
```

**Fix:** Use Werkzeug's salted, iterated hashing:
```python
password_hash = generate_password_hash(password)
...
check_password_hash(user["password_hash"], password)
```

---

### Finding 3: SQL Injection
**Severity:** Medium | **CWE-89**

Queries were built with string formatting/concatenation of raw user input,
allowing attackers to alter query logic (e.g., `' OR '1'='1`) to bypass
login or dump the database.

**Vulnerable code:**
```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hashed + "'"
cursor = db.execute(query)
```

**Fix:** Use parameterized queries so the driver escapes input safely:
```python
cursor = db.execute("SELECT * FROM users WHERE username = ?", (username,))
```

---

### Finding 4: Broken Access Control / Insecure Direct Object Reference (IDOR)
**Severity:** High | **CWE-639**

The `/notes` route trusted a `user_id` passed directly in the URL query
string with no authentication check, letting any user view any other
user's notes by changing the ID.

**Vulnerable code:**
```python
user_id = request.args.get("user_id")
query = "SELECT * FROM notes WHERE user_id = " + user_id
```

**Fix:** Identify the user from a signed server-side session set at login,
never from client input:
```python
user_id = session.get("user_id")
if user_id is None:
    return redirect("/login")
```

---

### Finding 5: Cross-Site Scripting (XSS)
**Severity:** Medium | **CWE-79**

Note content was inserted directly into HTML output without escaping,
allowing a stored/reflected XSS payload (e.g., `<script>...</script>`) to
execute in another user's browser.

**Vulnerable code:**
```python
content += "<p>" + row[2] + "</p>"
```

**Fix:** Escape all user-controlled output before rendering:
```python
content += f"<p>{escape(row['content'])}</p>"
```

---

### Finding 6: Unrestricted File Upload
**Severity:** Medium | **CWE-434**

The upload endpoint saved any uploaded file under its original, unsanitized
filename with no extension or size checks — enabling path traversal or
uploading of executable/script files.

**Vulnerable code:**
```python
save_path = os.path.join("uploads", file.filename)
file.save(save_path)
```

**Fix:** Whitelist extensions, sanitize the filename, and cap upload size:
```python
if not allowed_file(file.filename):
    abort(400, "file type not allowed")
filename = secure_filename(file.filename)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
```

---

### Finding 7: Debug Mode Enabled in Runtime Config
**Severity:** High | **CWE-94 / CWE-605**

The app was launched with `debug=True` and bound to `0.0.0.0`, exposing the
Werkzeug interactive debugger — which allows arbitrary remote code
execution — to any network client.

**Vulnerable code:**
```python
app.run(host="0.0.0.0", debug=True)
```

**Fix:** Default to debug off, controlled by an environment flag, and bind
to localhost unless explicitly configured otherwise:
```python
debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
app.run(host="127.0.0.1", debug=debug_mode)
```

---

### Finding 8: Outdated / Vulnerable Dependency
**Severity:** Medium | **CWE-1104**

`requirements.txt` pinned `Flask==2.0.1`, an outdated release lacking
several years of security patches.

**Fix:** Upgrade and pin to a current, patched release:
```
Flask==3.0.3
Werkzeug==3.0.4
MarkupSafe==2.1.5
```

---

## 5. Static Analysis Tool Output (Bandit)

Bandit was run with: `bandit -r app.py -f txt -o bandit_report.txt`

- **Before remediation:** 8 issues (1 Low, 4 Medium, 3 High)
- **After remediation:** 0 issues

Full raw output is included in `bandit_report.txt` in this repository.

---

## 6. General Secure Coding Recommendations

1. **Never trust user input** — validate, sanitize, and use parameterized
   queries for all database access.
2. **Escape all output** rendered into HTML, using the template engine's
   auto-escaping (Jinja2 `{{ }}`) rather than manual string building.
3. **Use strong, salted hashing** (bcrypt/Argon2/PBKDF2) for passwords —
   never MD5/SHA1 alone.
4. **Enforce authentication and authorization server-side** — never trust a
   client-supplied ID to determine data ownership.
5. **Keep secrets out of source control** — use environment variables or a
   secrets manager, and add `.env` to `.gitignore`.
6. **Disable debug mode in any environment reachable over a network.**
7. **Validate file uploads** by extension, content type, and size; store
   uploads outside the web root when possible.
8. **Keep dependencies current** — run `pip-audit` or `safety` regularly and
   subscribe to security advisories for core frameworks.
9. **Adopt a routine review cadence** — run static analyzers (Bandit,
   Semgrep) in CI on every pull request, not just before major releases.

---

## 7. Conclusion

The reviewed application contained multiple high-impact vulnerabilities
typical of early-stage or student projects — none individually exotic, but
collectively enough to allow full account takeover, data exfiltration, and
potentially remote code execution. All 8 findings were remediated and
verified via a clean re-scan. Applying the OWASP Top 10 checklist alongside
an automated scanner like Bandit provides an efficient, repeatable review
process suitable for small teams and student projects alike.
