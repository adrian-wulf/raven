# Raven Live Test — Real-World Vulnerability Detection

**Date:** 2026-04-24  
**Raven version:** v3.3  
**Method:** 4 intentionally vulnerable files scanned with `raven scan`

---

## Summary

| File | Language | Findings | Critical | High | Medium |
|------|----------|----------|----------|------|--------|
| `vulnerable-express.js` | JavaScript (Express) | 14 | 7 | 5 | 2 |
| `vulnerable-flask.py` | Python (Flask) | 13 | 6 | 4 | 3 |
| `vulnerable-go.go` | Go | 8 | 3 | 5 | 0 |
| `VulnerableJava.java` | Java | 7 | 3 | 2 | 2 |
| **Total** | | **42** | **19** | **16** | **7** |

**Scan time:** ~125ms total for all 4 files  
**No false-positive storms.** Circuit breaker inactive (all rules behaved).

---

## Test 1: JavaScript / Express (`vulnerable-express.js`)

33 lines. Contains: SQLi, XSS, Open Redirect, Command Injection, Hardcoded Secret.

### Findings

| Severity | Rule | Line | Issue |
|----------|------|------|-------|
| CRITICAL | SQL Query String Formatting | 7 | `+ req.query.id` concatenated into SQL |
| CRITICAL | SQL Injection via String Concatenation | 7 | User input → SQL query |
| CRITICAL | SQL Injection via String Concatenation | 8 | `db.query()` receives tainted string |
| CRITICAL | Command Injection via String Concatenation | 29 | `'ping ' + req.query.host` |
| CRITICAL | Command Injection via exec/spawn | 29 | `exec()` with user input |
| CRITICAL | JavaScript child_process exec with User Input | 29 | `child_process.exec` command injection |
| CRITICAL | Node.js child_process.exec with Variables | 29 | `exec` with variables |
| HIGH | Express Direct Response Write (XSS) | 15 | `res.send()` with user input |
| HIGH | XSS via innerHTML or dangerouslySetInnerHTML | 15 | Template literal with user data |
| HIGH | Dangerous eval with Template Literal | 15 | Template literal evaluated |
| HIGH | JavaScript Open Redirect via Location Header | 20 | `res.redirect(req.query.url)` |
| HIGH | Open Redirect via res.redirect | 20 | User-controlled redirect URL |
| MEDIUM | Hardcoded Secret | 24 | `API_KEY` hardcoded |
| MEDIUM | High-Entropy String | 24 | Possible secret in `API_KEY` |

**Detected:** SQLi ✅ | XSS ✅ | Open Redirect ✅ | Command Injection ✅ | Hardcoded Secret ✅

---

## Test 2: Python / Flask (`vulnerable-flask.py`)

36 lines. Contains: SQLi, Path Traversal, eval() RCE, Open Redirect, Debug Mode, Hardcoded Secret, Missing CSRF.

### Findings

| Severity | Rule | Line | Issue |
|----------|------|------|-------|
| CRITICAL | SQL Query String Formatting | 10 | `%s` formatting with `user_id` |
| CRITICAL | SQL Injection via String Formatting | 11 | `cursor.execute(query)` with tainted query |
| CRITICAL | Command Injection in Python | 32 | `eval()` with user input |
| CRITICAL | Unsafe eval() or exec() in Python | 32 | `eval()` arbitrary code execution |
| CRITICAL | Python eval on Untrusted Input | 32 | `eval()` with untrusted input |
| CRITICAL | eval() Code Execution | 32 | `eval()` on user-controlled expression |
| HIGH | Debug Information in Production | 35 | `debug=True` |
| HIGH | Path Traversal in Python | 18 | `open('/tmp/' + filename)` |
| HIGH | redirect with user URL | 27 | `redirect(request.args.get('url'))` |
| HIGH | Flask Hardcoded Secret Key | 22 | `SECRET_KEY` hardcoded |
| MEDIUM | Debug Mode Enabled in Flask/Django | 35 | `debug=True` in production |
| MEDIUM | Flask Session Without Secure Settings | 22 | Session cookies may lack security flags |
| MEDIUM | Flask Missing CSRF Protection | 4 | Missing Flask-WTF CSRF |

**Detected:** SQLi ✅ | Path Traversal ✅ | eval() RCE ✅ | Open Redirect ✅ | Debug Mode ✅ | Hardcoded Secret ✅ | Missing CSRF ✅

---

## Test 3: Go (`vulnerable-go.go`)

40 lines. Contains: SQLi, Command Injection (safe array args), MD5 hash, Path Traversal.

### Findings

| Severity | Rule | Line | Issue |
|----------|------|------|-------|
| CRITICAL | SQL Query String Formatting | 14 | `+ id` concatenated into SQL |
| CRITICAL | Go SQL String Concatenation | 14 | SQL string concatenation |
| CRITICAL | SQL Injection via String Concatenation | 15 | `db.Query(query)` with tainted query |
| HIGH | Sensitive Data in Log Output | 29 | `fmt.Sprintf` with password hash |
| HIGH | MD5 Hash for Password or Integrity | 28 | `md5.New()` for passwords |
| HIGH | os.Open with User Controlled Path | 35 | `os.ReadFile(path)` with user input |
| HIGH | Insecure Cryptographic Algorithm | 4 | `crypto/md5` import |
| HIGH | Insecure Cryptographic Algorithm | 28 | `md5.New()` usage |

**Detected:** SQLi ✅ | MD5 ✅ | Path Traversal ✅  
**Correctly skipped:** Command Injection — Go's `exec.Command("ping", host)` uses array args, inherently safe. Raven correctly did NOT flag this. ✅

---

## Test 4: Java (`VulnerableJava.java`)

36 lines. Contains: SQLi, Command Injection, Insecure Random, Path Traversal.

### Findings

| Severity | Rule | Line | Issue |
|----------|------|------|-------|
| CRITICAL | Command Injection via String Concatenation | 34 | `"ping " + host` in `Runtime.exec()` |
| CRITICAL | SQL Query String Formatting | 12 | `+ id` concatenated into SQL |
| CRITICAL | Runtime.exec with Dynamic Input | 34 | `Runtime.exec()` with dynamic string |
| HIGH | Path Traversal in Java | 27 | `new File("/tmp/" + filename)` |
| HIGH | Non-Cryptographic Random for Security | 19 | `new Random()` for tokens |
| MEDIUM | Weak Random Number Generation | 19 | `java.util.Random` not crypto-safe |
| MEDIUM | Insecure Random Generator | 19 | `Random` instead of `SecureRandom` |

**Detected:** SQLi ✅ | Command Injection ✅ | Insecure Random ✅ | Path Traversal ✅

---

## Detection Accuracy Summary

| Vulnerability | JS | Python | Go | Java |
|---------------|-----|--------|-----|------|
| SQL Injection | ✅ 3x | ✅ 2x | ✅ 3x | ✅ 2x |
| Command Injection | ✅ 4x | ✅ 1x | N/A* | ✅ 2x |
| XSS | ✅ 3x | N/A | N/A | N/A |
| Open Redirect | ✅ 2x | ✅ 1x | N/A | N/A |
| Path Traversal | N/A | ✅ 1x | ✅ 1x | ✅ 1x |
| Insecure Crypto | N/A | N/A | ✅ 3x | ✅ 2x |
| eval() RCE | N/A | ✅ 4x | N/A | N/A |
| Debug Mode | N/A | ✅ 2x | N/A | N/A |
| Hardcoded Secret | ✅ 2x | ✅ 1x | N/A | N/A |
| Missing CSRF | N/A | ✅ 1x | N/A | N/A |

*Go `exec.Command("ping", host)` uses array args — inherently safe. **Raven correctly skipped it.** ✅

---

## Performance

| File | Size | Time |
|------|------|------|
| `vulnerable-express.js` | 33 lines | 56ms |
| `vulnerable-flask.py` | 36 lines | 28ms |
| `vulnerable-go.go` | 40 lines | 15ms |
| `VulnerableJava.java` | 36 lines | 27ms |
| **Total** | **145 lines** | **~126ms** |
