# 🐦‍⬛ Raven

> **Security scanner for vibe coders.**
>
> Catch the security bugs AI puts in your code before you ship.

[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## The Problem

You vibe-coded an app with Cursor/Claude/Copilot. It works. You ship it.

**But your AI assistant just wrote:**
- SQL injection via string concatenation
- XSS via `innerHTML` 
- Hardcoded API keys
- `eval()` with user input
- Command injection via `exec()`

**You didn't notice. The attacker will.**

---

## What Raven Does

Raven scans your code for **the exact mistakes LLMs make** and tells you how to fix them.

```bash
$ raven scan

🐦‍⬛ Raven Security Scan
  42 files scanned in 23ms

Summary:
  critical: 2
  high: 3
  medium: 1

 CRITICAL  SQL Injection via String Concatenation
  src/api.js:12:18
  Potential SQL injection: user input is concatenated into a SQL query.
  Use parameterized queries.
       const query = "SELECT * FROM users WHERE id = " + req.query.id;
  💡 Fix available: raven fix

 HIGH  Hardcoded API Key or Secret
  src/config.js:5:7
  Hardcoded secret detected. Move this to environment variables.
     const API_KEY = "sk-live-abc123...";
```

---

## Installation

```bash
# macOS / Linux
brew install raven-security/tap/raven

# Or with Go
go install github.com/raven-security/raven/cmd/raven@latest

# Or download binary from releases
curl -sSL https://get.raven.sh | bash
```

---

## Quick Start

```bash
# Scan your project
cd my-project
raven scan

# Watch for changes during development
raven watch

# Auto-fix issues (dry-run by default)
raven fix
raven fix --apply

# See all rules
raven rules

# CI mode (exits 1 on findings, outputs SARIF)
raven ci --format sarif --output report.sarif

# Learn about a vulnerability
raven learn sqli
```

### GitHub Action

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  raven:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: raven-security/raven/.github/actions/raven@main
        with:
          fail-on: high
          format: sarif
```

Results appear in **Security → Code scanning alerts**.

---

## Features

### 🎯 AI-Aware Detection
Rules designed for **common LLM mistakes**:
- SQL injection (string concat, template literals, `.format()`)
- XSS (`innerHTML`, `dangerouslySetInnerHTML`, template injection)
- Hardcoded secrets (API keys, tokens, passwords)
- Command injection (`exec`, `spawn` with shell)
- Path traversal (unsanitized file paths)
- Code injection (`eval`, `new Function`)

### 🔧 Auto-Fix
Raven suggests and applies fixes where possible:
```bash
raven fix --apply
```

### 👁️ Watch Mode
Catch issues as you code:
```bash
raven watch
```

### 🚀 CI/CD Ready
GitHub Actions, GitLab CI, etc.:
```bash
raven ci --format sarif --output report.sarif
```

### 🎨 Beautiful Output
Colored, readable terminal output with code snippets.

---

## Supported Languages

| Language | Status |
|----------|--------|
| JavaScript / TypeScript | ✅ Full |
| Python | ✅ Full |
| Go | ✅ Full |
| PHP | ✅ Full |
| Rust | ✅ Basic |
| Java / Kotlin | ✅ Basic |
| Ruby | ✅ Basic |
| Swift | ✅ Basic |

---

## How It Works

Raven uses **local rule-based analysis** — no API calls, no data leaves your machine:

1. **Parse rules** from YAML files (built-in + custom)
2. **Walk files** in your project
3. **Pattern match** using regex (fast, lightweight)
4. **Output findings** with severity, location, and fix suggestions

All free. All local. All fast.

---

## Configuration

Create `raven.yaml` in your project root:

```yaml
rules:
  paths:
    - ./src
  exclude:
    - node_modules
    - dist
    - "*.test.js"
  confidence: medium

output:
  format: pretty  # pretty, json, sarif
  color: true
  show_code: true

fix:
  enabled: true
  dry_run: true

severity:
  min: low
```

---

## Rules

Raven ships with **30+ security rules** covering OWASP Top 10 and common LLM mistakes.

```bash
# List all rules
raven rules

# List only JavaScript rules
raven rules --lang javascript

# List with full details
raven rules --detail
```

---

## Why Raven vs Others?

| | Raven | Semgrep | Snyk | CodeQL |
|---|-------|---------|------|--------|
| **Cost** | Free | Free/Paid | $$$ | Free (GitHub only) |
| **Setup** | Zero config | Config-heavy | Account required | Complex |
| **Speed** | < 1s | ~5s | Cloud | ~30s |
| **AI-focused** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Auto-fix** | ✅ Yes | ⚠️ Partial | ❌ No | ❌ No |
| **Offline** | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes |
| **IDE** | CLI + LSP | Extensions | Extensions | GitHub only |

---

## Roadmap

- [x] Core rule engine
- [x] 28 security rules (OWASP Top 10 + AI-specific)
- [x] Auto-fix
- [x] Watch mode
- [x] CI mode + SARIF
- [x] 49 rules covering OWASP Top 10 + AI-specific mistakes
- [x] 49 rules (SQLi, XSS, RCE, secrets, crypto, SSRF, CORS, auth, etc.)
- [ ] IDE extensions (VS Code, Cursor, Zed)
- [ ] GitHub Action
- [ ] LLM-powered fix suggestions
- [ ] AST-based analysis (not just regex)
- [ ] Pre-commit hook

---

## Contributing

Raven is open source. Contributions welcome!

```bash
git clone https://github.com/raven-security/raven.git
cd raven
go test ./...
```

### Adding a Rule

Rules are YAML files in `rules/<language>/`:

```yaml
id: my-rule-001
name: Descriptive Name
severity: high
category: xss
confidence: high
languages: [javascript]
message: What the developer should know
patterns:
  - type: regex
    pattern: "dangerous\\.pattern"
references:
  - https://owasp.org/...
```

---

## License

MIT © Raven Security

---

> *"The best security tool is the one you actually use."*
