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

# Scan only staged files (instant pre-commit check)
raven scan --staged

# Watch for changes during development
raven watch

# Auto-fix issues (dry-run by default)
raven fix
raven fix --apply

# See all rules
raven rules
raven rules validate          # Validate custom rule files

# CI mode (exits 1 on findings, outputs SARIF)
raven ci --format sarif --output report.sarif

# Baseline / diff scanning (only report NEW issues)
raven scan --baseline .raven-baseline.json
raven scan --update-baseline  # Save current findings as baseline

# Deep secrets scanning
raven scan --secrets

# Enforce security policy
raven scan --policy .raven-policy.yaml

# Generate HTML report
raven scan --format html -o report.html

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

### VS Code / Cursor Extension

Install from VS Code Marketplace (coming soon) or build from source:

```bash
cd editor/vscode
npm install
npm run compile
```

Then press F5 in VS Code to launch the extension. You'll see:
- 🛡️ Status bar icon showing security status
- 🔴 Red squiggles under vulnerable code
- 💡 "Fix with Raven" code actions
- 📋 Command palette: `Raven: Scan Workspace`

### AI-Powered Fixes

Let AI fix vulnerabilities for you. Raven supports **10+ LLM providers** with auto-detection:

| Provider | Setup | Free Tier |
|----------|-------|-----------|
| **NVIDIA NIM** | `export NVIDIA_API_KEY=...` | ✅ 40 req/min |
| **OpenRouter** | `export OPENROUTER_API_KEY=...` | ✅ Available |
| **Groq** | `export GROQ_API_KEY=...` | ✅ Available |
| **Ollama** | `export OLLAMA_HOST=...` | ✅ Local, unlimited |
| **OpenAI** | `export OPENAI_API_KEY=...` | ❌ Paid |
| **Anthropic** | `export ANTHROPIC_API_KEY=...` | ❌ Paid |
| **DeepSeek** | `export DEEPSEEK_API_KEY=...` | ✅ Available |
| **Together** | `export TOGETHER_API_KEY=...` | ✅ Credits |
| **Google Gemini** | `export GEMINI_API_KEY=...` | ✅ Generous |
| **Azure OpenAI** | `export AZURE_OPENAI_API_KEY=...` | ❌ Paid |

```bash
# Auto-detects any configured provider
raven fix-ai

# Force a specific provider
raven fix-ai --provider nvidia

# Preview without applying
raven fix-ai --dry-run

# Use local Ollama (completely free)
export OLLAMA_HOST=http://localhost:11434
raven fix-ai --provider ollama
```

### Pre-commit Hook

Block commits with security issues:

```bash
raven install-hook        # Install
raven install-hook --uninstall  # Remove
```

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

### 🔬 Advanced Analysis
- **AST-based scanning** via Tree-sitter (not just regex)
- **Taint analysis** — tracks user input from source to sink
- **Inter-procedural taint** — follows data through function calls
- **Cross-file analysis** — tracks imports/exports across modules
- **Sanitizer-aware** — knows when `DOMPurify`, `html.EscapeString`, etc. make data safe

### 🔧 Auto-Fix
Raven suggests and applies fixes where possible:
```bash
raven fix --apply
```

### ⚡ Staged Scanning
Scan only git staged files in milliseconds:
```bash
raven scan --staged
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

### 📊 HTML Reports
Interactive dashboard with filtering:
```bash
raven scan --format html -o report.html
```

### 🛡️ Policy Engine
Enforce security thresholds in CI:
```yaml
# .raven-policy.yaml
max_findings:
  critical: 0
  high: 0
fail_on_new: true
```

### 📈 Incremental Caching
Skip unchanged files on subsequent scans (~40-60% speedup):
```bash
raven scan              # Warm cache — ultra fast
raven scan --no-cache   # Force full re-scan
```

### 🎨 Beautiful Output
Colored, readable terminal output with code snippets.

---

## Supported Languages

| Language | Status | Taint | AST | Rules |
|----------|--------|-------|-----|-------|
| JavaScript / TypeScript | ✅ Full | ✅ | ✅ | 60+ |
| Python | ✅ Full | ✅ | ✅ | 50+ |
| Go | ✅ Full | ✅ | ✅ | 40+ |
| PHP | ✅ Full | ✅ | ✅ | 40+ |
| Java | ✅ Full | ✅ | ✅ | 40+ |
| Kotlin | ✅ Full | ✅ | ✅ | 25+ |
| C# | ✅ Full | ✅ | ✅ | 30+ |
| Rust | ✅ Full | ✅ | ✅ | 30+ |
| Ruby | ✅ Full | ✅ | ✅ | 25+ |
| Swift | ✅ Full | ✅ | ✅ | 20+ |

---

## How It Works

Raven uses **local rule-based analysis** — no API calls, no data leaves your machine:

1. **Parse rules** from YAML files (built-in + custom)
2. **Walk files** in your project (or staged files only)
3. **Pattern match** using regex with compiled pattern cache
4. **AST analysis** via Tree-sitter for deep structural understanding
5. **Taint tracking** follows user input from sources (req.body) to sinks (db.query)
6. **Cross-file resolution** tracks taint through imports/exports
7. **Cache unchanged files** by SHA256 hash for warm-run speedup
8. **Output findings** with severity, location, fix suggestions, and HTML reports

All free. All local. All fast.

---

## Configuration

Create `.raven.yaml` in your project root:

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

Raven ships with **500+ security rules** covering OWASP Top 10, common LLM mistakes, AST-based analysis, taint tracking, and IaC scanning.

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
- [x] 500+ security rules (regex + AST + taint + IaC)
- [x] Auto-fix
- [x] Watch mode
- [x] CI mode + SARIF
- [x] VS Code / Cursor Extension (LSP-based)
- [x] AI-powered fixes (OpenRouter/DeepSeek)
- [x] Pre-commit hook
- [x] GitHub Action
- [x] AST-based analysis (Tree-sitter)
- [x] Framework-aware rules
- [x] Supply chain scanning (OSV)
- [x] Baseline / diff scanning
- [x] Incremental caching (SHA256-based)
- [x] Cross-file taint tracking
- [x] Inter-procedural taint analysis
- [x] Rule DSL v2 (where clauses, metavariables)
- [x] HTML reports with interactive filtering
- [x] Policy engine (.raven-policy.yaml)
- [x] Sanitizer-aware taint tracking
- [x] Staged file scanning (--staged)
- [x] Java / Kotlin / C# support
- [ ] Zed / Vim support
- [ ] IDE inline fixes

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

## 🔌 IDE & AI Integration

**📖 Full integration guide:** [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md)

Raven integrates with your favorite tools:

### VS Code Extension

```bash
cd vscode-raven
npm install && npm run compile
# F5 to launch Extension Development Host
```

Features: real-time diagnostics, findings panel, hover info, quick fixes, CodeLens.

### MCP Server (for Claude, Codex, etc.)

```bash
raven mcp  # Starts Model Context Protocol server
```

**Claude Desktop config:**
```json
{
  "mcpServers": {
    "raven": {
      "command": "raven",
      "args": ["mcp"]
    }
  }
}
```

**Available MCP tools:**
- `raven_scan_workspace` — full project scan
- `raven_scan_file` — single file scan
- `raven_scan_snippet` — scan AI-generated code snippets
- `raven_list_rules` / `raven_get_rule` — rule documentation
- `raven_explain_finding` — detailed vulnerability analysis

### LSP Server

```bash
raven lsp  # Language Server Protocol on stdio
```

Works with: VS Code, Neovim, Zed, Emacs, Kimi Code, Cursor.

### Pre-commit Hook

```bash
raven init --pre-commit  # Auto-installs git hook
```

---

## License

MIT © Raven Security

---

> *"The best security tool is the one you actually use."*
