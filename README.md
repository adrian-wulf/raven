# Raven v3.3

> **The AI-native security scanner. Built for vibe coders. Engineered for zero false positives.**
>
> 1,900+ rules. 35 language categories. 10 LLM providers for auto-fix. 7-layer false positive reduction.

[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-1,900+-success?logo=shield)](rules)
[![Languages](https://img.shields.io/badge/languages-35+-orange?logo=code)](rules)

---

## What AI wrote in your code

You built an app with Cursor/Claude/Copilot. It works. You ship to production.

**But your AI assistant just wrote:**
- SQL injection via string concatenation
- XSS via `innerHTML`  
- Hardcoded API keys in source
- `eval()` with user data
- Command injection via `exec()`
- Missing CSRF protection
- JWT signed with "none" algorithm
- Secrets logged to console

**You didn't notice. Attackers will.**

Raven catches exactly these vulnerabilities in **< 1 second**.

---

## Quick Start

```bash
# Scan your project
cd my-project
raven scan

# Scan only staged files (instant pre-commit)
raven scan --staged

# AI-powered fixes (multi-provider)
export OPENROUTER_API_KEY=your-key
raven fix-ai

# Watch mode during development
raven watch

# CI mode with SARIF output
raven ci --format sarif --output report.sarif

# Quality gate enforcement
raven scan --policy .raven-policy.yaml

# Baseline comparison (reports ONLY NEW issues)
raven scan --baseline .raven-baseline.json
raven scan --save-baseline baseline.json
```

---

## v2.5 Highlights

### 1,900+ Security Rules

| Category | Rules | Languages | Key Coverage |
|----------|-------|-----------|--------------|
| **Injection** | 400+ | JS/TS, Python, Go, Java, PHP, C#, Ruby, Rust | SQLi, XSS, CMDi, NoSQLi, LDAPi, XPathi, SSTI, EL injection |
| **Cryptography** | 120+ | All | Weak hashes, bad random, hardcoded keys, weak TLS, JWT flaws |
| **Secrets** | 100+ patterns | All | AWS, GitHub, Slack, Stripe, Firebase, private keys, generic high-entropy |
| **Authentication** | 150+ | All | Missing auth, weak sessions, insecure cookies, JWT misconfig, OAuth flaws |
| **API Security** | 80+ | JS/TS, Python, Go, Java | Rate limiting, GraphQL, mass assignment, pagination, webhook validation |
| **Mobile** | 50+ | Java/Kotlin, Swift, Dart | WebView XSS, root detection, clipboard leaks, hardcoded keys |
| **Infrastructure** | 200+ | Dockerfile, Terraform, YAML, Bash | Container security, IaC misconfig, K8s hardening, shell script flaws |
| **Smart Contracts** | 40+ | Solidity | Reentrancy, overflow, access control, tx.origin, timestamp dependence |
| **Framework-Specific** | 300+ | Express, Django, Flask, FastAPI, Rails, Laravel, Spring Boot, ASP.NET, Gin, React, Vue, Angular | Deep integration with 80+ frameworks |
| **General** | 400+ | All | Path traversal, SSRF, XXE, file upload, open redirect, CORS, CSRF, race conditions |

### AI-Powered Fix Generation (10 Providers)

Connect any LLM provider for automatic vulnerability remediation:

| Provider | Status | Best For |
|----------|--------|----------|
| **OpenAI** (GPT-4o/o3) | Supported | Best overall quality |
| **Anthropic** (Claude 3.5/3.7 Sonnet) | Supported | Excellent code reasoning |
| **Mistral** (Codestral) | Supported | Fast, code-optimized |
| **DeepSeek** (V3/Coder) | Supported | Cost-effective |
| **Groq** (Llama/Mixtral) | Supported | Ultra-fast inference |
| **NVIDIA** (NIM) | Supported | Self-hosted GPU |
| **Ollama** (Local) | Supported | 100% offline/privacy |
| **Azure OpenAI** | Supported | Enterprise compliance |
| **Google Gemini** | Supported | Multi-modal context |
| **Cohere** (Command) | Supported | Production deployments |

25 vulnerability-specific prompt types with **few-shot examples** for 8 languages.

### 7-Layer False Positive Reduction

The most advanced FP reduction system in any open-source SAST:

1. **Confidence Scoring** — every finding scored 0.0-1.0 based on pattern specificity, context depth, sink sensitivity, sanitizer proximity
2. **AI False Positive Filter** — 8 heuristics (test context, safe variable names, validation proximity, common FP patterns, documentation detection, safe values, sanitization nearby, framework defaults)
3. **Dead Code Detection** — skips findings in unreachable code blocks
4. **Input Validation Awareness** — 50+ validation patterns per language (joi, pydantic, Hibernate Validator, validator.js, etc.)
5. **Path Sensitivity** — understands if/else branches where one path sanitizes
6. **Multi-Pattern Correlation** — boosts confidence when related patterns match nearby
7. **`#raven-ignore` Annotations** — Gosec-style annotations for developer overrides with required justification

### Quality Gates & CI/CD Integration

```yaml
# .raven-policy.yaml
quality_gate:
  max_critical: 0
  max_high: 0
  max_medium: 5
  fail_on_new_secrets: true

new_code:
  max_critical: 0
  max_high: 0
  max_total: 5

ignore_patterns:
  - path: "*_test.go"
    rules: ["*"]
    reason: "Test files"
  - path: "vendor/"
    rules: ["*"]
    reason: "Third-party code"
  - path: "migrations/"
    rules: ["sqli"]
    reason: "Database migrations use raw SQL by design"
```

### SARIF v2.1.0 + GitLab SAST Export

Full SARIF 2.1.0 compliance with CWE taxonomy, code snippets, and tool info. Native GitLab SAST JSON export for GitLab Security Dashboard integration.

### Semgrep-Style Rule Operators

Support for advanced rule composition:
- `pattern-either` (OR logic)
- `pattern-not` (exclusion)
- `pattern-inside` / `pattern-not-inside` (context scoping)
- `metavariable-regex` (capture group validation)

---

## Competitive Comparison

| Feature | **Raven v2.5** | Semgrep CE | CodeQL | Snyk Code | Brakeman | Bearer |
|---------|---------------|------------|--------|-----------|----------|--------|
| **Rules** | **1,915** | 2,800+ | 483 | 156 | 84 | 124 |
| **Languages** | **35** | 30+ | 11 | 8 | 1 (Ruby) | 2 |
| **AI-Aware Rules** | **Yes** | No | No | No | No | No |
| **LLM Auto-Fix** | **10 providers** | No | No (Copilot sep.) | 1 (Snyk AI) | No | No |
| **FP Reduction Layers** | **7** | 2-3 | 3-4 | 3-4 | 1 | 2 |
| **Scan Speed** | **<1s** | ~5s | ~30s | ~270s (cloud) | ~80s | ~130s |
| **AI-Generated FP Filter** | **Yes** | No | No | Partial | No | No |
| **Framework Detection** | **80+** | Some | Some | Some | Rails only | None |
| **SARIF 2.1.0** | **Yes** | Yes | Yes | Yes | Yes | Yes |
| **GitLab SAST** | **Yes** | No | No | Yes | No | No |
| **Cost** | **Free** | Free/$$$ | Free (GH only) | $$$/100scans | Free | Free/$$$ |
| **Offline** | **Yes** | Yes | Yes | No | Yes | Yes |
| **LSP Server** | **Yes** | No | No | No | No | No |
| **#raven-ignore Annotations** | **Yes** | No | No | No | No (#nosec) | No |
| **Quality Gates** | **Yes** | No | No | Yes | No | No |
| **Scan Comparison** | **Yes** | No | No | Yes | Yes | No |
| **Confidence Scoring** | **Yes (0.0-1.0)** | Partial | Partial | Yes | High/Med/Low | No |
| **Exploitability Scorer** | **Yes (CVSS-like)** | No | No | No | No | No |

**Sources:** Semgrep CE blog (2024), CodeQL changelog 2.23.5 (2025), Cycode SAST benchmark (2023), Snyk documentation (2025), Brakeman docs, Bearer benchmark.

---

## CWE Coverage

Raven maps every rule to CWE. We cover the **CWE Top 25 2024** in full:

| CWE | Name | Raven Rules | Status |
|-----|------|-------------|--------|
| CWE-787 | Out-of-bounds Write | 15+ | Full |
| CWE-79 | Cross-site Scripting | 80+ | Full |
| CWE-89 | SQL Injection | 60+ | Full |
| CWE-416 | Use After Free | 10+ | Full |
| CWE-78 | OS Command Injection | 40+ | Full |
| CWE-20 | Improper Input Validation | 100+ | Full |
| CWE-125 | Out-of-bounds Read | 12+ | Full |
| CWE-22 | Path Traversal | 35+ | Full |
| CWE-352 | Cross-Site Request Forgery | 15+ | Full |
| CWE-434 | Unrestricted File Upload | 8+ | Full |
| CWE-862 | Missing Authorization | 12+ | Full |
| CWE-476 | NULL Pointer Dereference | 15+ | Full |
| CWE-287 | Improper Authentication | 25+ | Full |
| CWE-190 | Integer Overflow | 20+ | Full |
| CWE-77 | Command Injection | 40+ | Full |
| CWE-119 | Improper Restriction of Operations | 50+ | Full |
| CWE-798 | Hardcoded Credentials | 100+ | Full |
| CWE-918 | Server-Side Request Forgery | 25+ | Full |
| CWE-306 | Missing Authentication | 15+ | Full |
| CWE-362 | Race Condition | 20+ | Full |
| CWE-269 | Improper Privilege Management | 10+ | Full |
| CWE-94 | Code Injection | 45+ | Full |
| CWE-863 | Incorrect Authorization | 10+ | Full |
| CWE-276 | Incorrect Default Permissions | 8+ | Full |
| CWE-200 | Information Exposure | 20+ | Full |

---

## Supported Languages

| Language | Status | Taint | AST | Regex | Rules |
|----------|--------|-------|-----|-------|-------|
| JavaScript / TypeScript | Full | Yes | Yes | Yes | **200+** |
| Python | Full | Yes | Yes | Yes | **150+** |
| Go | Full | Yes | Yes | Yes | **120+** |
| Java | Full | Yes | Yes | Yes | **145+** |
| PHP | Full | Yes | Yes | Yes | **125+** |
| C / C++ | Full | Yes | Yes | Yes | **120+** |
| C# | Full | Yes | Yes | Yes | **80+** |
| Rust | Full | Yes | Yes | Yes | **80+** |
| Ruby | Full | Yes | Yes | Yes | **65+** |
| Kotlin | Full | Yes | Yes | Yes | **55+** |
| Swift | Full | Yes | Yes | Yes | **55+** |
| Dart / Flutter | Regex+Taint | Yes | No | Yes | **40+** |
| Elixir / Phoenix | Regex+Taint | Yes | No | Yes | **35+** |
| Scala / Play | Regex+Taint | Yes | No | Yes | **35+** |
| Lua / OpenResty | Regex+Taint | Yes | No | Yes | **30+** |
| Solidity | Regex+Taint | Yes | No | Yes | **35+** |
| Bash / Shell | Regex | No | No | Yes | **30+** |
| Dockerfile | Regex | No | No | Yes | **35+** |
| Terraform / IaC | Regex | No | No | Yes | **35+** |
| YAML / Kubernetes | Regex | No | No | Yes | **30+** |
| JSON | Regex | No | No | Yes | Secrets only |
| IoT / Embedded | Regex | No | No | Yes | **45+** |

---

## How It Works

1. **Rule engine** loads 1,900+ YAML rules (regex + AST + taint + IaC)
2. **File scanner** walks the project (or just staged files)
3. **Regex matcher** with compiled pattern cache finds surface-level issues
4. **AST analysis** via Tree-sitter understands code structure for deep patterns
5. **Taint tracker** follows user data from sources (`req.body`) to sinks (`db.query`) across function calls and files
6. **Sanitizer awareness** knows when `DOMPurify`, `html.EscapeString`, `validator.js` make data safe
7. **Framework detection** auto-detects 80+ frameworks and applies framework-specific source/sink mappings
8. **Confidence scoring** assigns 0.0-1.0 score to every finding based on 5 factors
9. **FP filter** applies 8 heuristics to suppress likely false positives
10. **Annotation parser** respects `#raven-ignore` comments from developers
11. **Quality gate** enforces thresholds and fails CI if exceeded
12. **LLM fix generation** sends vulnerability-specific prompts to chosen AI provider for auto-remediation
13. **Fix validator** checks AI-generated fixes for syntax correctness and security
14. **Export** to SARIF v2.1.0, GitLab SAST JSON, HTML, or terminal

**Everything is local. Everything is fast. Everything is free.**

---

## OWASP Top 10 2025 Coverage

| OWASP | Category | Raven Coverage |
|-------|----------|----------------|
| A01 | Broken Access Control | IDOR, Missing Auth, Mass Assignment, Privilege Escalation, Insecure Direct Object References |
| A02 | Security Misconfiguration | Debug Mode, Insecure Headers, CORS Wildcard, TLS/SSL Misconfig, Server Disclosure |
| A03 | Software Supply Chain | Dependency Confusion, Unpinned Versions, Typosquatting, npm install without lock |
| A04 | Cryptographic Failures | Weak Crypto (MD5/SHA1/DES), Bad Random, Hardcoded Secrets, Weak TLS, JWT Flaws |
| A05 | Injection | SQLi, XSS, CMDi, NoSQLi, LDAPi, XPathi, SSTI, EL Injection, Header Injection, Log Injection |
| A06 | Insecure Design | File Upload, Open Redirect, SSRF, XXE, Race Conditions, Prototype Pollution |
| A07 | Authentication Failures | JWT Weaknesses, Session Fixation, Insecure Cookies, Password Hashing, OAuth Flaws |
| A08 | Integrity Failures | Unsafe Deserialization, XXE, Insecure Dependencies, Missing Checksums |
| A09 | Logging Failures | Log Injection, Sensitive Data in Logs, Missing Audit Trail, Console Secrets |
| A10 | Exception Handling | Information Leakage, Stack Trace Exposure, Debug Info in Production, Generic Error Handling |

---

## Architecture

```
 Rules (1,900+ YAML)          Engine
 +------------------+        +---------------------+
 | Regex Rules      |------->| Confidence Scorer   |
 | AST Rules        |------->| FP Filter (7 layers)|
 | Taint Rules      |------->| Dead Code Detector  |
 | IaC Rules        |------->| Annotation Parser   |
 | Secret Patterns  |------->| Quality Gate        |
 +------------------+        +----------+----------+
                                        |
             Tree-sitter AST            v
 +------------------+        +---------------------+
 | Language Parsers |------->| Taint Tracker       |
 | (Go, JS, Python  |        | (Intra + Cross-file)|
 |  Java, etc.)     |        | Framework Detector  |
 +------------------+        +----------+----------+
                                        |
                                        v
                              +---------------------+
                              | LLM Fix Generation  |
                              | (10 providers,      |
                              |  25 vuln types)     |
                              +----------+----------+
                                         |
                                         v
                              +---------------------+
                              | SARIF 2.1.0         |
                              | GitLab SAST         |
                              | HTML Report         |
                              +---------------------+
```

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
  format: pretty  # pretty, json, sarif, html, summary
  color: true
  show_code: true

fix:
  enabled: true
  dry_run: true
  provider: openai  # openai, anthropic, mistral, deepseek, groq, ollama, azure, gemini, cohere, nvidia

severity:
  min: low

quality_gate:
  max_critical: 0
  max_high: 0
  max_secrets: 0
```

---

## Roadmap

- [x] VS Code extension (with diagnostics, commands, status bar)
- [x] Zed / Vim / Neovim support (LSP configuration + keymaps)
- [x] IDE inline fixes (CodeActions via LSP — "Fix with Raven" lightbulb)
- [x] LSP server (diagnostics, hover, code actions, execute command)
- [x] GitHub Action (CI/CD integration)
- [x] MCP server for AI agents (Model Context Protocol)
- [x] MCP prompt injection scanner
- [x] HTML & SARIF v2.1.0 reporting
- [x] GitLab SAST export
- [x] Quality gates with `.raven-policy.yaml`
- [x] Scan comparison (`--baseline`, `--save-baseline`)
- [x] #raven-ignore annotations
- [x] AI-powered fix generation (10 LLM providers)
- [x] Exploitability scoring (CVSS-like)
- [x] Emacs LSP configuration (editor/emacs/raven.el)
- [x] JetBrains integration (LSP4IJ + external annotator, editor/jetbrains/README.md)
- [x] Pre-commit hook (hooks/pre-commit + .pre-commit-hooks.yaml)
- [x] Docker image (Dockerfile)
- [x] Homebrew formula (homebrew/raven.rb)

---

## Contributing

Raven is open source. Contributions welcome!

```bash
git clone https://github.com/raven-security/raven.git
cd raven
go test ./...
```

### Adding a Rule

Rules are YAML files in `rules/<category>/`:

```yaml
id: my-rule-001
name: Descriptive Rule Name
severity: high
category: sqli
confidence: high
cwe: "CWE-89"
languages: [javascript]
message: "Use parameterized queries instead of string concatenation"
patterns:
  - type: regex
    pattern: "query\s*\+\s*"
    where:
      - not-constant: true
      - not-sanitized: ["DOMPurify.sanitize", "validator.escape"]
references:
  - https://cwe.mitre.org/data/definitions/89.html
  - https://owasp.org/www-community/attacks/SQL_Injection.html
```

---

## License

MIT (c) Raven Security

---

> *"The best security tool is the one you actually use."*
