# Raven Roadmap

## ✅ COMPLETED — v0.9.0 through v0.19.0+

Features that have been implemented and are available in Raven v3.3:

- ✅ **Baseline & Diff Scanning** — `--baseline`, `--save-baseline`, `--compare` flags. Shows NEW, FIXED, UNCHANGED findings.
- ✅ **Ignore Comments & Inline Suppressions** — `#raven-ignore` annotations with required justification. Single-line and block formats.
- ✅ **Secrets Deep Scanning** — 100+ secret patterns + entropy-based detection + context-aware filtering. Git history scanning.
- ✅ **Cross-File Taint Analysis** — JS/TS require/import, Python import, Go import resolution. Call graph construction.
- ✅ **Incremental & Cached Scanning** — `.raven-cache/` directory. File-hash based re-scans.
- ✅ **Custom Rule DSL v2** — Semgrep-style operators: `pattern-either`, `pattern-not`, `pattern-inside`, `metavariable-regex`.
- ✅ **SBOM Generation** — CycloneDX/SPDX export. Manifest and lock file scanning.
- ✅ **Language Expansion** — Java (145+ rules), C# (83+ rules), Ruby (68+ rules), Kotlin (57+), Swift (59+). Plus 10 new languages.
- ✅ **DAST Lite (Config/Infra Scanning)** — Dockerfile (37 rules), Terraform (37), Kubernetes YAML (32), Bash (32).
- ✅ **Policy Engine & Compliance** — `.raven-policy.yaml` with severity gates, compliance mappings, path exclusions.
- ✅ **IDE Integrations v2** — VS Code extension (full), Zed (LSP config), Neovim/Vim (LSP + keymaps), Emacs (lsp-mode).
- ✅ **IDE Inline Quick-Fixes** — LSP CodeActions: "Fix with Raven", "Learn more", "Ignore with #raven-ignore".
- ✅ **Reporting & Dashboards** — HTML report, SARIF v2.1.0, GitLab SAST JSON, trend support.
- ✅ **Git Integration** — `--since` flag, PR annotations, pre-commit hook template.
- ✅ **AI-Powered Fix Generation** — 25 vulnerability-specific prompt types, 10 LLM providers, diff/patch generation, fix validation.
- ✅ **Exploitability Scoring** — CVSS 3.1-like scoring per finding (Attack Vector, Complexity, Privileges, Scope).
- ✅ **7-Layer False Positive Reduction** — Confidence scoring, AI FP filter, dead code detection, input validation awareness, path sensitivity, multi-pattern correlation, annotations.

---

## 🚧 IN PROGRESS / PLANNED

### v0.25.0 — Pre-commit Hook & Git Hooks
Official pre-commit hook with zero-config setup:
- `raven install-hook` — installs pre-commit and pre-push hooks
- `.pre-commit-config.yaml` — official pre-commit.com integration
- Zero-config: auto-detects project type
- `--staged-only` for instant pre-commit scanning
- `--fail-on-new-secrets` blocks commits with leaked secrets
- `raven uninstall-hook` — removes hooks

### v0.26.0 — JetBrains Plugin (Lightweight)
JetBrains IDE integration via LSP4IJ (not a full plugin):
- `editor/jetbrains/` — configuration for IntelliJ, PyCharm, GoLand, WebStorm, Rider
- External annotator integration
- Inlay hints for security findings
- Quick fixes via intention actions
- Tool window with finding list

### v0.27.0 — Docker & Container Support
- `Dockerfile` — official Raven Docker image
- `docker-compose.yml` — for CI/CD pipelines
- Scan inside containers without local install
- Multi-arch builds (amd64, arm64)
- GitHub Container Registry publishing

### v0.28.0 — Package Managers
- **Homebrew**: `brew install raven-security/raven`
- **npm**: `npm install -g @raven-security/raven`
- **pip**: `pip install raven-scanner`
- **Go**: `go install github.com/raven-security/raven@latest`
- **Snap**: `snap install raven`
- **Chocolatey** (Windows): `choco install raven`

### v0.29.0 — Advanced AI Features
- **AI Rule Generation** — `raven rule-gen --from "detect unsafe eval in Python"`
- **AI Severity Adjustment** — LLM reviews findings and adjusts severity based on context
- **AI Patch Review** — LLM validates generated patches for correctness and security
- **Explain Finding** — `raven explain <rule-id>` — LLM explains why this is a vulnerability

### v0.30.0 — Enterprise & Team Features
- **Centralized Config** — `--config-url` for team-wide policy
- **Shared Baselines** — team baselines stored in repo or remote
- **Notifications** — Slack/Discord/Microsoft Teams webhooks
- **Metrics Export** — Prometheus metrics for monitoring
- **Audit Logging** — who scanned what, when, and what was found
- **SSO Integration** — SAML/OIDC for web dashboard (if built)

### v0.31.0 — Extended Language Support
- **R** — data science security
- **Julia** — scientific computing
- **Haskell** — functional programming
- **Clojure** — JVM ecosystem
- **OCaml** — systems programming
- **Groovy** — Jenkins/Gradle scripts
- **PowerShell** — Windows administration
- **TypeScript strict** — advanced TS patterns

### v0.32.0 — Deeper Framework Integration
- **React Server Components** — RSC-specific rules
- **Next.js App Router** — app/ directory security
- **Remix** — loader/action injection
- **tRPC** — procedure injection
- **Prisma** — raw query detection
- **Drizzle** — ORM security
- **Supabase** — RLS policy checks
- **Firebase** — security rules scanning

---

## 🎯 LONG-TERM VISION

### v1.0.0 — The Complete Security Platform
- **SAST + SCA + IaC + Secrets** in one tool
- **Unified dashboard** with trends and metrics
- **CI/CD native** — first-class GitHub Actions, GitLab CI, CircleCI, Jenkins support
- **Community rule marketplace** — share and discover rules
- **IDE everywhere** — every major IDE supported
- **Zero-config by default** — works out of the box for any project

---

*Last updated: 2026-04-24*
