# Raven Roadmap

## v0.9.0 — Baseline & Diff Scanning
Baseline scanning for CI/CD. Scan against previous results, report only new issues.
- `--baseline <file>` flag
- `--update-baseline` flag to save current results as baseline
- JSON baseline format: `{rule_id, file, line, column, snippet_hash}`
- `Result.NewFindings`, `Result.BaselineFindings`, `Result.IgnoredFindings`

## v0.10.0 — Ignore Comments & Inline Suppressions
Inline suppressions for false positives.
- `// raven-ignore: R001` — suppress specific rule
- `// raven-ignore-next-line` — suppress next line
- `--no-ignore-comments` flag
- Store suppression reasons in SARIF

## v0.11.0 — Secrets Deep Scanning
Entropy-based and git-history secret detection.
- High-entropy string detection
- `--history` flag: scan git commits for leaked secrets
- Custom secret patterns via `.raven.yaml`
- Integration with GitLeaks-style patterns

## v0.12.0 — Cross-File Taint Analysis
Track data flow across file/module boundaries.
- JS/TS: require/import resolution
- Python: import resolution
- Go: import resolution
- Call graph construction

## v0.13.0 — Incremental & Cached Scanning
File-hash based cache for fast re-scans.
- `.raven-cache/` directory
- Only re-scan changed files
- Watch mode uses cache for instant feedback
- 10x faster re-scans

## v0.14.0 — Custom Rule DSL v2
More powerful rule composition.
- Composite rules: AND, OR, NOT between patterns
- Contextual rules: "if framework X and pattern Y"
- Rule templates / parameterized rules
- Rule validation command: `raven validate-rules`

## v0.15.0 — SBOM Generation
Software Bill of Materials export.
- `--sbom` flag generates CycloneDX/SPDX
- Scans manifests and lock files
- Includes transitive dependencies
- VEX (Vulnerability Exploitability eXchange) support

## v0.16.0 — Language Expansion (Java, C#, Ruby)
New language parsers and rules.
- Java: SQLi, XSS, deserialization, XXE
- C#: SQLi, XSS, XXE, insecure crypto
- Ruby: SQLi, XSS, RCE, mass assignment
- 15+ rules per language

## v0.17.0 — DAST Lite (Config/Infra Scanning)
Static analysis of infrastructure-as-code.
- Dockerfile best practices
- Terraform/CloudFormation scanning
- Kubernetes manifest scanning
- 20+ infrastructure rules

## v0.18.0 — Policy Engine & Compliance
Organization-wide security policies.
- `.raven-policy.yaml` — define policies
- Severity gates: "no critical in production"
- Compliance mappings: OWASP ASVS, PCI-DSS
- Policy violations in SARIF

## v0.19.0 — IDE Integrations v2
More editor support.
- Zed extension
- Vim/Neovim plugin (LSP)
- JetBrains plugin
- Inline quick-fixes via LSP CodeAction

## v0.20.0 — Reporting & Dashboards
Rich report generation.
- HTML report (`--format html`)
- Trend graphs over time
- Per-rule statistics
- PDF export

## v0.21.0 — Git Integration
Deeper git integration.
- Pre-push hook
- PR annotations (GitHub, GitLab)
- Blame integration: who introduced each finding
- `--since` flag: scan commits since date

## v0.22.0 — AI-Powered Rule Generation
Generate rules from natural language.
- `raven rule-gen --from <description>`
- LLM generates regex/AST patterns
- Rule validation and testing
- Community rule sharing

## v0.23.0 — Fuzzing Integration
Automatic fuzz input generation.
- `raven fuzz` for detected sinks
- Integration with go-fuzz / libfuzzer
- Crash detection and reporting

## v0.24.0 — Enterprise Features
Team and org features.
- Centralized config via URL (`--config-url`)
- Team policies and shared baselines
- Slack/Discord/webhook notifications
- Prometheus metrics export
