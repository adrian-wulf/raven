# Changelog

All notable changes to Raven will be documented in this file.

## [v3.0.0] - 2026-04-24

### Added
- Rule quality scoring heuristic (`CalculateQualityScore`):
  - AST-based rules score highest (+20), taint next (+15), regex lowest (+5)
  - Confidence and framework-specificity adjust the score
  - Every JSON/SARIF finding now includes `quality_score`
- `raven rules --score` — audit rule quality from the CLI

### Notes
- SARIF output was already schema-compliant; v3.0 makes it production-grade
  by attaching quality metadata to every result.

## [v2.7.0] - 2026-04-24

### Added
- Auto-FP detection: tracks suppressed findings per rule and warns when a rule
  is suppressed ≥3 times (suggests tightening or lowering confidence).
- Expanded auto-exclude list: `libs`, `lib`, `third_party`, `3rdparty`,
  `external`, `assets` (avoids scanning bundled/vendor code).

### Changed
- `Result` struct now includes `suppressed_counts` for post-scan analysis.

## [v2.6.0] - 2026-04-24

### Added
- `type: ast` alias for `ast-query` pattern type.
- 5 new high-precision AST-based rules:
  - `raven-ast-java-insecure-random-001` — detects `new Random()` in Java
  - `raven-ast-java-sqli-concat-001` — detects SQL injection via string `+` in `executeQuery`
  - `raven-ast-js-open-redirect-001` — detects `res.redirect(req.query.*)`
  - `raven-ast-js-proto-001` — detects prototype pollution via `__proto__` or `Object.assign`
  - `raven-ast-js-json-parse-001` — detects insecure `JSON.parse(req.body)`

## [v2.5.1] - 2026-04-24

### Added
- Circuit breaker in scan engine: auto-downgrades or drops overly noisy rules
  (>30 findings/file → low confidence, >100/project → dropped with warning)
- `--no-cache` CLI flag (was documented but never registered)

### Fixed
- `concurrent map writes` panic in cache (`sync.RWMutex` added)

### Changed
- Tightened 14 regex rules to reduce false-positive storm:
  - Downgraded confidence from high → low/medium for broad patterns
  - Added `not-test-file` filters where applicable
  - Removed `java-null-001` (matched every method call in Java)

## [v1.7.0] - 2026-04-22

### Added
- Shell completions: `raven completion bash|zsh|fish|powershell`
- Instructions for adding completions to `.bashrc`, `.zshrc`, etc.

## [v1.6.0] - 2026-04-22

### Changed
- Updated `.raven-baseline.json` with 26 tracked findings
- CI workflow now runs with `--secrets --deps` for deeper scanning

## [v1.5.0] - 2026-04-22

### Fixed
- **Critical**: Fixed `concurrent map writes` panic in regex cache (thread-safety with `sync.RWMutex`)
- Self-scan now runs cleanly (0 findings in `internal/`)
- Fixed false positives in `raven learn` examples

## [v1.4.0] - 2026-04-22

### Changed
- Updated README with all v1.x features
- Added language support table with taint/AST/rule counts
- Completed roadmap items (baseline, cache, cross-file taint, inter-procedural, DSL v2, HTML reports, policy, sanitizers, staged scanning, Java/Kotlin/C#)

## [v1.3.0] - 2026-04-22

### Added
- Enhanced `raven init` with full project bootstrapping:
  - `--all`: Full setup (CI + policy + hook + baseline)
  - `--ci`: GitHub Actions workflow
  - `--policy`: `.raven-policy.yaml` template
  - `--pre-commit`: Install git pre-commit hook
  - `--baseline`: Empty `.raven-baseline.json`

## [v1.2.0] - 2026-04-22

### Added
- Performance benchmarks (`go test -bench=. ./internal/engine/`)
- Regex compilation cache in `Scanner` (~5-10% speedup)

### Performance
- 10 files: ~0.6ms cold scan
- 100 files: ~4.2ms cold scan
- Warm cache: ~0.06ms (10x faster)

## [v1.1.0] - 2026-04-22

### Added
- `--staged` flag: scan only git staged files (`git diff --cached`)
- Pre-commit hook updated to use `--staged` by default
- ~10x faster pre-commit scans

## [v1.0.1] - 2026-04-22

### Added
- GitHub Action (`action.yml`) for easy CI/CD integration
- Dockerfile with multi-stage build

## [v1.0.0] - 2026-04-22

### Added
- **Policy engine**: `.raven-policy.yaml` with `max_findings`, `blocked_rules`, `fail_on_new`
- `--policy` flag for `raven scan` and `raven ci`
- Exit codes: 0=clean, 1=findings, 2=policy violation
- Stable API — backwards compatibility guaranteed

## [v0.19.0] - 2026-04-22

### Added
- LSP server improvements:
  - Real-time diagnostics on `textDocument/didChange` (files <1000 lines)
  - WorkspaceEdit code actions (Ctrl+. applies fix directly)
  - Language support: Kotlin, C#, Ruby, Swift
  - Hover provider for security context

## [v0.18.0] - 2026-04-22

### Added
- HTML report generation: `raven scan --format html`
- Interactive severity filtering
- Dark theme dashboard with code snippets
- Vulnerable dependencies section
- Zero external dependencies (self-contained HTML)

## [v0.17.0] - 2026-04-22

### Added
- **Java** support (`.java`) with SQLi, command injection, XSS rules
- **Kotlin** support (`.kt`) — parser ready, shares Java rules
- **C#** support (`.cs`) with SQLi, command injection, XSS rules
- Taint configs for Java and C#

## [v0.16.0] - 2026-04-22

### Added
- **Sanitizer-aware taint tracking**: `LanguageConfig.Sanitizers`
- Built-in sanitizers for JS/TS, Python, Go
- `isTaintedExpr` returns `false` for sanitizer calls
- Reduced false positives on sanitized data

## [v0.15.0] - 2026-04-22

### Added
- **Inter-procedural taint analysis**
- `FunctionSummary`: detects functions returning tainted data
- Tracks taint through: `req.body` → `getUserInput()` → `db.query()`
- Cross-file support preserved alongside inter-procedural

## [v0.14.0] - 2026-04-22

### Added
- **Rule DSL v2**:
  - `where` clauses: `not-constant`, `not-sanitized`, `not-test-file`, `inside-function`
  - Named capture group metavariables: `(?P<var>\w+)` → `$var` in messages/fixes
  - `inside` / `not-inside` pattern operators
- `raven rules validate` command
- Dynamic message/fix expansion with `expandMetavars()`

### Changed
- Rewrote key rules with new DSL (XSS, SQLi, command injection)

## [v0.13.0] - 2026-04-22

### Added
- Incremental caching with `.raven-cache.json`
- SHA256-per-file cache (skips unchanged files)
- `--no-cache` flag
- ~40-60% speedup on warm runs

## [v0.12.0] - 2026-04-22

### Added
- Cross-file taint analysis
- Import/export resolution for JS/TS/Python/Go
- Tracks taint across file boundaries

## [v0.11.0] - 2026-04-22

### Added
- Deep secrets scanning (`--secrets`)
- AWS keys, GitHub tokens, private keys, JWT detection
- Shannon entropy filtering (threshold 4.0)
- Test value exclusions

## [v0.10.0] - 2026-04-22

### Added
- Inline suppression comments:
  - `// raven-ignore: R001`
  - `// raven-ignore-next-line: R001,R002`
  - `// raven-ignore-next-line: all`
- `--no-ignore-comments` flag

## [v0.9.0] - 2026-04-22

### Added
- Baseline & diff scanning
- `--baseline`, `--update-baseline`
- Fuzzy matching (±5 lines)
- Exit 0 when no new findings

## [v0.8.0] - 2026-04-22

### Added
- Stability, tests, and polish
- 31 tests across 7 packages
- 7 bug fixes
