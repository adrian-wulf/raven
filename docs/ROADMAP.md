# Raven Development Roadmap

> "The best security tool is the one you actually use."

This roadmap prioritizes **user value** over technical complexity. Each milestone delivers a tangible improvement that makes Raven more useful to vibe coders.

---

## Milestone 1: v0.1 "It Works" ✅ DONE

**Goal:** Prove the concept. Raven scans code and finds real vulnerabilities.

**Delivered:**
- [x] Core rule engine (regex-based, concurrent)
- [x] 10 security rules (JS/TS, Python, Go, PHP)
- [x] CLI: `scan`, `fix`, `watch`, `rules`, `ci`, `learn`, `init`
- [x] Pretty terminal output with code snippets
- [x] JSON + SARIF output
- [x] Deduplication engine
- [x] Config system (YAML)

**Success Criteria:**
- Scans 1 file in < 5ms
- Finds all 7 vulnerabilities in test app
- Zero external dependencies beyond Go stdlib + CLI libs

**Status:** ✅ COMPLETE

---

## Milestone 2: v0.2 "Actually Useful" (2-3 weeks)

**Goal:** Raven catches the bugs people actually ship. Not a demo anymore.

**Why this matters:** 10 rules is a toy. 50+ rules covering the OWASP Top 10 + common AI mistakes makes Raven a real tool.

### 2.1 Rules Expansion (Priority: CRITICAL)

**Target: 50 rules across all languages**

New rule categories:

| Category | Rules | Languages |
|----------|-------|-----------|
| SQL Injection | 8 | JS, TS, Python, Go, PHP, Java |
| XSS | 6 | JS, TS, PHP |
| Hardcoded Secrets | 5 | All |
| Command Injection | 4 | JS, Python, Go, PHP, Ruby |
| Path Traversal | 4 | JS, Python, Go, PHP, Java |
| Insecure Crypto | 5 | All (MD5, SHA1, ECB, weak RSA, random) |
| Auth Bypass | 4 | All (missing auth, weak JWT, default creds) |
| SSRF | 3 | JS, Python, Go, PHP |
| CSRF | 2 | JS, Python, PHP |
| Prototype Pollution | 2 | JS |
| Insecure Headers | 3 | JS, Python, Go |
| Race Conditions | 2 | Go, JS |
| Deserialization | 2 | JS, Python, Java, PHP |

**AI-specific rules** (the killer feature):
- `console.log` with sensitive data
- `TODO/FIXME` security comments left by AI
- Default admin credentials (`admin/admin123`)
- Debug mode left enabled (`debug: true`, `app.run(debug=True)`)
- CORS set to `*` in production
- Missing rate limiting on auth endpoints

### 2.2 Fix Engine Rewrite (Priority: HIGH)

**Current state:** 1/5 fixes work. Regex-based fixes are too fragile.

**Solution:** Template-based fix system

```yaml
fix:
  description: Replace string concat SQL with parameterized query
  match_template: '{db}.query({query} + {user_input})'
  replace_template: '{db}.query({query} + "?", [{user_input}])'
```

**Target:** 80% of findings have working fixes.

### 2.3 False Positive Reduction (Priority: HIGH)

**Current state:** Some rules match test files, comments, or safe patterns.

**Improvements:**
- Exclude patterns: `test_`, `spec.`, `example`, `demo`, `mock`
- Comment-aware scanning (skip matches inside `//` or `/* */`)
- String-literal-only matches (don't match variable names)
- Configurable confidence levels per rule

### 2.4 Baseline / Ignore File (Priority: MEDIUM)

**Feature:** `.ravenignore` file + baseline mode

```bash
# Create baseline (ignore current findings)
raven scan --create-baseline

# Future scans only show NEW findings
raven scan --baseline .raven-baseline.json
```

### 2.5 Better Output (Priority: MEDIUM)

- Diff view for fixes (`raven fix --show-diff`)
- Severity filtering in output (`raven scan --only critical,high`)
- Statistics: files scanned, lines scanned, time per rule
- Progress bar for large codebases

### Success Criteria
- [ ] 50+ rules, all tested on real open-source projects
- [ ] Fixes work for 80%+ of findings
- [ ] Zero false positives on 5 real projects tested
- [ ] Scans 1000 files in < 1 second

---

## Milestone 3: v0.3 "In Your Editor" (2-3 weeks)

**Goal:** Raven lives where developers work - in the IDE.

**Why this matters:** CLI is great for CI. But developers need instant feedback while coding. This is where ESLint, Prettier, and Rust Analyzer live. Raven needs to be there too.

### 3.1 LSP Server (Priority: CRITICAL)

**Feature:** Language Server Protocol implementation

```bash
raven lsp  # Starts LSP server
```

**Capabilities:**
- Diagnostics on save (or on type)
- Code actions ("Fix this vulnerability")
- Hover info ("Why is this dangerous?")
- Quick fixes via IDE UI

**Tech:** `github.com/tliron/glsp` or custom LSP over stdio

### 3.2 VS Code Extension (Priority: CRITICAL)

**Feature:** Official VS Code extension

**Functionality:**
- Auto-start LSP server
- Sidebar panel with all findings
- "Fix All" button
- Config UI (no YAML editing)
- Status bar icon (green/red)

**Publishing:** VS Code Marketplace

### 3.3 Cursor Extension (Priority: HIGH)

Cursor is the #1 vibe coding IDE. Same extension as VS Code (Cursor uses VS Code extensions), but we optimize for:
- Cursor-specific workflows
- Integration with Cursor's AI chat ("@raven fix this")

### 3.4 Zed / Vim / Neovim Support (Priority: LOW)

- Zed: Native extension API
- Vim/Neovim: Via LSP + ALE / CoC / nvim-lspconfig

### Success Criteria
- [ ] Developer sees red squiggles within 1 second of saving a file
- [ ] "Fix" code action works in IDE
- [ ] Extension published to VS Code Marketplace
- [ ] 100+ downloads in first week

---

## Milestone 4: v0.4 "Ship With Confidence" (1-2 weeks)

**Goal:** Raven protects every commit and PR.

### 4.1 GitHub Action (Priority: CRITICAL)

**Feature:** Official GitHub Action

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  raven:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: raven-security/raven-action@v1
        with:
          fail-on: high
          format: sarif
      - uses: github/codeql-action/upload-sarif@v3
```

**Features:**
- PR annotations (comments on vulnerable lines)
- SARIF upload to GitHub Advanced Security
- Configurable severity thresholds
- Baseline support (only new findings fail)

### 4.2 Pre-commit Hook (Priority: HIGH)

```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/raven-security/raven
    rev: v0.4.0
    hooks:
      - id: raven
```

### 4.3 GitLab CI Integration (Priority: MEDIUM)

```yaml
# .gitlab-ci.yml
raven:
  image: ravensecurity/raven:latest
  script:
    - raven ci --format sarif --output raven.sarif
  artifacts:
    reports:
      sast: raven.sarif
```

### 4.4 Slack / Discord Notifications (Priority: LOW)

Notify team when critical findings are detected in CI.

### Success Criteria
- [ ] GitHub Action published to Marketplace
- [ ] PR annotations work
- [ ] Pre-commit hook setup takes < 30 seconds
- [ ] Used in 10+ real projects

---

## Milestone 5: v0.5 "Smart" (3-4 weeks)

**Goal:** Raven understands code, not just patterns.

**Why this matters:** Regex has limits. AST analysis finds bugs regex can't:
- Data flow: user input → sink (SQL query, exec, etc.)
- Context-aware: `const query = "SELECT..."` is safe unless `query` is later executed with user input
- Framework-aware: Next.js `getServerSideProps`, Express middleware, Flask decorators

### 5.1 Tree-sitter Integration (Priority: CRITICAL)

**Feature:** Parse code into AST for precise analysis

```go
// Instead of regex:
// pattern: "query(.*\\+.*req\\."

// AST query:
query: |
  (call_expression
    function: (identifier) @fn (#eq? @fn "query")
    arguments: (argument_list
      (binary_expression
        left: (string)
        right: (member_expression) @input)))
```

**Benefits:**
- Zero false positives from comments/strings
- Tracks variables across assignments
- Understands function calls and arguments
- Multi-language with one parser

**Tech:** `github.com/tree-sitter/go-tree-sitter` or WASM bindings

### 5.2 Data Flow Analysis (Priority: HIGH)

**Feature:** Track user input from source to sink

```javascript
// Raven traces: req.body.name → query → db.query()
const name = req.body.name;      // SOURCE
const query = "SELECT * WHERE name = '" + name + "'";  // PROPAGATION
db.query(query);                  // SINK → ALERT!
```

**Implementation:**
- Build simple CFG (Control Flow Graph)
- Track tainted variables
- Report when tainted data reaches sink

### 5.3 Framework-Specific Rules (Priority: HIGH)

Rules that understand popular frameworks:

| Framework | Rules |
|-----------|-------|
| Express.js | Missing helmet, CORS *, no rate limit |
| Next.js | getServerSideProps injection, API route auth |
| FastAPI | Depends() bypass, CORS misconfig |
| Django | @csrf_exempt misuse, raw() queries |
| Flask | @app.route without auth, session config |
| React | dangerouslySetInnerHTML, href="javascript:" |

### 5.4 Supply Chain Scanning (Priority: MEDIUM)

**Feature:** Check dependencies for known vulnerabilities

```bash
raven scan --deps  # Check package.json, requirements.txt, go.mod
```

**Integration:** OSV (Open Source Vulnerabilities) API or local database

### Success Criteria
- [ ] 50% reduction in false positives vs regex-only
- [ ] Finds vulnerabilities regex misses
- [ ] Framework rules for top 10 web frameworks
- [ ] Dependency scanning works offline

---

## Milestone 6: v1.0 "Production Ready" (2-3 weeks)

**Goal:** Raven is the default security tool for vibe coders.

### 6.1 Performance Optimization
- Incremental scanning (only changed files)
- Parallel rule evaluation
- Memory optimization for large monorepos
- Target: 10,000 files in < 5 seconds

### 6.2 Enterprise Features
- Team dashboards
- Centralized policy management
- SSO / SAML
- Audit logging

### 6.3 Cloud (Optional)
- Managed scanning service
- Web dashboard
- Historical trends
- **Note:** Keep local-first as default. Cloud is opt-in.

### 6.4 Documentation & Community
- Interactive documentation site
- Video tutorials
- Discord community
- Rule contribution guide
- Bug bounty program for Raven itself

### 6.5 Stability
- 100% test coverage on engine
- Fuzz testing on rules
- Benchmark suite
- Regression tests

### Success Criteria
- [ ] 1,000+ GitHub stars
- [ ] 10,000+ VS Code extension installs
- [ ] Used by 100+ projects in production
- [ ] Community-contributed rules
- [ ] Stable API (semantic versioning)

---

## Timeline Summary

| Milestone | Version | Duration | Key Deliverable |
|-----------|---------|----------|-----------------|
| Foundation | v0.1 | ✅ Done | Working scanner |
| Rules + Fixes | v0.2 | 2-3 weeks | 50 rules, 80% fix rate |
| IDE Integration | v0.3 | 2-3 weeks | VS Code extension |
| CI/CD | v0.4 | 1-2 weeks | GitHub Action |
| AST + Smart | v0.5 | 3-4 weeks | Tree-sitter, data flow |
| Production | v1.0 | 2-3 weeks | Stability, docs, community |

**Total: ~3 months to v1.0**

---

## Decision Points

### Go vs AST-first?
**Decision:** Do v0.2 (rules) first, then v0.3 (IDE), then v0.5 (AST).
**Rationale:** 50 good regex rules deliver more value than 10 AST rules. IDE integration drives adoption. AST is the long-term moat.

### Free vs Paid?
**Decision:** Core is forever free. Cloud features may be paid.
**Rationale:** Security tools must be accessible. Monetize via enterprise cloud, not basic scanning.

### Rules in-repo vs marketplace?
**Decision:** Core rules in-repo. Community rules via git submodule or registry.
**Rationale:** Zero-setup is critical for adoption. Power users can extend.

---

## Next Steps (What to do NOW)

1. **Implement v0.2 rules** (this week)
   - Add 20 most important rules
   - Fix the fix engine
   - Test on 5 real open-source projects

2. **Pick an open-source project to test on**
   - Find a popular JS/Python/Go repo
   - Run Raven on it
   - Document false positives
   - Iterate rules

3. **Prepare for v0.3**
   - Research LSP implementation
   - Set up VS Code extension scaffold

---

*Last updated: April 2026*
