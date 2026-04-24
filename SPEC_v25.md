# Raven v2.5 SPEC — World's Best Open Source SAST

## Research Findings (what competitors do best)

### Semgrep
- pattern-either, pattern-not, pattern-inside, pattern-not-inside operators
- mode: taint with pattern-sources, pattern-sinks, pattern-sanitizers, pattern-propagators
- metavariable-regex, metavariable-comparison, focus-metavariable
- interfile analysis, taint_assume_safe_functions, taint_assume_safe_indexes
- 2,400+ community rules, 20,000+ Pro rules

### Brakeman (Rails)
- Confidence levels: High/Medium/Weak
- Interactive ignore wizard (brakeman -I)
- Scan comparison (--compare baseline.json)
- Framework-specific deep analysis (knows Rails routing, params flow)
- 33 warning types, 11 output formats

### Gosec
- CWE mapping for every rule
- #nosec annotations with justification
- Path-based rule exclusions
- SSA-based analyzers
- Rule IDs: G1xx (general), G2xx (injection), G3xx (file), G4xx (crypto), G5xx (blocklist), G6xx (correctness), G7xx (taint)

### CodeQL (GitHub)
- Deep data flow analysis across functions, modules, files
- Copilot Autofix — AI-generated fixes
- CodeQL database (10-30 min build for large repos)
- Powerful but steep learning curve (QL language)

### Mobb/Semgrep Assistant
- LLM-powered autofix generation from SARIF
- Contextual fix explanations
- Automatic PR creation

### Bearer (now Cycode)
- API key detection focus
- Risk Intelligence Graph
- 90% alert reduction via correlation

## Upgrade Plan

### Module 1: LLM Fix Generation v2 (CRITICAL)

#### 1.1 Vulnerability-Specific Prompt Templates
Each vulnerability class gets a tailored prompt with few-shot examples:
- SQL Injection → parameterized queries, ORM usage
- XSS → encoding, safe APIs, Content Security Policy
- Command Injection → subprocess with array args, avoid shell=True
- Path Traversal → path normalization, chroot, allowlists
- Hardcoded Secrets → env vars, secret managers
- Insecure Deserialization → safe formats, schema validation
- Weak Crypto → modern algorithms, key management
- SSRF → URL validation, allowlists, network segmentation
- JWT → proper verification, algorithm whitelist, key rotation
- Prototype Pollution → Object.freeze, schema validation

File: `internal/llm/prompts.go`

#### 1.2 Diff/Patch Generation
Instead of returning full fixed code, generate unified diff format:
```go
type FixPatch struct {
    OriginalCode string   // lines being replaced
    FixedCode    string   // replacement
    StartLine    int      // start line in original file
    EndLine      int      // end line in original file
    ContextLines int      // lines of context around change
    IsMultiFile  bool     // does fix require changes in other files?
    RelatedFiles []string // other files that need changes
}
```

#### 1.3 Exploitability Scorer
```go
type ExploitabilityScore struct {
    Score       float64 // 0.0-1.0
    Prerequisites []string // what attacker needs
    AttackVector  string   // network, local, adjacent
    Complexity    string   // high, medium, low
    Privileges    string   // none, low, high
    UserInteraction string // none, required
}
```

#### 1.4 Fix Validation
After generating a fix, validate it:
- Syntax check (parse as valid code in target language)
- Semantics check (fix actually addresses the vulnerability)
- No new vulnerabilities introduced
- No functionality broken

File: `internal/llm/validator.go`

#### 1.5 Security Advisory Integration
- CVE lookup for matched vulnerability patterns
- Link to relevant OWASP cheat sheets
- Link to language-specific security guides

### Module 2: #raven-ignore Annotations (from Gosec)

```go
// #raven-ignore sqli-001 -- Using parameterized query internally
// #raven-ignore secrets -- This is a test key, safe to ignore
// #raven-ignore CWE-798 -- Hardcoded credentials in test fixture
```

File: `internal/engine/annotations.go`
- Parse comments before findings
- Extract rule IDs, CWEs, categories to ignore
- Require justification after --
- Support block annotations:
```go
// #raven-ignore-begin sqli
... code ...
// #raven-ignore-end sqli
```

### Module 3: Scan Comparison (from Brakeman)

```bash
raven scan --compare baseline.json     # Compare against baseline
raven scan --save-baseline baseline.json # Save current as baseline
```

Shows: NEW findings, FIXED findings, UNCHANGED findings.

File: `internal/engine/comparison.go`

### Module 4: Quality Gates (from SonarQube)

```yaml
# .raven-policy.yaml
quality_gate:
  max_critical: 0
  max_high: 0
  max_medium: 5
  max_total: 20
  min_coverage: 80
  
new_code:
  max_critical: 0
  max_high: 0
  fail_on_new_secrets: true
  
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

### Module 5: CWE Top 25 2024 Full Coverage

Map every rule to CWE. Add missing rules for:
1. CWE-787: Out-of-bounds Write
2. CWE-79: Cross-site Scripting (XSS) ✓
3. CWE-89: SQL Injection ✓
4. CWE-416: Use After Free ✓
5. CWE-78: OS Command Injection ✓
6. CWE-20: Improper Input Validation
7. CWE-125: Out-of-bounds Read
8. CWE-22: Path Traversal ✓
9. CWE-352: Cross-Site Request Forgery (CSRF)
10. CWE-434: Unrestricted File Upload
11. CWE-862: Missing Authorization
12. CWE-476: NULL Pointer Dereference
13. CWE-287: Improper Authentication
14. CWE-190: Integer Overflow ✓
15. CWE-77: Command Injection ✓
16. CWE-119: Improper Restriction of Operations
17. CWE-798: Hardcoded Credentials ✓
18. CWE-918: Server-Side Request Forgery (SSRF) ✓
19. CWE-306: Missing Authentication
20. CWE-362: Race Condition ✓
21. CWE-269: Improper Privilege Management
22. CWE-94: Code Injection ✓
23. CWE-863: Incorrect Authorization
24. CWE-276: Incorrect Default Permissions
25. CWE-200: Information Exposure

### Module 6: 500+ More Rules

Fill gaps in coverage:
- HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Cookie security (Secure, HttpOnly, SameSite)
- CORS misconfigurations
- Insecure TLS/SSL configs
- JWT best practices
- OAuth/OpenID Connect security
- API security (GraphQL, REST, gRPC, WebSocket)
- Mobile-specific (Android, iOS)
- Container security (Docker, Kubernetes)
- IaC (Terraform, CloudFormation, Ansible, Pulumi)
- Supply chain (dependency confusion, typosquatting)

### Module 7: SARIF v2.1.0 Export Enhancement

Full SARIF 2.1.0 compliance for GitHub/GitLab integration:
- Complete run/tool info
- All SARIF levels (error, warning, note, none)
- Code flows for taint analysis
- Related locations
- Fixes in SARIF format (for auto-fix tools)
- Suppressions (for #raven-ignore)
- Taxa (CWE mapping)

### Module 8: Semgrep-Style Operators

Add to rule engine:
```yaml
patterns:  # AND
  - pattern: "..."
  - pattern: "..."
pattern-either:  # OR
  - pattern: "..."
  - pattern: "..."
pattern-not: "..."  # exclude
pattern-inside: "..."  # only match inside this context
pattern-not-inside: "..."  # don't match inside this context
metavariable-regex:
  metavariable: $X
  regex: "^[A-Z]+$"
focus-metavariable: $X
```
