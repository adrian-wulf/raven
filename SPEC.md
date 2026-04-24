# Raven SAST Scanner — Total Upgrade Specification

## Project Overview
Raven is a Go-based static application security testing (SAST) scanner using Tree-sitter for AST parsing. We are upgrading it from 455 rules to 2000+ rules, adding 10+ new languages, drastically reducing false positives, and adding framework-aware detection.

## Architecture
- **Language**: Go 1.23+
- **Module**: `github.com/raven-security/raven`
- **Base path**: `/mnt/agents/output/raven`
- **Key packages**:
  - `internal/engine` — core scanning engine (regex + AST + taint)
  - `internal/taint` — taint analysis tracker
  - `internal/ast` — Tree-sitter AST parser
  - `internal/cli` — CLI commands
  - `rules/` — YAML rule files organized by language/category

## Upgrade Modules

### Module 1: Core Engine FP Reduction
**Engineer**: `engine_upgrader`
**Branch**: `upgrade-engine`

Enhance `internal/engine/engine.go` and related files:

1. **Confidence Scoring System** — Add a `ScoreConfidence(finding Finding, content []byte) float64` function that calculates confidence (0.0-1.0) based on:
   - Context depth (how many layers of validation surround the finding)
   - Pattern specificity (regex vs AST vs taint — taint=highest)
   - Sink sensitivity (SQL query arg 0 > arg N)
   - Presence of sanitizers in scope
   - Data flow path length (shorter = higher confidence)
   - Add `ConfidenceScore float64` to Finding struct

2. **Dead Code Detection** — Add `internal/engine/deadcode.go`:
   - Detect unreachable code blocks (after return/break/continue)
   - Detect commented-out code regions
   - Skip findings in dead code regions
   - Functions: `IsDeadCode(content []byte, line int) bool`

3. **Input Validation Awareness** — Enhance `isSanitized()`:
   - Add 50+ common validation patterns per language
   - Regex validation, type casting, length checks
   - Whitelist checks, enum validation
   - Language-specific validators (joi, pydantic, zod, validator, etc.)

4. **Multi-Pattern Correlation** — Add correlation engine:
   - When multiple patterns in same rule match nearby, boost confidence
   - Cross-reference related rules for same vulnerability class
   - Reduce confidence for single-pattern matches

5. **Path Sensitivity** — Add basic path analysis:
   - Detect if/else branches where one branch sanitizes
   - Flag findings only when ALL paths to sink are tainted
   - Skip findings where at least one path has validation

### Module 2: Taint Analysis Upgrade
**Engineer**: `taint_upgrader`
**Branch**: `upgrade-taint`

Enhance `internal/taint/tracker.go` and `internal/taint/config.go`:

1. **Inter-Procedural Deep Analysis**:
   - Track taint through function parameters and return values
   - Handle callback/promise chains (JS)
   - Handle context propagation (Go ctx, Python flask.g)
   - Track through struct/object fields

2. **Enhanced Sanitizer Detection**:
   - Per-language sanitizer libraries (DOMPurify, bleach, html/template, etc.)
   - Built-in sanitizers (encodeURIComponent, htmlspecialchars, etc.)
   - Custom sanitizer registration via rules
   - Sanitizer chaining awareness

3. **Taint Config Expansion**:
   - Add `internal/taint/config_dart.go`, `config_elixir.go`, `config_scala.go`, `config_lua.go`, `config_solidity.go`, `config_bash.go`
   - Each with language-specific sources, sinks, sanitizers

### Module 3: Rule Expansion — JavaScript/TypeScript
**Engineer**: `rules_js_upgrader`
**Branch**: `upgrade-rules-js`

Expand `rules/javascript/` from ~53 to 200+ rules:

**Categories to add** (keep existing, add these):
- **Prototype Pollution** (10 rules): lodash set, Object.assign, recursive merge
- **SSRF** (10 rules): fetch with user URL, axios user-controlled URL, request to internal IPs
- **Open Redirect** (8 rules): res.redirect with user input, window.location with user input
- **JWT Security** (8 rules): none algorithm, weak secret, missing verification
- **NoSQL Injection** (8 rules): MongoDB $where, $ne operator injection
- **DOM Clobbering** (5 rules): named DOM elements shadowing globals
- **React Security** (10 rules): dangerouslySetInnerHTML with user data, href with user input, script injection in JSX
- **Vue Security** (5 rules): v-html with user data, component injection
- **Angular Security** (5 rules): bypassSecurityTrust, ng-bind-html
- **Express Security** (10 rules): body-parser config, helmet missing, CORS misconfig, session config
- **Next.js/Nuxt** (5 rules): getServerSideProps injection, middleware issues
- **GraphQL** (8 rules): query depth, introspection, injection, DoS
- **WebSocket Security** (5 rules): ws message handling, protocol issues
- **Crypto** (10 rules): weak algorithms, IV reuse, insufficient key length, Math.random for crypto
- **Race Conditions** (5 rules): shared mutable state, async timing issues
- **Regex DoS** (5 rules): ReDoS patterns in user input
- **File Upload** (8 rules): unrestricted upload, path traversal in filename, extension bypass
- **Local Storage** (5 rules): sensitive data in localStorage/sessionStorage
- **PostMessage** (5 rules): missing origin check, wildcard origin
- **CSP Bypass** (5 rules): unsafe-inline, unsafe-eval, wildcard source
- **Clipboard** (3 rules): paste event XSS
- **WebRTC** (3 rules): IP leak, media stream issues
- **Service Worker** (3 rules): cache poisoning, scope issues
- **iFrame** (5 rules): sandbox attribute missing, allow-scripts
- **Import/Require** (5 rules): dynamic require with user input, path traversal

### Module 4: Rule Expansion — Python
**Engineer**: `rules_python_upgrader`
**Branch**: `upgrade-rules-python`

Expand `rules/python/` from ~34 to 150+ rules:

- **Django Security** (20 rules): SQLi via ORM raw, XSS via |safe, CSRF bypass, settings issues, mass assignment, pickle in sessions
- **Flask Security** (15 rules): Jinja autoescape disabled, session signing, before_request issues, send_file path traversal
- **FastAPI Security** (10 rules): dependency injection issues, background task RCE, openapi exposure
- **SQLAlchemy** (8 rules): text() injection, raw SQL in ORM, connection string exposure
- **Deserialization** (10 rules): pickle.loads, yaml.load, json.loads with eval, marshal, shelve
- **Subprocess** (8 rules): shell=True variants, os.system, subprocess.Popen, popen2
- **Path Traversal** (8 rules): open with user path, send_file, static file serving
- **SSRF** (8 rules): urllib with user URL, requests to internal, aiohttp SSRF
- **Template Injection** (8 rules): Jinja2 SSTI, Tornado, Mako, Django template RCE
- **Crypto** (8 rules): weak hashes (md5, sha1), hardcoded keys, ECB mode, insufficient iterations
- **Django REST Framework** (5 rules): serializer bypass, permission issues, throttle bypass
- **Celery** (5 rules): pickle serialization, task injection
- **Logging** (5 rules): log injection, sensitive data in logs
- **ORM Injection** (5 rules): Django ORM injection, Peewee, PonyORM
- **AWS/Boto** (5 rules): hardcoded credentials, bucket enumeration, IAM issues
- **Regex DoS** (5 rules): ReDoS patterns
- **Pickle variants** (5 rules): cpickle, dill, cloudpickle
- **XML** (5 rules): XXE, entity expansion, lxml parsing
- **Environment** (5 rules): hardcoded secrets in settings, DEBUG=True
- **Code Execution** (5 rules): exec, eval, compile, __import__, importlib

### Module 5: Rule Expansion — Go + Java + PHP + C/C++ + C# + Rust + Ruby + Kotlin + Swift
**Engineer**: `rules_other_upgrader`
**Branch**: `upgrade-rules-other`

Expand each language's rules:

**Go** (24 → 100+):
- SQLi via database/sql, GORM, Bun (10 rules)
- XSS via html/template (5 rules)
- Command injection via os/exec (5 rules)
- Path traversal (5 rules)
- Race conditions (5 rules)
- Cryptography (5 rules)
- HTTP middleware issues (5 rules)
- JWT/Gin/Echo/Fiber framework rules (15 rules)
- Memory safety (5 rules)
- Error handling info leak (5 rules)
- SSRF (5 rules)
- Reflection/dynamic code (5 rules)
- Deserialization (5 rules)
- goroutine leaks (5 rules)
- Insecure HTTP config (5 rules)

**Java** (17 → 120+):
- Spring Boot security (20 rules): @RequestParam injection, @PathVariable trust, SpEL injection, Actuator exposure
- Hibernate/JPA injection (8 rules)
- Deserialization (10 rules): ObjectInputStream, XStream, Jackson, Fastjson
- XSS via JSP/Thymeleaf (8 rules)
- XXE (8 rules): SAXParser, DocumentBuilder, TransformerFactory
- SSRF (5 rules)
- LDAP injection (5 rules)
- XPath injection (5 rules)
- Expression Language injection (5 rules)
- Struts/Servlet (10 rules)
- Android-specific (10 rules): WebView XSS, Intent injection, SharedPreferences leak
- Crypto (5 rules)
- Log4j/Logging (5 rules): log injection, JNDI lookup
- File upload (5 rules)
- Mass assignment (5 rules)
- CORS (3 rules)

**PHP** (22 → 100+):
- Laravel security (15 rules): Eloquent injection, Blade XSS, middleware issues, mass assignment
- Symfony security (10 rules): Twig SSTI, form validation bypass
- WordPress (10 rules): plugin vulnerabilities, option injection, nonce bypass
- SQLi via PDO/mysqli (10 rules)
- XSS (8 rules): echo user input, print_r, var_dump
- File inclusion (8 rules): include/require with user path, LFI/RFI
- Command injection (5 rules): system, exec, passthru, shell_exec, backticks
- Deserialization (5 rules): unserialize, phar deserialization
- XXE (5 rules): libxml_disable_entity_loader, SimpleXML
- SSRF (5 rules): curl with user URL, file_get_contents
- Open redirect (5 rules): header(Location)
- Crypto (5 rules): weak hash, ECB, random_bytes
- Session fixation (3 rules)
- Mail header injection (3 rules)
- Type juggling (3 rules)
- Eval/code execution (5 rules)

**C/C++** (20 → 80+):
- Buffer overflow extended (15 rules): strcpy, strcat, sprintf, gets, memcpy bounds
- Format string (8 rules): printf with user format, syslog
- Integer overflow (8 rules): signed/unsigned, wraparound
- Use-after-free (8 rules): dangling pointers, double-free
- Race conditions (5 rules): TOCTOU, signal handlers
- Command injection (5 rules): system, popen, exec family
- Cryptography (5 rules): weak random, hardcoded keys, deprecated algorithms
- Memory leaks (5 rules): malloc without free, resource leaks
- Injection (5 rules): SQLi via sqlite3_exec, command injection
- Path traversal (5 rules): fopen with user path
- SSRF (5 rules): curl usage
- Info disclosure (5 rules): error messages, stack traces

**C#** (11 → 80+):
- ASP.NET Core (15 rules): model binding injection, Razor XSS, middleware, auth bypass
- Entity Framework (8 rules): RawSqlCommand, SQL injection, LINQ injection
- Deserialization (8 rules): BinaryFormatter, Json.NET, DataContractSerializer
- XSS (8 rules): Razor @Html.Raw, Response.Write, innerHtml
- XXE (5 rules): XmlReader, XDocument, XmlTextReader
- SSRF (5 rules): HttpClient with user URL
- Command injection (5 rules): Process.Start, cmd.exe
- Crypto (5 rules): weak algorithms, hardcoded keys, RNG
- LDAP injection (3 rules): DirectorySearcher
- XPath injection (3 rules): XPathNavigator
- Mass assignment (5 rules): [Bind], model binding
- Session management (5 rules): cookie config, session fixation
- File upload (5 rules): IFormFile path traversal
- ViewState (3 rules): MAC disabled, encryption disabled
- Authorization (5 rules): [AllowAnonymous] misuse, [Authorize] bypass

**Rust** (13 → 70+):
- SQLi via diesel, sqlx, tokio-postgres (8 rules)
- Command injection via std::process (5 rules)
- Path traversal via std::fs (5 rules)
- XSS in templates (5 rules): Tera, Askama, Handlebars
- Deserialization (5 rules): serde with untrusted
- Crypto (5 rules): weak random, hardcoded keys
- Rocket framework (5 rules)
- Actix-web (5 rules)
- Axum (5 rules)
- Unsafe code patterns (10 rules): pointer derefs, transmute, FFI
- Concurrency (5 rules): Send/Sync misuse, data races
- Panic safety (5 rules)
- Memory safety in unsafe (5 rules)
- SSRF (3 rules): reqwest with user URL
- Log injection (3 rules)

**Ruby** (7 → 60+):
- Rails security (20 rules): ActiveRecord injection, ERB SSTI, Strong Parameters bypass, CSRF, mass assignment
- Sinatra (5 rules): param injection, template injection
- ERB (5 rules): user-controlled templates
- SQLi (8 rules): ActiveRecord conditions, find_by_sql, execute
- XSS (5 rules): html_safe, raw, content_tag
- Command injection (5 rules): system, backticks, exec, popen, eval
- Deserialization (5 rules): YAML.load, Marshal.load, JSON.parse
- File operations (5 rules): File.open, send_file, Pathname
- Crypto (3 rules): weak digest, hardcoded secrets
- SSRF (3 rules): Net::HTTP, open-uri, RestClient
- Open redirect (3 rules): redirect_to
- Regex DoS (3 rules)

**Kotlin** (7 → 50+):
- Android security (15 rules): WebView XSS, Intent injection, SharedPreferences, BroadcastReceiver, exported components
- Spring (8 rules): similar to Java Spring
- Server-side (10 rules): Ktor security, Exposed SQLi
- Deserialization (5 rules): ObjectInputStream, Jackson, Gson
- Crypto (5 rules): weak algorithms, hardcoded keys
- File operations (3 rules)
- SSRF (3 rules)

**Swift** (6 → 40+):
- iOS security (15 rules): WebView XSS, URL scheme hijacking, pasteboard leak, keychain issues, TouchID bypass
- Server-side (10 rules): Vapor security, Kitura, Perfect
- SQLi (5 rules): Core Data, SQLite.swift, GRDB
- Deserialization (5 rules): NSCoding, NSKeyedUnarchiver, Codable
- Crypto (3 rules): weak random, hardcoded keys
- SSRF (3 rules): URLSession
- File operations (3 rules)

### Module 6: New Languages + Secret Scanner + IaC
**Engineer**: `new_langs_upgrader`
**Branch**: `upgrade-new-langs`

1. **Add Tree-sitter parsers to `internal/ast/languages.go`** for:
   - Dart (`.dart`) — uses `github.com/smacker/go-tree-sitter/dart`
   - Elixir (`.ex`, `.exs`) — uses `github.com/smacker/go-tree-sitter/elixir`
   - Scala (`.scala`, `.sc`) — uses `github.com/smacker/go-tree-sitter/scala`
   - Lua (`.lua`) — uses `github.com/smacker/go-tree-sitter/lua`
   - Solidity (`.sol`) — uses `github.com/smacker/go-tree-sitter/solidity` if available, else regex-only
   - Bash (`.sh`, `.bash`) — regex-based
   - Dockerfile — regex-based
   - Terraform (`.tf`, `.tfvars`) — regex-based or HCL parser
   - YAML (`.yaml`, `.yml`) — regex-based security patterns
   - JSON — regex-based

2. **Create taint configs** for each new language

3. **Create initial rule sets** (20-30 rules each):
   - `rules/dart/`: SQLi (sqflite), command injection, XSS, hardcoded secrets, insecure HTTP, path traversal
   - `rules/elixir/`: SQLi (Ecto), command injection, XSS (Phoenix), template injection, DoS
   - `rules/scala/`: SQLi (Slick, Anorm), XSS (Twirl), deserialization, Play framework issues
   - `rules/lua/`: command injection, SQLi, path traversal, deserialization
   - `rules/solidity/`: reentrancy, integer overflow, unchecked calls, timestamp dependence, access control
   - `rules/bash/`: command injection, path traversal, hardcoded secrets, eval, SSRF
   - `rules/dockerfile/`: latest tag, secrets in ENV, running as root, no HEALTHCHECK, exposed secrets
   - `rules/terraform/`: hardcoded credentials, open security groups, unencrypted storage, public S3 bucket
   - `rules/yaml/`: hardcoded secrets, misconfigs, dangerous patterns

4. **Secret Scanner v2** — Expand `internal/secrets/scanner.go`:
   - Add 100+ secret patterns:
     - AWS Access Key ID, Secret Key, Session Token
     - GitHub Personal Access Token (classic + fine-grained)
     - GitLab PAT, Runner Token
     - Slack Token, Webhook URL
     - Stripe API Key, Publishable Key
     - SendGrid API Key
     - Twilio SID, Auth Token
     - Mailgun API Key
     - Firebase API Key, FCM Token
     - Heroku API Key
     - JWT secrets, RSA private keys, EC private keys
     - PKCS#8, PKCS#12, X.509 private keys
     - OpenAI API Key, Anthropic Key
     - Database connection strings (PostgreSQL, MySQL, MongoDB, Redis)
     - OAuth Client Secret, Client ID
     - Bearer tokens in various formats
     - Basic Auth in URLs
     - NPM, PyPI, RubyGems, Docker registry tokens
     - Kubernetes secrets, service account tokens
     - Azure SAS token, Storage account key
     - GCP API Key, Service Account JSON
     - Datadog API Key, App Key
     - PagerDuty Integration Key
     - Sentry Auth Token
     - New Relic API Key
     - Terraform Cloud Token
     - Vault Token
     - Grafana API Key
     - Prometheus Basic Auth
     - Elasticsearch credentials
     - RabbitMQ credentials
     - Kafka credentials
     - LDAP bind DN/password
     - SMTP credentials
     - SSH private keys (all formats)
     - API keys with common prefixes (sk-, pk-, ak-, bk-, etc.)
   - Entropy-based detection for generic secrets
   - Context-aware filtering (skip example/test keys)

### Module 7: Framework Detection + AI FP Filter
**Engineer**: `framework_upgrader`
**Branch**: `upgrade-framework`

1. **Enhance `internal/framework/detector.go`**:
   - Add detection for: Express, Fastify, NestJS, Next.js, Nuxt, Django, Flask, FastAPI, Rails, Laravel, Symfony, Spring Boot, ASP.NET Core, Gin, Echo, Fiber, Rocket, Actix, Axum, Vapor, Kitura, React Native, Flutter, Android, iOS
   - Detect from package.json, go.mod, requirements.txt, Gemfile, pom.xml, build.gradle, Cargo.toml, composer.json, Podfile, pubspec.yaml
   - Framework version detection for known-vulnerable versions

2. **Framework-specific taint configs**:
   - `internal/taint/frameworks/` — per-framework source/sink/sanitizer mappings
   - Express: req.params, req.query, req.body → res.send, db.query, eval
   - Django: request.GET, request.POST → render, execute, mark_safe
   - Flask: request.args, request.form → render_template_string, os.system
   - Rails: params[], request → render, eval, system
   - Laravel: Request::input, Input:: → DB::raw, eval, shell_exec
   - Spring: @RequestParam, @PathVariable → JdbcTemplate, Runtime.exec

3. **AI False Positive Filter** — Add `internal/engine/fp_filter.go`:
   - Post-processing module that scores findings for FP likelihood
   - Context analysis: is finding in test code, example, documentation?
   - Semantic analysis: does variable name suggest it's safe? (sanitized_*, safe_*, escaped_*)
   - Flow analysis: is there validation between source and sink?
   - Cross-reference with known-good patterns
   - Auto-suppress findings with FP score > 0.8
   - Configurable threshold

### Module 8: Test Suite + Build Verification
**Engineer**: `test_upgrader`
**Branch**: `upgrade-tests`

1. Write comprehensive tests for all new engine features
2. Write rule validation tests for new rules
3. Verify `go build ./...` passes
4. Verify `go test ./...` passes
5. Create integration test harness

## Rule YAML Format (unchanged from original)
```yaml
id: lang-category-###
name: Descriptive Rule Name
severity: critical|high|medium|low|info
category: sqli|xss|cmdi|pathtraversal|crypto|secrets|ssrf|...
confidence: high|medium|low
cwe: "CWE-XXX"
languages: [javascript|python|go|...]
frameworks: [express|django|flask|...]  # optional
message: "What the developer should know and how to fix"
patterns:
  - type: regex|literal|ast-query|taint
    pattern: "regex_or_query"
    sources: ["source_pattern"]  # for taint
    sinks: ["sink_pattern"]      # for taint
    where:
      - not-constant: true
      - not-sanitized: ["sanitizer1", "sanitizer2"]
      - not-test-file: true
      - inside-function: "function_pattern"
references:
  - https://cwe.mitre.org/data/definitions/XXX.html
  - https://owasp.org/...
fix:
  description: "How to fix"
  pattern: "regex_to_match"
  replace: "replacement_template"
```

## Deliverables
- All branches merged to `master`
- `go build ./...` passes
- `go test ./...` passes
- Total rule count > 2000
- 25+ languages supported
- FP reduction mechanisms active
- Documentation updated
