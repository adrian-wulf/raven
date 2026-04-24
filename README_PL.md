# Raven v3.3

> **AI-native skaner bezpieczenstwa. Zbudowany dla vibe coderow. Zaprojektowany na zero false positives.**
>
> 1,900+ regul. 35 kategorii jezykowych. 10 dostawcow LLM do auto-naprawy. 7-warstwowa redukcja FP.

[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Reguly](https://img.shields.io/badge/reguly-1,900+-success?logo=shield)](rules)
[![Jezyki](https://img.shields.io/badge/jezyki-35+-orange?logo=code)](rules)

---

## Instalacja

### Opcja 1: go install (zalecana)

```bash
go install github.com/raven-security/raven/cmd/raven@latest
```

Wymaga Go 1.25+.

### Opcja 2: Pobierz binarke

```bash
# Linux/macOS
curl -sL https://github.com/adrian-wulf/raven/releases/latest/download/raven-linux-amd64.tar.gz | tar xz
sudo mv raven /usr/local/bin/

# Lub pobierz najnowszy release z:
# https://github.com/adrian-wulf/raven/releases
```

### Opcja 3: Homebrew

```bash
brew tap adrian-wulf/raven https://github.com/adrian-wulf/raven
brew install raven
```

### Opcja 4: Docker

```bash
docker build -t raven https://github.com/adrian-wulf/raven.git#main
docker run --rm -v $(pwd):/code raven scan /code
```

---

## Problem

Napisales aplikacje z pomoca Cursor/Claude/Copilot. Dziala. Wysylasz na produkcje.

**Ale Twoj asystent AI wlasnie napisal:**
- SQL injection poprzez konkatenacje stringow
- XSS przez `innerHTML`
- Zakodowane na stale klucze API
- `eval()` z danymi uzytkownika
- Command injection przez `exec()`
- Brak ochrony CSRF
- JWT podpisany algorytmem "none"
- Sekrety w logach konsoli

**Ty tego nie zauwazyles. Atakujacy tak.**

Raven wykrywa dokladnie te podatnosci w **< 1 sekundy**.

---

## Szybki start

```bash
# Przeskanuj swoj projekt
cd moj-projekt
raven scan

# Skanuj tylko pliki w stagingu (natychmiastowy pre-commit)
raven scan --staged

# Naprawy wspierane przez AI (wielu dostawcow)
export OPENROUTER_API_KEY=your-key
raven fix-ai

# Tryb obserwacji podczas developmentu
raven watch

# Tryb CI z wyjsciem SARIF
raven ci --format sarif --output report.sarif

# Wymuszanie progow bezpieczenstwa
raven scan --policy .raven-policy.yaml

# Porownanie z baseline (zglasza TYLKO NOWE problemy)
raven scan --baseline .raven-baseline.json
raven scan --update-baseline

# Raport HTML do podzielenia sie z zespolem
raven scan --format html -o raport-bezpieczenstwa.html

# Gleboki skan z detekcja sekretow + bez cache
raven scan --secrets --no-cache

# Tylko findings z wysoka confidence
raven scan --confidence high --min-sev medium

# Walidacja wszystkich regul przed CI
raven rules validate

# Zobacz score jakosci regul
raven rules --score | head -20
```

---

## Co nowego w v3.3

### Zapis do pliku (`--output`)
Zapisuj raporty bezpośrednio do plików w dowolnym formacie:

```bash
raven scan --format html -o raport-bezpieczenstwa.html
raven scan --format sarif -o wyniki.sarif
raven scan --format json -o findings.json --quiet
```

### Ocenianie jakosci regul
Kazde finding otrzymuje wynik jakosci (0–100). Reguly AST score'uja najwyzej (~85), taint next (~75), regex najnizej (~50–60). Filtruj po jakosci w CI:

```bash
raven rules --score          # audytuj wszystkie reguly
raven rules validate         # waliduj skladnie + AST queries
```

### Cross-File Taint Resolver v2
Analiza taint teraz podaza za danymi miedzy plikami dla **6 jezykow**: JavaScript/TypeScript, Go, Python, Java i C#. Wykrywa gdy user input z eksportowanej funkcji plynie do dangerous sink w innym pliku.

### Circuit Breaker
Reguly produkujace >30 findings na plik lub >100 na projekt sa automatycznie obnizane lub usuwane jako prawdopodobne false-positive storm. Koniec ze spamem od zbyt szerokich regexow.

### Auto-FP Detection
Raven sledzi ile razy kazda regula jest thumiona przez `#raven-ignore`. Reguly thumione ≥3 razy triggeruja ostrzezenie po skanie sugerujace zacisniecie reguly lub obnizenie confidence.

### Fallback `regexp2`
Zlozone wzorce regex z lookahead/lookbehind (np. `(?!...)`) teraz kompiluja sie przez `regexp2` zamiast failowac. 17 zepsutych regul przeniesiono do `rules/.disabled-broken/` do recznej naprawy.

---

## Nowosci w v3.3

### 1,900+ Regul Bezpieczenstwa

| Kategoria | Regul | Jezyki | Kluczowe pokrycie |
|-----------|-------|--------|-------------------|
| **Injection** | 400+ | JS/TS, Python, Go, Java, PHP, C#, Ruby, Rust | SQLi, XSS, CMDi, NoSQLi, LDAPi, XPathi, SSTI, EL injection |
| **Kryptografia** | 120+ | Wszystkie | Slabe hashe, slaby RNG, klucze na stale, slaby TLS, JWT |
| **Sekrety** | 100+ wzorcow | Wszystkie | AWS, GitHub, Slack, Stripe, Firebase, klucze prywatne, ogolne high-entropy |
| **Autentykacja** | 150+ | Wszystkie | Brak auth, slabe sesje, niebezpieczne ciasteczka, JWT, OAuth |
| **Bezpieczenstwo API** | 80+ | JS/TS, Python, Go, Java | Rate limiting, GraphQL, mass assignment, paginacja, webhooki |
| **Mobile** | 50+ | Java/Kotlin, Swift, Dart | WebView XSS, detekcja root, clipboard, klucze na stale |
| **Infrastruktura** | 200+ | Dockerfile, Terraform, YAML, Bash | Kontenery, IaC, Kubernetes, skrypty shell |
| **Smart Contracts** | 40+ | Solidity | Reentrancy, overflow, kontrola dostepu, tx.origin |
| **Specyficzne frameworka** | 300+ | Express, Django, Flask, FastAPI, Rails, Laravel, Spring Boot, ASP.NET, Gin, React, Vue, Angular | Gleboka integracja z 80+ frameworkami |
| **Ogolne** | 400+ | Wszystkie | Path traversal, SSRF, XXE, upload plikow, open redirect, CORS, CSRF |

### Naprawy Wspierane Przez AI (10 Dostawcow)

Podlacz dowolnego dostawce LLM do automatycznej naprawy podatnosci:

| Dostawca | Status | Najlepszy dla |
|----------|--------|---------------|
| **OpenAI** (GPT-4o/o3) | Wspierany | Najlepsza ogolna jakosc |
| **Anthropic** (Claude 3.5/3.7 Sonnet) | Wspierany | Doskonale rozumienie kodu |
| **Mistral** (Codestral) | Wspierany | Szybki, zoptymalizowany pod kod |
| **DeepSeek** (V3/Coder) | Wspierany | Oplacalny |
| **Groq** (Llama/Mixtral) | Wspierany | Ultra-szybka inferencja |
| **NVIDIA** (NIM) | Wspierany | Self-hosted GPU |
| **Ollama** (Lokalny) | Wspierany | 100% offline/prywatnosc |
| **Azure OpenAI** | Wspierany | Enterprise compliance |
| **Google Gemini** | Wspierany | Kontekst multimodalny |
| **Cohere** (Command) | Wspierany | Produkcyjne wdrozenia |

25 typow promptow specyficznych dla podatnosci z **przykladami few-shot** dla 8 jezykow.

### 7-Warstwowa Redukcja False Positives

Najbardziej zaawansowany system redukcji FP w kazdym open-source SAST:

1. **Confidence Scoring** — kazdy finding oceniany 0.0-1.0 na podstawie specyficznosci wzorca, glebokosci kontekstu, czuosci sinka, bliskosci sanitizerow
2. **AI Filtr FP** — 8 heurystyk (kontekst testowy, bezpieczne nazwy zmiennych, bliskosc walidacji, typowe wzorce FP, detekcja dokumentacji, bezpieczne wartosci, sanitizer w poblizu, domyslne wartosci frameworka)
3. **Detekcja Martwego Kodu** — pomija findings w nieosiagalnych blokach kodu
4. **Swiadomosc Walidacji Inputu** — 50+ wzorcow walidacji per jezyk (joi, pydantic, Hibernate Validator, validator.js, etc.)
5. **Czulosc Sciezki** — rozumie galezie if/else gdzie jedna sciezka sanitizuje
6. **Korelacja Multi-Pattern** — zwieksza confidence gdy powiazane wzorce matchuja w poblizu
7. **Anotacje `#raven-ignore`** — adnotacje w stylu Gosec dla deweloperow z wymagana uzasadnieniem

### Brama Jakosciowa & CI/CD

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
    reason: "Pliki testowe"
  - path: "vendor/"
    rules: ["*"]
    reason: "Kod firm trzecich"
  - path: "migrations/"
    rules: ["sqli"]
    reason: "Migracje bazy danych uzywaja raw SQL z definicji"
```

### SARIF v2.1.0 + Eksport GitLab SAST

Pelna zgodnosc z SARIF 2.1.0 z taksonomia CWE, snippetami kodu i informacjami o narzedziu. Natywny eksport GitLab SAST JSON do integracji z GitLab Security Dashboard.

### Operatory w Stylu Semgrep

Wsparcie dla zaawansowanej kompozycji regul:
- `pattern-either` (logika OR)
- `pattern-not` (wykluczenie)
- `pattern-inside` / `pattern-not-inside` (ograniczenie kontekstu)
- `metavariable-regex` (walidacja grup przechwytywania)

---

## Porownanie z Konkurencja

| Funkcja | **Raven v3.3** | Semgrep CE | CodeQL | Snyk Code | Brakeman | Bearer |
|---------|---------------|------------|--------|-----------|----------|--------|
| **Reguly** | **1,911** | 2,800+ | 483 | 156 | 84 | 124 |
| **Jezyki** | **35** | 30+ | 11 | 8 | 1 (Ruby) | 2 |
| **Reguly swiadome AI** | **Tak** | Nie | Nie | Nie | Nie | Nie |
| **Auto-Fix LLM** | **10 dostawcow** | Nie | Nie (Copilot osobno) | 1 (Snyk AI) | Nie | Nie |
| **Warstwy redukcji FP** | **7** | 2-3 | 3-4 | 3-4 | 1 | 2 |
| **Predkosc skanu** | **<1s** | ~5s | ~30s | ~270s (cloud) | ~80s | ~130s |
| **AI-Generowany Filtr FP** | **Tak** | Nie | Nie | Czesciowo | Nie | Nie |
| **Detekcja Frameworkow** | **80+** | Czesciowo | Czesciowo | Czesciowo | Tylko Rails | Brak |
| **SARIF 2.1.0** | **Tak** | Tak | Tak | Tak | Tak | Tak |
| **GitLab SAST** | **Tak** | Nie | Nie | Tak | Nie | Nie |
| **Koszt** | **Darmowy** | Darmowy/$$$ | Darmowy (tylko GH) | $$$/100 skanow | Darmowy | Darmowy/$$$ |
| **Offline** | **Tak** | Tak | Tak | Nie | Tak | Tak |
| **Serwer LSP** | **Tak** | Nie | Nie | Nie | Nie | Nie |
| **Anotacje `#raven-ignore`** | **Tak** | Nie | Nie | Nie | Nie (#nosec) | Nie |
| **Bramy Jakosciowe** | **Tak** | Nie | Nie | Tak | Nie | Nie |
| **Porownanie Skanow** | **Tak** | Nie | Nie | Tak | Tak | Nie |
| **Confidence Scoring** | **Tak (0.0-1.0)** | Czesciowo | Czesciowo | Tak | High/Med/Low | Nie |
| **Walidacja Regul** | **Tak (AST + regex)** | Czesciowo | Tak | Nie | Nie | Nie |
| **Ocenianie Jakosci** | **Tak (0–100)** | Nie | Nie | Nie | Nie | Nie |
| **Taint Miedzy Plikami** | **Tak (6 jezykow)** | Nie | Czesciowo | Nie | Nie | Nie |
| **Exploitability Scorer** | **Tak (jak CVSS)** | Nie | Nie | Nie | Nie | Nie |

**Zrodla:** Blog Semgrep CE (2024), CodeQL changelog 2.23.5 (2025), Benchmark SAST Cycode (2023), Dokumentacja Snyk (2025), Dokumentacja Brakeman, Benchmark Bearer.

---

## Pokrycie CWE

Raven mapuje kazda regule do CWE. Pokrywamy **CWE Top 25 2024** w calosci:

| CWE | Nazwa | Reguly Raven | Status |
|-----|-------|-------------|--------|
| CWE-787 | Out-of-bounds Write | 15+ | Pelne |
| CWE-79 | Cross-site Scripting | 80+ | Pelne |
| CWE-89 | SQL Injection | 60+ | Pelne |
| CWE-416 | Use After Free | 10+ | Pelne |
| CWE-78 | OS Command Injection | 40+ | Pelne |
| CWE-20 | Improper Input Validation | 100+ | Pelne |
| CWE-125 | Out-of-bounds Read | 12+ | Pelne |
| CWE-22 | Path Traversal | 35+ | Pelne |
| CWE-352 | Cross-Site Request Forgery | 15+ | Pelne |
| CWE-434 | Unrestricted File Upload | 8+ | Pelne |
| CWE-862 | Missing Authorization | 12+ | Pelne |
| CWE-476 | NULL Pointer Dereference | 15+ | Pelne |
| CWE-287 | Improper Authentication | 25+ | Pelne |
| CWE-190 | Integer Overflow | 20+ | Pelne |
| CWE-77 | Command Injection | 40+ | Pelne |
| CWE-119 | Improper Restriction of Operations | 50+ | Pelne |
| CWE-798 | Hardcoded Credentials | 100+ | Pelne |
| CWE-918 | Server-Side Request Forgery | 25+ | Pelne |
| CWE-306 | Missing Authentication | 15+ | Pelne |
| CWE-362 | Race Condition | 20+ | Pelne |
| CWE-269 | Improper Privilege Management | 10+ | Pelne |
| CWE-94 | Code Injection | 45+ | Pelne |
| CWE-863 | Incorrect Authorization | 10+ | Pelne |
| CWE-276 | Incorrect Default Permissions | 8+ | Pelne |
| CWE-200 | Information Exposure | 20+ | Pelne |

---

## Wspierane Jezyki

| Jezyk | Status | Taint | AST | Regex | Reguly |
|-------|--------|-------|-----|-------|--------|
| JavaScript / TypeScript | Pelny | Tak | Tak | Tak | **200+** |
| Python | Pelny | Tak | Tak | Tak | **150+** |
| Go | Pelny | Tak | Tak | Tak | **120+** |
| Java | Pelny | Tak | Tak | Tak | **145+** |
| PHP | Pelny | Tak | Tak | Tak | **125+** |
| C / C++ | Pelny | Tak | Tak | Tak | **120+** |
| C# | Pelny | Tak | Tak | Tak | **80+** |
| Rust | Pelny | Tak | Tak | Tak | **80+** |
| Ruby | Pelny | Tak | Tak | Tak | **65+** |
| Kotlin | Pelny | Tak | Tak | Tak | **55+** |
| Swift | Pelny | Tak | Tak | Tak | **55+** |
| Dart / Flutter | Regex+Taint | Tak | Nie | Tak | **40+** |
| Elixir / Phoenix | Regex+Taint | Tak | Nie | Tak | **35+** |
| Scala / Play | Regex+Taint | Tak | Nie | Tak | **35+** |
| Lua / OpenResty | Regex+Taint | Tak | Nie | Tak | **30+** |
| Solidity | Regex+Taint | Tak | Nie | Tak | **35+** |
| Bash / Shell | Regex | Nie | Nie | Tak | **30+** |
| Dockerfile | Regex | Nie | Nie | Tak | **35+** |
| Terraform / IaC | Regex | Nie | Nie | Tak | **35+** |
| YAML / Kubernetes | Regex | Nie | Nie | Tak | **30+** |
| JSON | Regex | Nie | Nie | Tak | Tylko sekrety |
| IoT / Embedded | Regex | Nie | Nie | Tak | **45+** |

---

## Jak To Dziala

1. **Silnik regul** laduje 1,900+ regul YAML (regex + AST + taint + IaC)
2. **Skaner plikow** przechodzi przez projekt (lub tylko pliki w stagingu)
3. **Matcher regex** z cachem skompilowanych wzorcow znajduje problemy powierzchniowe
4. **Analiza AST** przez Tree-sitter rozumie strukture kodu dla glebokich wzorcow
5. **Tracker taint** podaza za danymi uzytkownika od zrodel (`req.body`) do sinkow (`db.query`) przez wywolania funkcji i pliki
6. **Swiadomosc sanitizerow** wie kiedy `DOMPurify`, `html.EscapeString`, `validator.js` czynia dane bezpiecznymi
7. **Detekcja frameworkow** auto-wykrywa 80+ frameworkow i stosuje specyficzne dla nich mapowania zrodel/sinkow
8. **Confidence scoring** przypisuje wynik 0.0-1.0 kazdemu finding na podstawie 5 czynnikow
9. **Filtr FP** stosuje 8 heurystyk do thumienia prawdopodobnych false positives
10. **Parser adnotacji** respektuje komentarze `#raven-ignore` od deweloperow
11. **Brama jakosciowa** egzekwuje progi i failuje CI jesli przekroczone
12. **Generacja napraw LLM** wysyla specyficzne dla podatnosci prompty do wybranego dostawcy AI
13. **Walidator napraw** sprawdza wygenerowane przez AI naprawy pod katem poprawnosci skladni i bezpieczenstwa
14. **Eksport** do SARIF v2.1.0, GitLab SAST JSON, HTML lub terminala

**Wszystko lokalne. Wszystko szybkie. Wszystko darmowe.**

---

## Poradnik Uzytkownika

### Czytanie Outputu

Kazde finding pokazuje:
- **Severity**: `critical` → `high` → `medium` → `low` → `info`
- **Confidence**: `high` (pewne) / `medium` (prawdopodobne) / `low` (mozliwe)
- **Quality Score**: 0–100 heurystyka (reguly AST ~85, taint ~75, regex ~50–60)
- **Lokacja**: `plik:linia:kolumna`
- **Podpowiedz naprawy**: 💡 gdy auto-fix jest dostepny

```bash
# Tylko findings z wysoka confidence
raven scan --confidence high

# Tylko critical i high severity
raven scan --min-sev high
```

### Workflow z Baseline

Sledz tylko *nowe* problemy od ostatniego skanu:

```bash
# 1. Zapisz aktualny stan jako baseline
raven scan --update-baseline

# 2. W CI, zglaszaj tylko nowe findings
raven scan --baseline .raven-baseline.json

# 3. Zaktualizuj baseline po celowych naprawach
raven scan --update-baseline
```

### Circuit Breaker

Raven automatycznie wykrywa reguly produkujace za duzo findings:
- **>30 findings/plik** → confidence obnizone do `low`
- **>100 findings/projekt** → regula calkowicie usuwana

To chroni przed false-positive storm od zbyt szerokich regexow. Zobaczysz ostrzezenie:

```
⚠️  Circuit breaker: rule gen-rp-001 produced 1881 findings — treating as potential false-positive storm
```

### Ignorowanie Findings

Uzyj komentarzy `#raven-ignore` z wymaganym uzasadnieniem:

```javascript
// #raven-ignore: To jest celowy open redirect dla OAuth callback
res.redirect(req.query.callback_url);
```

### Pisanie Wlasnych Regul

Stworz plik `.yaml` w `rules/<kategoria>/`:

```yaml
id: moj-zespol-sql-001
name: Niestandardowy wzorzec SQLi
severity: critical
category: sqli
confidence: high
cwe: "CWE-89"
languages: [javascript]
message: "Nasz wewnetrzny ORM wymaga tu raw SQL — uzyj QueryBuilder"
patterns:
  - type: regex
    pattern: "db\\.raw\\(.*\\+.*\\)"
references:
  - https://internal.docs/query-builder
```

Waliduj swoja regule:
```bash
raven rules validate
```

---

## Pokrycie OWASP Top 10 2025

| OWASP | Kategoria | Pokrycie Raven |
|-------|-----------|----------------|
| A01 | Broken Access Control | IDOR, Missing Auth, Mass Assignment, Privilege Escalation |
| A02 | Security Misconfiguration | Debug Mode, Insecure Headers, CORS Wildcard, TLS/SSL |
| A03 | Software Supply Chain | Dependency Confusion, Unpinned Versions, Typosquatting |
| A04 | Cryptographic Failures | Weak Crypto, Bad Random, Hardcoded Secrets, Weak TLS, JWT |
| A05 | Injection | SQLi, XSS, CMDi, NoSQLi, LDAPi, XPathi, SSTI, Header Injection |
| A06 | Insecure Design | File Upload, Open Redirect, SSRF, XXE, Race Conditions |
| A07 | Authentication Failures | JWT, Session Fixation, Insecure Cookies, Password Hashing, OAuth |
| A08 | Integrity Failures | Deserialization, XXE, Insecure Dependencies |
| A09 | Logging Failures | Log Injection, Sensitive Data in Logs, Console Secrets |
| A10 | Exception Handling | Information Leakage, Stack Traces, Debug Info in Production |

---

## Architektura

```
 Reguly (1,900+ YAML)          Silnik
 +------------------+        +---------------------+
 | Regex Rules      |------->| Confidence Scorer   |
 | AST Rules        |------->| FP Filter (7 warstw)|
 | Taint Rules      |------->| Dead Code Detector  |
 | IaC Rules        |------->| Parser Adnotacji    |
 | Secret Patterns  |------->| Brama Jakosciowa    |
 +------------------+        +----------+----------+
                                        |
             Tree-sitter AST            v
 +------------------+        +---------------------+
 | Parsers Jezykow  |------->| Taint Tracker       |
 | (Go, JS, Python  |        | (Intra + Cross-file)|
 |  Java, etc.)     |        | Detektor Frameworkow|
 +------------------+        +----------+----------+
                                        |
                                        v
                              +---------------------+
                              | LLM Fix Generation  |
                              | (10 dostawcow,      |
                              |  25 typow podatnosci)|
                              +----------+----------+
                                         |
                                         v
                              +---------------------+
                              | SARIF 2.1.0         |
                              | GitLab SAST         |
                              | Raport HTML         |
                              +---------------------+
```

---

## Konfiguracja

Stworz `.raven.yaml` w katalogu glownym projektu:

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

- [x] Rozszerzenie VS Code (z diagnostyka, komendami, paskiem statusu)
- [x] Wsparcie Zed / Vim / Neovim (konfiguracja LSP + skroty klawiszowe)
- [x] Naprawy inline w IDE (CodeActions przez LSP — żarówka "Fix with Raven")
- [x] Serwer LSP (diagnostyka, hover, code actions, execute command)
- [x] GitHub Action (integracja CI/CD)
- [x] Serwer MCP dla agentow AI (Model Context Protocol)
- [x] Skaner MCP prompt injection
- [x] Raportowanie HTML & SARIF v2.1.0
- [x] Eksport GitLab SAST
- [x] Brama jakosciowa z `.raven-policy.yaml`
- [x] Porownanie skanow (`--baseline`, `--save-baseline`)
- [x] Adnotacje #raven-ignore
- [x] Generacja napraw przez AI (10 dostawcow LLM)
- [x] Ocenianie exploitability (jak CVSS)
- [x] Konfiguracja LSP dla Emacs (editor/emacs/raven.el)
- [x] Integracja JetBrains (LSP4IJ + external annotator, editor/jetbrains/README.md)
- [x] Hook pre-commit (hooks/pre-commit + .pre-commit-hooks.yaml)
- [x] Obraz Docker (Dockerfile)
- [x] Formula Homebrew (homebrew/raven.rb)

---

## Wklad W Projekt

Raven jest open source. Wklad mile widziany!

```bash
git clone https://github.com/raven-security/raven.git
cd raven
go test ./...
```

### Dodawanie Reguly

Reguly to pliki YAML w `rules/<kategoria>/`:

```yaml
id: moja-regula-001
name: Opisowa Nazwa Reguly
severity: high
category: sqli
confidence: high
cwe: "CWE-89"
languages: [javascript]
message: "Uzyj zapytan parametryzowanych zamiast konkatenacji stringow"
patterns:
  - type: regex
    pattern: "query\\s*\\+\\s*"
    where:
      - not-constant: true
      - not-sanitized: ["DOMPurify.sanitize", "validator.escape"]
references:
  - https://cwe.mitre.org/data/definitions/89.html
  - https://owasp.org/www-community/attacks/SQL_Injection.html
```

---

## Licencja

MIT (c) Raven Security

---

> *"Najlepsze narzedzie bezpieczenstwa to to, ktorego faktycznie uzywasz."*
