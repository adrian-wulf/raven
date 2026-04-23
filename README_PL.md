# 🐦‍⬛ Raven

> **Skaner bezpieczeństwa dla vibe coderów.**
>
> Złap błędy bezpieczeństwa, które AI wpisuje w Twój kod, zanim je wyślesz.

[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Problem

Napisałeś aplikację z pomocą Cursor/Claude/Copilot. Działa. Wysyłasz ją na produkcję.

**Ale Twój asystent AI właśnie napisał:**
- SQL injection poprzez konkatenację stringów
- XSS przez `innerHTML`
- Zakodowane na stałe klucze API
- `eval()` z danymi użytkownika
- Command injection przez `exec()`

**Ty tego nie zauważyłeś. Atakujący tak.**

---

## Co robi Raven

Raven skanuje Twój kod w poszukiwaniu **dokładnie tych błędów, które popełniają LLMy** i mówi Ci, jak je naprawić.

```bash
$ raven scan

🐦‍⬛ Raven Security Scan
  42 plików przeskanowanych w 23ms

Podsumowanie:
  krytyczne: 2
  wysokie: 3
  średnie: 1

 KRYTYCZNE  SQL Injection przez konkatenację stringów
  src/api.js:12:18
  Potencjalne SQL injection: dane użytkownika są konkatenowane do zapytania SQL.
  Użyj zapytań parametryzowanych.
       const query = "SELECT * FROM users WHERE id = " + req.query.id;
  💡 Dostępna naprawa: raven fix

 WYSOKIE  Zakodowany na stałe klucz API lub sekret
  src/config.js:5:7
  Wykryto zakodowany sekret. Przenieś to do zmiennych środowiskowych.
     const API_KEY = "sk-live-abc123...";
```

---

## Instalacja

```bash
# macOS / Linux
brew install raven-security/tap/raven

# Lub przez Go
go install github.com/raven-security/raven/cmd/raven@latest

# Lub pobierz binarkę z wydań
curl -sSL https://get.raven.sh | bash
```

---

## Szybki start

```bash
# Przeskanuj swój projekt
cd moj-projekt
raven scan

# Skanuj tylko pliki w stagingu (natychmiastowy pre-commit)
raven scan --staged

# Obserwuj zmiany podczas developmentu
raven watch

# Auto-napraw problemy (domyślnie dry-run)
raven fix
raven fix --apply

# Zobacz wszystkie reguły
raven rules
raven rules validate          # Waliduj własne pliki reguł

# Tryb CI (zwraca exit 1 przy wykryciu, wyjście SARIF)
raven ci --format sarif --output report.sarif

# Skanowanie bazowe / różnicowe (zglasza TYLKO NOWE problemy)
raven scan --baseline .raven-baseline.json
raven scan --update-baseline  # Zapisz obecne wyniki jako bazowe

# Głębokie skanowanie sekretów
raven scan --secrets

# Wymuś politykę bezpieczeństwa
raven scan --policy .raven-policy.yaml

# Generuj raport HTML
raven scan --format html -o report.html

# Naucz się o podatności
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

Wyniki pojawią się w **Security → Code scanning alerts**.

### Rozszerzenie VS Code / Cursor

Zainstaluj z VS Code Marketplace (wkrótce) lub zbuduj ze źródeł:

```bash
cd editor/vscode
npm install
npm run compile
```

Następnie naciśnij F5 w VS Code, aby uruchomić rozszerzenie. Zobaczysz:
- 🛡️ Ikona na pasku statusu pokazująca status bezpieczeństwa
- 🔴 Czerwone podkreślenia pod podatnym kodem
- 💡 Akcje kodu "Napraw z Raven"
- 📋 Paletę poleceń: `Raven: Scan Workspace`

### Naprawy wspierane przez AI

Niech AI naprawi podatności za Ciebie:

```bash
# Ustaw swój klucz API (OpenRouter zalecany - dostępny darmowy tier)
export OPENROUTER_API_KEY=your-key

# AI-napraw wszystkie problemy interaktywnie
raven fix-ai

# Podgląd bez zastosowania
raven fix-ai --dry-run
```

### Hook pre-commit

Blokuj commity z problemami bezpieczeństwa:

```bash
raven install-hook        # Instaluj
raven install-hook --uninstall  # Usuń
```

---

## Funkcje

### 🎯 Detekcja świadoma AI
Reguły zaprojektowane dla **typowych błędów LLM**:
- SQL injection (konkatenacja stringów, template literals, `.format()`)
- XSS (`innerHTML`, `dangerouslySetInnerHTML`, template injection)
- Zakodowane na stałe sekrety (klucze API, tokeny, hasła)
- Command injection (`exec`, `spawn` z shell)
- Path traversal (niezabezpieczone ścieżki plików)
- Code injection (`eval`, `new Function`)
- SSRF (Server-Side Request Forgery)
- NoSQL Injection
- Prototype Pollution
- Insecure Deserialization
- ReDoS (Regular Expression Denial of Service)
- Weak Cryptography (MD5, SHA1, DES)
- Insecure Cookies (brak HttpOnly/Secure/SameSite)
- Missing CSRF Protection
- Open Redirect
- File Upload bez walidacji
- Mass Assignment
- Log Injection
- LDAP Injection
- XPath Injection
- XXE (XML External Entity)
- Insecure TLS/SSL

### 🔬 Zaawansowana analiza
- **Skanowanie oparte na AST** przez Tree-sitter (nie tylko regex)
- **Analiza taint** — śledzi dane użytkownika od źródła do sinku
- **Taint międzyproceduralny** — podąża za danymi przez wywołania funkcji
- **Analiza międzyplikowa** — śledzi importy/eksporty między modułami
- **Świadomy sanitizerów** — wie, kiedy `DOMPurify`, `html.EscapeString`, itp. czynią dane bezpiecznymi

### 🔧 Auto-naprawa
Raven sugeruje i stosuje naprawy tam, gdzie to możliwe:
```bash
raven fix --apply
```

### ⚡ Skanowanie plików w stagingu
Skanuj tylko pliki w git stagingu w milisekundach:
```bash
raven scan --staged
```

### 👁️ Tryb obserwacji
Łap problemy w trakcie pisania:
```bash
raven watch
```

### 🚀 Gotowy do CI/CD
GitHub Actions, GitLab CI, itp.:
```bash
raven ci --format sarif --output report.sarif
```

### 📊 Raporty HTML
Interaktywny dashboard z filtrowaniem:
```bash
raven scan --format html -o report.html
```

### 🛡️ Silnik polityk
Wymuszaj progi bezpieczeństwa w CI:
```yaml
# .raven-policy.yaml
max_findings:
  critical: 0
  high: 0
fail_on_new: true
```

### 📈 Przyrostowe cacheowanie
Pomijaj niezmienione pliki przy kolejnych skanach (~40-60% przyspieszenia):
```bash
raven scan              # Ciepły cache — ultra szybki
raven scan --no-cache   # Wymuś pełne ponowne skanowanie
```

### 🎨 Piękne wyjście
Kolorowe, czytelne wyjście terminala ze snippetami kodu.

### 📋 Tryb podsumowania
Kompaktowe wyjście dla CI (tylko liczby według krytyczności):
```bash
raven scan --format summary
```

### 🔇 Tryb cichy
Wycisz nieistotne komunikaty w CI:
```bash
raven scan --quiet
```

---

## Wspierane języki

| Język | Status | Taint | AST | Reguły |
|-------|--------|-------|-----|--------|
| JavaScript / TypeScript | ✅ Pełny | ✅ | ✅ | 60+ |
| Python | ✅ Pełny | ✅ | ✅ | 50+ |
| Go | ✅ Pełny | ✅ | ✅ | 40+ |
| PHP | ✅ Pełny | ✅ | ✅ | 40+ |
| Java | ✅ Pełny | ✅ | ✅ | 40+ |
| Kotlin | ✅ Pełny | ✅ | ✅ | 25+ |
| C# | ✅ Pełny | ✅ | ✅ | 30+ |
| Rust | ✅ Pełny | ✅ | ✅ | 30+ |
| Ruby | ✅ Pełny | ✅ | ✅ | 25+ |
| Swift | ✅ Pełny | ✅ | ✅ | 20+ |

---

## Jak to działa

Raven używa **lokalnej analizy opartej na regułach** — żadnych wywołań API, żadne dane nie opuszczają Twojego komputera:

1. **Parsuje reguły** z plików YAML (wbudowane + własne)
2. **Przegląda pliki** w projekcie (lub tylko pliki w stagingu)
3. **Dopasowuje wzorce** używając regex z cachem skompilowanych wzorców
4. **Analizuje AST** przez Tree-sitter dla głębokiego zrozumienia struktury
5. **Śledzi taint** podążając za danymi użytkownika od źródeł (req.body) do sinków (db.query)
6. **Rozwiązuje międzyplikowo** śledząc taint przez importy/eksporty
7. **Cache'uje niezmienione pliki** po hashu SHA256 dla szybkości ciepłych uruchomień
8. **Wypisuje wyniki** z krytycznością, lokalizacją, sugestiami napraw i raportami HTML

Wszystko za darmo. Wszystko lokalnie. Wszystko szybko.

---

## Konfiguracja

Stwórz `.raven.yaml` w katalogu głównym projektu:

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

severity:
  min: low
```

---

## Reguły

Raven dostarcza **500+ reguł bezpieczeństwa** pokrywających OWASP Top 10, typowe błędy LLM, analizę opartą na AST, śledzenie taint i skanowanie IaC.

```bash
# Wylistuj wszystkie reguły
raven rules

# Wylistuj tylko reguły JavaScript
raven rules --lang javascript

# Wylistuj z pełnymi szczegółami
raven rules --detail

# Wyszukaj reguły po słowie kluczowym
raven rules search sql
```

---

## Dlaczego Raven vs inne?

| | Raven | Semgrep | Snyk | CodeQL |
|---|-------|---------|------|--------|
| **Koszt** | Darmowy | Darmowy/Płatny | $$$ | Darmowy (tylko GitHub) |
| **Konfiguracja** | Zero konfiguracji | Wymaga konfiguracji | Wymaga konta | Złożony |
| **Szybkość** | < 1s | ~5s | Cloud | ~30s |
| **Skupiony na AI** | ✅ Tak | ❌ Nie | ❌ Nie | ❌ Nie |
| **Auto-naprawa** | ✅ Tak | ⚠️ Częściowa | ❌ Nie | ❌ Nie |
| **Offline** | ✅ Tak | ✅ Tak | ❌ Nie | ✅ Tak |
| **IDE** | CLI + LSP | Rozszerzenia | Rozszerzenia | Tylko GitHub |
| **LSP Server** | ✅ Tak | ❌ Nie | ❌ Nie | ❌ Nie |

---

## Mapowanie OWASP Top 10 2025

Raven pokrywa wszystkie kategorie OWASP Top 10 2025:

| OWASP | Kategoria | Reguły Raven |
|-------|-----------|-------------|
| A01 | Broken Access Control | Missing Auth, Mass Assignment, Default Creds |
| A02 | Security Misconfiguration | Debug Mode, Insecure Headers, CORS Wildcard |
| A03 | Software Supply Chain | Dependency Scanner (OSV), `--deps` flag |
| A04 | Cryptographic Failures | Weak Crypto, Hardcoded Secrets, Weak Random |
| A05 | Injection | SQLi, XSS, Command Injection, NoSQLi, LDAPi, XPathi, SSTI |
| A06 | Insecure Design | File Upload, Open Redirect, SSRF |
| A07 | Authentication Failures | JWT Secret, Default Creds, Insecure Cookies |
| A08 | Integrity Failures | Unsafe Deserialization, XXE |
| A09 | Logging Failures | Console Secrets, Log Injection |
| A10 | Exception Handling | Prototype Pollution, Unsafe Eval |

---

## Wsparcie językowe IDE

### Autouzupełnianie powłoki

```bash
# Bash
raven completion bash > /etc/bash_completion.d/raven

# Zsh
raven completion zsh > "${fpath[1]}/_raven"

# Fish
raven completion fish > ~/.config/fish/completions/raven.fish

# PowerShell
raven completion powershell | Out-String | Invoke-Expression
```

---

## Roadmap

- [x] Silnik reguł
- [x] 500+ reguł bezpieczeństwa (regex + AST + taint + IaC)
- [x] Auto-naprawa
- [x] Tryb obserwacji
- [x] Tryb CI + SARIF
- [x] Rozszerzenie VS Code / Cursor (oparte na LSP)
- [x] Naprawy wspierane przez AI (OpenRouter/DeepSeek)
- [x] Hook pre-commit
- [x] GitHub Action
- [x] Analiza oparta na AST (Tree-sitter)
- [x] Reguły świadome frameworków
- [x] Skanowanie łańcucha dostaw (OSV)
- [x] Skanowanie bazowe / różnicowe
- [x] Przyrostowe cacheowanie (oparte na SHA256)
- [x] Śledzenie taint międzyplikowego
- [x] Analiza taint międzyproceduralna
- [x] Rule DSL v2 (where clauses, metavariables)
- [x] Raporty HTML z interaktywnym filtrowaniem
- [x] Silnik polityk (.raven-policy.yaml)
- [x] Świadome sanitizerów śledzenie taint
- [x] Skanowanie plików w stagingu (--staged)
- [x] Wsparcie Java / Kotlin / C#
- [x] CHANGELOG
- [x] Wyszukiwanie reguł
- [x] Tryb cichy (--quiet)
- [x] Tryb podsumowania (--format summary)
- [x] Autouzupełnianie powłoki
- [ ] Wsparcie Zed / Vim
- [ ] Naprawy inline w IDE

---

## Wkład

Raven jest open source. Wkład jest mile widziany!

```bash
git clone https://github.com/raven-security/raven.git
cd raven
go test ./...
```

### Dodawanie reguły

Reguły to pliki YAML w `rules/<język>/`:

```yaml
id: moja-regula-001
name: Opisowa nazwa
severity: high
category: xss
confidence: high
languages: [javascript]
message: Co powinien wiedzieć deweloper
patterns:
  - type: regex
    pattern: "niebezpieczny\.wzorce"
references:
  - https://owasp.org/...
```

---

## Licencja

MIT © Raven Security

---

> *"Najlepsze narzędzie bezpieczeństwa to to, którego faktycznie używasz."*
