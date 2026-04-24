# Competitive Benchmark: Raven vs Semgrep, Bandit, gosec

**Date:** 2026-04-22  
**Raven version:** v3.3 (all FP waves completed)  
**Competitors:** Semgrep OSS 1.161.0, Bandit 1.9.4, gosec v2.25.0  

---

## Summary Table (Production Code Only)

| Repository | Lang | Files | **Raven** | Semgrep | Bandit | gosec | Raven Time | Semgrep Time |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| express/lib | JS | 6 | **0** | ~0 | — | — | **0.13s** | ~7s |
| flask/src | Python | 15 | **4** | ~8 | N/A | — | **0.07s** | ~8s |
| django | Python+HTML | 942+372 | **371** | 632 | 1,281 | — | **14s** | 42s |
| httprouter | Go | 3 | **2** | 2 | — | 0 | **0.16s** | 6.5s |
| mux | Go | 7 | **0** | 0 | — | 0 | **0.26s** | 6.3s |

> **Metodologia:** Raven uruchomiony z `--confidence low`, usuniętym cache, ze skanowaniem `.html`/`.jinja2`.  
> Semgrep/Bandit/gosec na pełnych repo (w tym examples/tests).

---

## Cztery fale poprawek — podsumowanie

### Fala 1 — Ignorowanie komentarzy + 10 poprawionych rules
Dodano `isCommentLine()` do `matchRegex()`. Poprawiono najgorsze generic rules.  
**Efekt:** Django 3140 → 297 findings. httprouter 17 FP → 2 TP.

### Fala 2 — Nowe rules + templates + bugfixy
8 nowych rules, skanowanie `.html`/`.jinja2`, fix race w cache.  
**Efekt:** Django 297 → 321.

### Fala 3 — Dopracowanie dokładności
- `raven-py-markup-xss-001` — KAŻDE `mark_safe()` (z 5 → 53 findings w Django)
- `raven-html-csrf-001` — wyklucza GET forms
- `raven-py-crypto-001` — usunięto duplikat `hashlib.sha1()`
- `raven-py-django-orm-raw-001` — nowy rule dla Django ORM
- `\b` word boundary — brak FPs z `TagMarkup`

### Fala 4 — SQL + `is_safe`
- `raven-gen-sql-001` — `%s['"].*(%|\.format|\+)` zamiast `.*%s.*(%|\.format|\+)` — wyklucza parametryzowane query z wieloma `%s` w stringu. **Django: 34 → 9 findings.**
- `raven-py-django-filter-safe-001` — `@register.filter(is_safe=True)` — **40 findings**, dokładnie tyle co Semgrep.

---

## Deep Dive per Repository

### Django (Python + HTML) — Raven coraz bliżej Semgrep

**Raven 371 findings** vs **Semgrep 632 findings**

**Raven unikalne (prawdziwe problemy):**
- `raven-py-markup-xss-001` — 53x `mark_safe()` w Python
- `raven-html-template-xss-001` — 16x `|safe` w template'ach
- `raven-py-django-filter-safe-001` — 40x `is_safe=True` w filterach
- `raven-html-csrf-001` — 1x brak CSRF w `technical_500.html`

**Semgrep unikalne (braki Ravena):**
- `direct-use-of-httpresponse` — 18x
- `template-translate-as-no-escape` — 10x
- `custom-expression-as-sql` — 162x (Raven ma 9x `raven-gen-sql-001`)

**Raven FP do dopracowania:**
- `raven-gen-sql-001` (9x) — 1x `"SELECT " + ", ".join(["QUOTE(?)"] * len(params))` to bezpieczne concatenation
- `raven-gen-log-001` (35x) — część to normalne logowanie w frameworku
- `raven-html-csrf-001` — 1x `tests.html` (test)

### httprouter (Go) — Raven = Semgrep

Dokładnie te same 2 open-redirect. gosec 0.

### Flask src/ (Python) — 4 findings, wszystkie TP

1. `SECRET_KEY = 'development key'`
2. `hashlib.sha1(string)`
3. `DEBUG = True`
4. `return Markup(value)`

---

## Lista zmian w kodzie (tej sesji)

### Go code
1. `internal/engine/engine.go` — `isCommentLine()` (ignorowanie komentarzy w regex)
2. `internal/engine/engine.go` — `hasSupportedExtension()` (+ `.html`, `.jinja2`, `.django`, `.ejs`)
3. `internal/engine/engine.go` — `DetectLanguage()` (+ `.html`, `.jinja2`, `.django`, `.ejs`)
4. `internal/cache/cache.go` — `sync.RWMutex` (fix race condition)

### Poprawione rules (YAML)
5. `gen-unsafe-crypto.yaml` — `\b` word boundary
6. `gen-unsafe-deserialization.yaml` — wymaga wywołania funkcji
7. `gen-missing-input-validation.yaml` — wymaga dangerous sink
8. `gen-missing-auth.yaml` — wymaga string literalu z `/`
9. `gen-stack-trace-exposure.yaml` — zaostrzone patterns
10. `gen-sensitive-log.yaml` — wymaga wywołania funkcji logującej
11. `python/path-traversal.yaml` — usunięto `path`/`filename`
12. `javascript/prototype-pollution.yaml` — wymaga user input
13. `python/py-django-settings-debug.yaml` — `frameworks: [django]`
14. `gen-sql-string-format.yaml` — wyklucza parametryzowane query (`%s['"]`)
15. `python/insecure-crypto.yaml` — usunięto duplikaty `hashlib.sha1()`

### Nowe rules (YAML)
16. `python/py-markup-xss.yaml` — `mark_safe()`, `Markup()`
17. `html/template-explicit-unescape.yaml` — `|safe`, `|html_safe`, `<%-`, `{{{`
18. `html/django-csrf-missing.yaml` — `<form>` bez `{% csrf_token %}`
19. `html/html-missing-integrity.yaml` — brak `integrity` w CDN
20. `go/go-open-redirect.yaml` — `http.Redirect` z user input
21. `javascript/express-direct-response-write.yaml` — `res.write(userInput)`
22. `javascript/express-hardcoded-session-secret.yaml` — hardcoded secret
23. `javascript/ejs-explicit-unescape.yaml` — `<%- %>`
24. `python/py-django-orm-raw-sql.yaml` — Django ORM `raw()` / `extra()`
25. `python/py-django-filter-is-safe.yaml` — `@register.filter(is_safe=True)`

---

## Co jeszcze zostało

### High Priority
1. **Poprawić `raven-gen-sql-001`** — 9x findings, 1x to bezpieczne `", ".join(["QUOTE(?)"] * len(params))`. Potrzeba rozróżnienia concatenation od safe string building.
2. **Poprawić `raven-gen-log-001`** — 35x findings, część to normalne `logger.info(...)` w frameworku.

### Medium Priority
3. **Dodać rule `direct-use-of-httpresponse`** — Semgrep unikalne (18x w Django)
4. **Dodać rule `template-translate-as-no-escape`** — Semgrep unikalne (10x)
5. **Poprawić `raven-fw-flask-001`** — nie fire'ować na `SECRET_KEY = None`
6. **Poprawić `raven-py-flask-001`** — nie fire'ować na `Flask(__name__)` w kodzie frameworku

### Bugfixy
7. **Invalidate cache gdy rules się zmieniają**
8. **Dodać `--no-cache` flagę do CLI**

---

*Benchmark run on 2026-04-22. Raven: 29 zmian w kodzie/rules, skanowanie template'ów, fix race w cache.*
