# Raven GitHub Action

Scan your code for AI-generated security vulnerabilities on every push and PR.

## Quick Start

Add this to `.github/workflows/security.yml`:

```yaml
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

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `fail-on` | Minimum severity to fail on | `high` |
| `format` | Output format (`sarif`, `json`, `pretty`) | `sarif` |
| `output` | Output file path | `raven-results.sarif` |
| `min-confidence` | Minimum rule confidence | `medium` |

## Examples

### Fail on critical only
```yaml
- uses: raven-security/raven/.github/actions/raven@main
  with:
    fail-on: critical
```

### Scan specific directory
```yaml
- uses: raven-security/raven/.github/actions/raven@main
  with:
    path: ./src
    fail-on: medium
```

### JSON output instead of SARIF
```yaml
- uses: raven-security/raven/.github/actions/raven@main
  with:
    format: json
    output: results.json
```

## SARIF Integration

When `format: sarif`, results are automatically uploaded to GitHub Security tab.
Navigate to **Security → Code scanning alerts** to view findings.
