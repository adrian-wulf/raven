# Contributing to Raven

Thanks for your interest in Raven! 🐦‍⬛

## Getting Started

```bash
git clone https://github.com/adrian-wulf/raven.git
cd raven
go mod tidy
go build ./cmd/raven
```

## Adding a Rule

Rules are YAML files in `rules/<language>/`. Here's a template:

```yaml
id: raven-js-my-rule-001
name: Descriptive Rule Name
description: |
  What this rule detects and why it's dangerous.
severity: high
category: xss
confidence: high
languages: [javascript, typescript]
message: |
  What the developer should know and how to fix it.
patterns:
  - type: regex
    pattern: "dangerous\\.pattern"
references:
  - https://owasp.org/...
```

## Testing Rules

Test your rule on real code before submitting:

```bash
# Add your rule to rules/javascript/
# Test it
./raven scan ./test-project
```

## Code Style

- Go: `gofmt`, `go vet`
- Rules: clear descriptions, actionable messages

## Pull Request Process

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit with clear messages
4. Push and open a PR
5. Ensure CI passes

## Questions?

Open an issue or discussion on GitHub.
