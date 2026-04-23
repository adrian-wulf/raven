# 🐦‍⬛ Raven Security Scanner for VS Code

> Catch security bugs before you ship. Real-time SAST for vibe coders.

## Features

- **🔴 Real-time scanning** — diagnostics update as you type (files < 1000 lines)
- **📊 Findings panel** — tree view grouped by severity with one-click navigation
- **🔧 Auto-fixes** — quick-fix code actions for supported vulnerabilities
- **🎯 500+ rules** — SQL injection, XSS, hardcoded secrets, insecure configs, and more
- **🌍 10 languages** — JavaScript, TypeScript, Python, Go, Java, PHP, Rust, Ruby, Kotlin, Swift
- **📈 Status bar** — live count of critical/high/medium findings
- **🔍 Hover info** — detailed vulnerability info on mouse hover
- **📋 CodeLens** — findings count displayed at the top of each file

## Requirements

- [Raven](https://github.com/adrian-wulf/raven) must be installed and available in your `PATH`
- VS Code 1.85.0 or newer

## Installation

### From VS Code Marketplace (soon)

Search for "Raven Security Scanner" in the Extensions panel.

### From Source

```bash
cd vscode-raven
npm install
npm run compile
# Press F5 to launch Extension Development Host
```

To package as `.vsix`:

```bash
npm run package
# Install in VS Code: Cmd+Shift+P → "Install from VSIX"
```

## Configuration

Open VS Code settings (`Cmd/Ctrl + ,`) and search for "Raven".

| Setting | Default | Description |
|---------|---------|-------------|
| `raven.enabled` | `true` | Enable/disable scanning |
| `raven.executablePath` | `raven` | Path to raven binary |
| `raven.minSeverity` | `low` | Minimum severity to report |
| `raven.languages` | `[]` | Limit to specific languages |
| `raven.scanOnSave` | `true` | Scan on file save |
| `raven.scanOnType` | `true` | Scan while typing |
| `raven.showCodeLens` | `true` | Show findings count in CodeLens |

## Commands

| Command | Keybinding | Description |
|---------|-----------|-------------|
| `Raven: Scan Workspace` | `Cmd/Ctrl+Shift+R` | Full workspace scan |
| `Raven: Scan Current File` | — | Scan active file |
| `Raven: Show Findings` | — | Open findings panel |
| `Raven: Clear All Findings` | — | Clear all results |

## Integration with AI Assistants

Raven works great alongside AI coding assistants:

- **GitHub Copilot** — Raven catches security issues in AI-generated code
- **Cursor** — use Raven MCP server for AI-driven security reviews
- **Claude Code** — connect via `raven mcp` for tool-based scanning
- **Kimi Code** — LSP integration provides real-time feedback

## MCP Server

To use Raven with Claude Desktop or other MCP clients:

```json
{
  "mcpServers": {
    "raven": {
      "command": "raven",
      "args": ["mcp"]
    }
  }
}
```

Available tools:
- `raven_scan_workspace` — scan entire project
- `raven_scan_file` — scan specific file
- `raven_scan_snippet` — scan code snippet (great for AI-generated code!)
- `raven_list_rules` — list all 500+ rules
- `raven_get_rule` — get rule details
- `raven_explain_finding` — detailed security explanation

## License

MIT — see [LICENSE](https://github.com/adrian-wulf/raven/blob/main/LICENSE)
