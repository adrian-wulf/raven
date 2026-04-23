# 🔌 Raven Integrations Guide

> How to use Raven with every popular vibe coding tool

**TL;DR:** Raven integrates via **three mechanisms:**
- **MCP** (Model Context Protocol) — AI tools can *call* Raven as a tool
- **LSP** (Language Server Protocol) — real-time diagnostics in your editor
- **VS Code Extension** — full GUI integration with panel, status bar, commands

**No hosting required.** Everything runs locally on the user's machine.

---

## 📋 Quick Comparison

| Tool | Best Integration | Setup Time | Experience |
|------|-----------------|------------|------------|
| **Claude Desktop** | MCP | 2 min | ⭐⭐⭐ AI asks Raven to scan your code |
| **Claude Code** | MCP | 2 min | ⭐⭐⭐ Same as Desktop, in terminal |
| **VS Code + Copilot** | VS Code Extension + LSP | 3 min | ⭐⭐⭐ Real-time squiggles + panel |
| **Cursor** | VS Code Extension + MCP | 3 min | ⭐⭐⭐ Best of both worlds |
| **Kimi Code** | LSP | 2 min | ⭐⭐⭐ Native LSP diagnostics |
| **GitHub Copilot Chat** | MCP (via VS Code) | 3 min | ⭐⭐ Ask Copilot to run Raven |
| **Codex CLI** | MCP | 2 min | ⭐⭐⭐ Codex uses Raven automatically |
| **Aider** | MCP or LSP | 2 min | ⭐⭐⭐ Aider can invoke Raven per change |
| **Continue.dev** | MCP or LSP | 2 min | ⭐⭐⭐ Works with both modes |
| **Zed** | LSP | 2 min | ⭐⭐ Native diagnostics |
| **Neovim** | LSP | 5 min | ⭐⭐⭐ Full control via lua config |
| **Emacs** | LSP (eglot/lsp-mode) | 5 min | ⭐⭐ Classic LSP integration |
| **Helix** | LSP | 2 min | ⭐⭐ Built-in LSP support |
| **Sublime Text** | LSP package | 3 min | ⭐⭐ Via LSP package |
| **JetBrains IDEs** | CLI + file watcher | 5 min | ⭐ No native LSP yet |

---

## 🦋 Claude Desktop (Anthropic)

**Integration:** MCP Server

### Setup

1. Install Raven (make sure `raven` is in your PATH):
   ```bash
   go install github.com/raven-security/raven/cmd/raven@latest
   # or download from GitHub releases
   ```

2. Open Claude Desktop → Settings → Developer → Edit Config

3. Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
   or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
   or `~/.config/Claude/claude_desktop_config.json` (Linux)

4. Add Raven MCP:
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

5. Restart Claude Desktop. You should see a 🔨 hammer icon with Raven tools.

### How to Use

Just ask Claude naturally:

- *"Scan this project for security issues"* → Claude calls `raven_scan_workspace`
- *"Is this code safe?"* (paste code) → Claude calls `raven_scan_snippet`
- *"What security rules do you know?"* → Claude calls `raven_list_rules`
- *"Explain why this SQL query is dangerous"* → Claude calls `raven_explain_finding`

### What Claude Sees

Claude gets 6 tools:
- `raven_scan_workspace` — full project scan
- `raven_scan_file` — single file scan
- `raven_scan_snippet` — scan any code block
- `raven_list_rules` — browse all 503 rules
- `raven_get_rule` — deep dive into a rule
- `raven_explain_finding` — educational explanations

---

## 💻 Claude Code (CLI)

**Integration:** MCP Server

### Setup

Claude Code supports MCP servers natively since v0.2.

```bash
# In your project directory
claude config set mcpServers.raven '{"command": "raven", "args": ["mcp"]}'

# Or edit ~/.claude/config.json manually:
{
  "mcpServers": {
    "raven": {
      "command": "raven",
      "args": ["mcp"]
    }
  }
}
```

### How to Use

```
User: check if my auth code has vulnerabilities
Claude: I'll scan your project with Raven...
       [calls raven_scan_workspace]
       Found 3 issues: 1 high (SQL injection in auth/login.go), 2 medium...
```

You can also run Raven directly in Claude Code's terminal:
```bash
raven scan --min-sev medium
```

---

## 🎯 VS Code + GitHub Copilot

**Integration:** VS Code Extension + LSP (best combo)

### Setup

**Option A: Install from marketplace** (when published)
1. Open Extensions panel
2. Search "Raven Security Scanner"
3. Install

**Option B: From source**
```bash
cd /path/to/raven/vscode-raven
npm install
npm run compile
# Press F5 to test, or:
# Cmd+Shift+P → "Install from VSIX" after `npm run package`
```

**Option C: LSP only** (no extension needed)
Install [LSP client extension](https://marketplace.visualstudio.com/items?itemName=prabirshrestha.vscode-lsp) and configure:
```json
{
  "lsp_configs": {
    "raven": {
      "command": ["raven", "lsp"],
      "filetypes": ["javascript", "typescript", "python", "go", "java", "php", "rust", "ruby", "kotlin", "swift", "csharp"]
    }
  }
}
```

### How to Use

With the extension you get:
- 🔴 **Real-time squiggles** under vulnerable code
- 📊 **Findings panel** in the sidebar (grouped by severity)
- 🔧 **Quick fixes** (Ctrl+. on a finding)
- 📈 **Status bar** showing vulnerability count
- ⌨️ **Ctrl/Cmd+Shift+R** — scan entire workspace

With Copilot + Raven together:
- Copilot generates code → Raven immediately flags issues
- Hover over squiggle → see why it's dangerous + how to fix

---

## ⚡ Cursor

**Integration:** VS Code Extension + MCP (both!)

### Setup

**VS Code Extension:** Same as VS Code above. Cursor is VS Code-based so the extension works out of the box.

**MCP for Cursor Chat:**
1. Open Cursor Settings → Features → MCP Servers
2. Add new server:
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
3. Restart Cursor

### How to Use

- **While coding:** Raven LSP shows real-time diagnostics
- **In Cursor Chat:** Ask "scan this file for security issues" → Cursor invokes Raven MCP
- **Tab completion:** Cursor generates code → Raven checks it instantly

---

## 🤖 Kimi Code

**Integration:** LSP Server

### Setup

Kimi Code (Kimi-CLI) uses LSP for code intelligence. Configure it to use Raven:

```bash
# In your project
kimi lsp register raven --command "raven lsp" --languages "javascript,typescript,python,go,java,php,rust,ruby,kotlin,swift,csharp"
```

Or in `.kimi/config.toml`:
```toml
[lsp.raven]
command = "raven"
args = ["lsp"]
filetypes = ["js", "ts", "py", "go", "java", "php", "rs", "rb", "kt", "swift", "cs"]
```

### How to Use

- Raven diagnostics appear inline as you code with Kimi
- Kimi can see Raven findings and suggest fixes automatically
- In chat: "fix the security issue on line 42" → Kimi sees the Raven diagnostic

---

## 🧪 Codex CLI (OpenAI)

**Integration:** MCP Server

### Setup

Codex CLI supports MCP via `--mcp-config`:

```bash
# Create mcp.json
cat > ~/.config/codex/mcp.json << 'EOF'
{
  "mcpServers": {
    "raven": {
      "command": "raven",
      "args": ["mcp"]
    }
  }
}
EOF

# Run codex with MCP
codex --mcp-config ~/.config/codex/mcp.json
```

Or set environment variable:
```bash
export CODEX_MCP_CONFIG=~/.config/codex/mcp.json
codex
```

### How to Use

```
User: review this auth module for security
Codex: [calls raven_scan_file on auth.js]
       This file has 2 medium-severity issues:
       1. Weak JWT secret (hardcoded string)
       2. Missing input validation on login...
```

---

## 🐙 GitHub Copilot Chat (in VS Code)

**Integration:** MCP via VS Code extension

### Setup

When you have the Raven VS Code Extension installed, Copilot Chat can reference Raven findings via context.

Additionally, configure MCP for Copilot Chat:
```json
// ~/.vscode/mcp.json (or workspace .vscode/mcp.json)
{
  "servers": {
    "raven": {
      "type": "stdio",
      "command": "raven",
      "args": ["mcp"]
    }
  }
}
```

### How to Use

In Copilot Chat:
- `@raven scan this file` — triggers file scan
- `@raven explain this finding` — explains the squiggle under cursor
- `@raven are there any secrets in this repo?` — deep secrets scan

---

## 🎩 Aider

**Integration:** MCP or command

### Setup

**Via MCP** (Aider supports MCP since v0.70):
```bash
aider --mcp-config ~/.aider/mcp.json
```

With `~/.aider/mcp.json`:
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

**Via command** (simpler):
```bash
# In .aider.conf.yml or .env
auto-commits: true
# Add a pre-commit check:
# Create .aider/hooks/pre-commit:
#!/bin/bash
raven scan --min-sev medium || exit 1
```

### How to Use

```
User: /security-check
Aider: [runs raven_scan_workspace]
       Found 2 new issues in your changes. Want me to fix them?

User: yes
Aider: [applies fixes and re-scans]
       ✅ All issues resolved.
```

---

## ➡️ Continue.dev

**Integration:** MCP or Context Provider

### Setup

In `~/.continue/config.json`:
```json
{
  "contextProviders": [
    {
      "name": "raven",
      "params": {
        "command": "raven scan --format json ."
      }
    }
  ],
  "mcpServers": [
    {
      "name": "raven",
      "command": "raven",
      "args": ["mcp"]
    }
  ]
}
```

### How to Use

- Type `@raven` in Continue chat to include current scan results in context
- Continue can invoke Raven tools automatically when you ask about security

---

## ⚡ Zed

**Integration:** LSP

### Setup

In your Zed `settings.json`:
```json
{
  "lsp": {
    "raven": {
      "binary": {
        "path": "raven",
        "arguments": ["lsp"]
      }
    }
  },
  "languages": {
    "JavaScript": {
      "language_servers": ["typescript-language-server", "raven"]
    },
    "TypeScript": {
      "language_servers": ["typescript-language-server", "raven"]
    },
    "Python": {
      "language_servers": ["pyright", "raven"]
    }
  }
}
```

### How to Use

- Diagnostics appear inline in Zed's editor
- Hover over error → full vulnerability description
- Zed's multi-buffer shows Raven findings across files

---

## 🌙 Neovim

**Integration:** LSP (nvim-lspconfig) + optional MCP

### Setup

**Option A: nvim-lspconfig**

In your `init.lua`:
```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

-- Define Raven LSP if not already defined
if not configs.raven then
  configs.raven = {
    default_config = {
      cmd = {'raven', 'lsp'},
      filetypes = {
        'javascript', 'typescript', 'python', 'go',
        'java', 'php', 'rust', 'ruby', 'kotlin',
        'swift', 'cs'
      },
      root_dir = lspconfig.util.root_pattern('.git', '.raven.yaml'),
      settings = {},
    },
  }
end

lspconfig.raven.setup{}
```

**Option B: Built-in LSP (no lspconfig)**
```lua
vim.api.nvim_create_autocmd('FileType', {
  pattern = {'javascript', 'typescript', 'python', 'go'},
  callback = function(args)
    vim.lsp.start({
      name = 'raven',
      cmd = {'raven', 'lsp'},
      root_dir = vim.fs.root(args.buf, {'.git', '.raven.yaml'}),
    })
  end,
})
```

**With nvim-cmp + null-ls:**
```lua
-- Raven diagnostics will show in your usual LSP UI
-- Use <leader>ca for code actions (quick fixes)
-- Use K for hover
-- Use ]d/[d for next/prev diagnostic
```

**MCP in Neovim:**
Use [mcphub.nvim](https://github.com/ravitemer/mcphub.nvim):
```lua
require("mcphub").setup({
  port = 3000,
  config = vim.fn.expand("~/.config/mcphub/servers.json"),
})
```

With `~/.config/mcphub/servers.json`:
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

### How to Use

- `:lua vim.diagnostic.goto_next()` — jump to finding
- `:lua vim.lsp.buf.code_action()` — apply quick fix
- `:lua vim.lsp.buf.hover()` — see vulnerability details

---

## 🦅 Emacs

**Integration:** LSP (eglot or lsp-mode)

### Setup

**With eglot:**
```elisp
(add-to-list 'eglot-server-programs
  '((js-mode ts-mode python-mode go-mode java-mode php-mode rust-mode ruby-mode kotlin-mode swift-mode csharp-mode)
    . ("raven" "lsp")))
```

**With lsp-mode:**
```elisp
(lsp-register-client
 (make-lsp-client
  :new-connection (lsp-stdio-connection '("raven" "lsp"))
  :activation-fn (lsp-activate-on "javascript" "typescript" "python" "go" "java" "php" "rust" "ruby" "kotlin" "swift" "csharp")
  :server-id 'raven))
```

### How to Use

- `M-x eglot` or `M-x lsp` — start Raven LSP
- Hover over diagnostic → popup with vulnerability info
- `M-x eglot-code-actions` — apply quick fixes

---

## 🌀 Helix

**Integration:** LSP (built-in)

### Setup

In `~/.config/helix/languages.toml`:
```toml
[language-server.raven]
command = "raven"
args = ["lsp"]

[[language]]
name = "javascript"
language-servers = [ "typescript-language-server", "raven" ]

[[language]]
name = "python"
language-servers = [ "pylsp", "raven" ]

[[language]]
name = "go"
language-servers = [ "gopls", "raven" ]

# ... repeat for other languages
```

### How to Use

- Diagnostics show in gutter and inline
- `Space + g` — goto diagnostic
- `Space + a` — code actions

---

## 🛩️ Sublime Text

**Integration:** LSP package

### Setup

Install [LSP](https://packagecontrol.io/packages/LSP) via Package Control, then in `LSP-raven.sublime-settings`:
```json
{
  "command": ["raven", "lsp"],
  "selector": "source.js, source.ts, source.python, source.go, source.java, source.php, source.rust, source.ruby, source.kotlin, source.swift, source.cs",
  "settings": {}
}
```

---

## 🗼 JetBrains (IntelliJ, PyCharm, WebStorm, etc.)

**Integration:** File Watcher + External Tool (no native LSP yet)

### Setup

**Option A: File Watcher**
1. Settings → Tools → File Watchers
2. Add new watcher:
   - **Program:** `raven`
   - **Arguments:** `scan --min-sev low --format json $FilePath$`
   - **Output paths to refresh:** `$FilePath$`
   - **Auto-save edited files:** Yes

**Option B: External Tool**
1. Settings → Tools → External Tools
2. Add `raven scan` tool
3. Bind to a keyboard shortcut

**Option C: Plugin** (future — JetBrains LSP support is improving)
JetBrains is adding LSP support. Once stable, Raven LSP will work natively.

---

## ❓ FAQ: Do I Need to Host Anything?

### Short Answer: **NO.**

Raven's integrations are **100% local**:

| Integration | Runs On | Needs Internet? | Needs Server? |
|------------|---------|----------------|---------------|
| **MCP** | User's machine | No | No |
| **LSP** | User's machine | No | No |
| **VS Code Extension** | User's machine | No | No |

### How MCP Works (Local Only)

```
┌─────────────────┐      stdio      ┌─────────────────┐
│  Claude Desktop │  ◄──────────►   │   raven mcp     │
│   (or Codex)    │   JSON-RPC 2.0  │  (local process)│
└─────────────────┘                 └─────────────────┘
```

The AI tool **spawns** `raven mcp` as a subprocess. They communicate via stdin/stdout. Nothing goes to the cloud. You don't run a server.

### Distribution

Users install Raven the same way they install any CLI tool:

```bash
# Go users
go install github.com/raven-security/raven/cmd/raven@latest

# Everyone else: download binary from GitHub Releases
# https://github.com/adrian-wulf/raven/releases
```

Once installed, all integrations work automatically. No API keys, no sign-up, no hosting.

---

## 🎯 Recommended Per Workflow

### "I use Claude/Cursor/Codex and want AI to check my code"
→ **MCP Server** (`raven mcp`)

### "I want red squiggles while I type"
→ **LSP Server** (`raven lsp`) + your editor's LSP client

### "I use VS Code and want the full experience"
→ **VS Code Extension** (LSP + panel + status bar + commands)

### "I want both: real-time + AI assistance"
→ **VS Code Extension + MCP** (Cursor setup)

---

## 🐛 Troubleshooting

### "raven: command not found"
```bash
which raven
# If empty, add to PATH:
export PATH="$PATH:$(go env GOPATH)/bin"
```

### "MCP server not connecting"
1. Check `raven mcp` works standalone:
   ```bash
   echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | raven mcp
   ```
2. Check the path in MCP config is absolute if needed:
   ```json
   {"command": "/usr/local/bin/raven", "args": ["mcp"]}
   ```

### "LSP not showing diagnostics"
1. Check `raven lsp` starts:
   ```bash
   raven lsp
   # Should show "Raven LSP server starting..."
   ```
2. Check your editor's LSP client logs
3. Verify file type is supported (`.js`, `.py`, `.go`, etc.)

### "VS Code extension won't load"
1. Make sure `raven` is in PATH (VS Code inherits shell PATH)
2. Check Output panel → "Raven Security Scanner" for logs
3. Try setting `raven.executablePath` explicitly in settings

---

## 🚀 Coming Soon

- [ ] JetBrains plugin (official LSP support)
- [ ] Vim plugin (beyond LSP — custom UI)
- [ ] Emacs package (MELPA)
- [ ] Pre-commit hook auto-install via `raven init`
- [ ] GitHub Action marketplace listing
- [ ] VS Code Extension marketplace publish

---

*Need help? Open an issue at https://github.com/adrian-wulf/raven/issues*
