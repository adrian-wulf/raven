# Editor Integrations

Raven provides a Language Server Protocol (LSP) implementation that works with any LSP-compatible editor.

## Supported Editors

| Editor | Status | Features |
|--------|--------|----------|
| **VS Code** | ✅ Full | Diagnostics, inline fixes, status bar, commands, hover info |
| **Zed** | ✅ Full | Diagnostics, inline fixes, hover info |
| **Neovim** | ✅ Full | Diagnostics, inline fixes, keymaps, auto-fix on save |
| **Vim** (with coc.nvim) | ✅ Full | Diagnostics, inline fixes |
| **Emacs** (lsp-mode/eglot) | ✅ Basic | Diagnostics |
| **Helix** | ✅ Basic | Diagnostics |
| **Sublime Text** (LSP package) | ✅ Basic | Diagnostics |

## VS Code

Install the extension from the editor/vscode/ directory:

```bash
cd editor/vscode
npm install
npm run compile
# Press F5 to launch extension host
```

Features:
- Real-time security diagnostics as you type
- `Ctrl+Shift+R` / `Cmd+Shift+R` — scan workspace
- `Ctrl+Shift+F` / `Cmd+Shift+F` — fix all issues with AI
- Status bar shows security score
- Hover over underlined code for vulnerability details
- Code action lightbulb for inline fixes

## Zed

Add to your Zed `settings.json`:

```json
{
  "languages": {
    "JavaScript": {
      "language_servers": ["raven-lsp", "typescript-language-server"]
    },
    "Python": {
      "language_servers": ["raven-lsp", "pyright"]
    },
    "Go": {
      "language_servers": ["raven-lsp", "gopls"]
    }
  },
  "lsp": {
    "raven-lsp": {
      "binary": {
        "path": "raven",
        "arguments": ["lsp"]
      }
    }
  }
}
```

Full configuration is in `editor/zed/settings.json`.

## Neovim

Add to your Neovim config (using nvim-lspconfig):

```lua
require('lspconfig.configs').raven = {
  default_config = {
    cmd = { 'raven', 'lsp' },
    filetypes = { 'go', 'javascript', 'typescript', 'python', 'java', 'php', 'c', 'cpp', 'cs', 'rust', 'ruby', 'kotlin', 'swift', 'dart', 'elixir', 'scala', 'lua', 'solidity', 'sh', 'dockerfile', 'terraform', 'yaml', 'json' },
    root_dir = require('lspconfig.util').root_pattern('.git', 'go.mod', 'package.json'),
  }
}

require('lspconfig').raven.setup({})
```

Keymaps (after setup):
- `<leader>ra` — code action (inline fix)
- `<leader>rf` — fix all with Raven
- `<leader>rs` — scan current file
- `K` — hover info

Full configuration is in `editor/nvim/raven.lua`.

## Vim (with coc.nvim)

Add to `coc-settings.json`:

```json
{
  "languageserver": {
    "raven": {
      "command": "raven",
      "args": ["lsp"],
      "filetypes": ["go", "javascript", "typescript", "python", "java", "php", "c", "cpp", "rust", "ruby", "kotlin", "swift"]
    }
  }
}
```

## Emacs

With `lsp-mode`:

```elisp
(use-package lsp-mode
  :hook ((go-mode . lsp)
         (python-mode . lsp)
         (js-mode . lsp))
  :commands lsp
  :config
  (add-to-list 'lsp-language-id-configuration '(go-mode . "go"))
  (lsp-register-client
   (make-lsp-client :new-connection (lsp-stdio-connection '("raven" "lsp"))
                    :major-modes '(go-mode python-mode js-mode)
                    :server-id 'raven)))
```

## IDE Inline Fixes

Raven LSP server provides **Code Actions** that appear as:
- **Lightbulb icon** in VS Code / Zed / Neovim
- **Quick Fix menu** (`Ctrl+.` / `Cmd+.` in VS Code)
- **Code action menu** (`<leader>ra` in Neovim)

Available actions per finding:
1. **"Fix with Raven"** — applies AI-generated fix (requires LLM provider configuration)
2. **"Learn more"** — opens vulnerability documentation
3. **"Ignore with #raven-ignore"** — adds annotation comment

### Auto-fix on Save (Neovim)

Enable automatic application of safe fixes when saving:

```lua
vim.api.nvim_create_autocmd('BufWritePost', {
  pattern = { '*.go', '*.js', '*.ts', '*.py' },
  callback = function()
    vim.lsp.buf.code_action({
      context = { only = { 'source.fixAll.raven' } },
      apply = true,
    })
  end,
})
```

### Fix All Command

```bash
# Command palette / keybinding
raven fix-ai

# Or via LSP command
raven lsp --fix-all
```

## LSP Features Reference

| Feature | Method | Status |
|---------|--------|--------|
| Diagnostics | `textDocument/publishDiagnostics` | ✅ |
| Hover info | `textDocument/hover` | ✅ |
| Code Actions | `textDocument/codeAction` | ✅ |
| Execute Command | `workspace/executeCommand` | ✅ |
| Inline Fixes | CodeAction (quickfix) | ✅ |
| Workspace Scan | Custom command | ✅ |
| Fix All | Custom command | ✅ |
| Document Links | `textDocument/documentLink` | ✅ |

## Troubleshooting

### LSP Server not starting

```bash
# Verify raven is installed and in PATH
which raven
raven lsp --help

# Check LSP logs
raven lsp --log-level debug
```

### No diagnostics showing

- Ensure the file type is in the LSP configuration
- Check if the file is in an excluded path (node_modules, vendor, etc.)
- Verify raven can scan the file: `raven scan <file>`

### Inline fixes not working

- Configure LLM provider: `export OPENROUTER_API_KEY=...`
- Check if the finding has an available fix: some vulnerabilities require manual remediation
- Enable debug logging to see fix generation errors
