# JetBrains IDE Integration for Raven

Raven integrates with JetBrains IDEs (IntelliJ IDEA, PyCharm, GoLand, WebStorm, Rider, CLion, RubyMine, PhpStorm) via the **LSP4IJ** plugin — a free, open-source LSP client for JetBrains.

## Installation

### 1. Install LSP4IJ Plugin

Open your JetBrains IDE:

```
Settings/Preferences → Plugins → Marketplace → Search "LSP4IJ" → Install → Restart IDE
```

Or download directly: [https://plugins.jetbrains.com/plugin/26015-lsp4ij](https://plugins.jetbrains.com/plugin/26015-lsp4ij)

### 2. Configure Raven LSP Server

After installing LSP4IJ, configure Raven as a language server:

```
Settings/Preferences → Languages & Frameworks → Language Servers
```

Click **+** (Add) and fill in:

| Field | Value |
|-------|-------|
| Name | `Raven Security Scanner` |
| Command | `raven` |
| Arguments | `lsp` |
| 

### 3. Associate File Types

In the same dialog, associate Raven with file types:

- Go files (`.go`)
- JavaScript/TypeScript (`.js`, `.ts`, `.jsx`, `.tsx`)
- Python (`.py`)
- Java (`.java`)
- PHP (`.php`)
- C/C++ (`.c`, `.cpp`, `.h`)
- C# (`.cs`)
- Rust (`.rs`)
- Ruby (`.rb`)
- Kotlin (`.kt`)
- Swift (`.swift`)
- Dart (`.dart`)
- YAML (`.yaml`, `.yml`) — for K8s scanning
- Dockerfile (`.dockerfile`, `Dockerfile`)
- Terraform (`.tf`, `.tfvars`)

### 4. Features Available

With LSP4IJ + Raven, you get:

| Feature | JetBrains UI Element |
|---------|---------------------|
| Security diagnostics | Editor gutter / underlined code |
| Hover info | Hover tooltip |
| Code actions | Alt+Enter quick fixes |
| Inline fixes | Lightbulb icon in gutter |
| Document links | Clickable CWE/OWASP links |

## Alternative: External Annotator (No Plugin Required)

If you prefer not to install LSP4IJ, use JetBrains' built-in External Annotator:

### Setup

1. Go to `Settings → Tools → External Tools`
2. Click **+** to add a new tool:

**Name:** `Raven Scan`

**Program:** `raven`

**Arguments:** `scan --format json $FilePath$`

**Working directory:** `$ProjectFileDir$`

**Output filters:** `$FILE_PATH$:$LINE$:$COLUMN$:$MESSAGE$`

3. Assign a keyboard shortcut:
   `Settings → Keymap → External Tools → Raven Scan → Add Shortcut`
   (e.g., `Ctrl+Shift+R` / `Cmd+Shift+R`)

4. (Optional) Set up as pre-commit:
   `Settings → Tools → External Tools → Raven Scan → Show console when a message is printed`

## Quick Actions

### Scan Current File
```
Tools → External Tools → Raven Scan
```

### Scan Entire Project
```
Terminal: raven scan .
```

### AI Fix Current Issue
```
Select code → Tools → External Tools → Raven Fix
```

## Troubleshooting

### LSP Server not starting
```
Check: Settings → Languages & Frameworks → Language Servers → Raven → Test Connection
```

### No diagnostics showing
1. Ensure file type is associated in LSP4IJ settings
2. Check if Raven can scan the file: `raven scan <file>` in terminal
3. Verify file is not in excluded path (node_modules, vendor, etc.)

### Slow performance
- LSP4IJ can be resource-intensive with large projects
- Consider using `--staged` or `--since` flags for faster scans
- Exclude large directories in `.raven.yaml`

## Related Tools

| JetBrains Plugin | Purpose | Compatible with Raven |
|-----------------|---------|----------------------|
| LSP4IJ | LSP client | ✅ Required |
| .env files support | Secret detection | ✅ Complementary |
| SonarLint | SAST | ✅ Complementary |
| Code With Me | Pair programming | ✅ Raven scans shared code |

## Future: Native JetBrains Plugin

A native Raven plugin for JetBrains Platform is planned (see ROADMAP.md v0.26.0). It would provide:
- First-class tool window with finding list
- Severity-based filtering and grouping
- One-click fixes with AI
- Baseline comparison view
- Policy enforcement UI
- Team configuration sync

---

*For now, LSP4IJ provides the best integration experience without a custom plugin.*
