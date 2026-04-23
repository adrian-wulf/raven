package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/raven-security/raven/internal/hooks"
	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	var (
		withCI        bool
		withPolicy    bool
		withPreCommit bool
		withBaseline  bool
		withAll       bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Raven in your project",
		Long: `Set up Raven configuration in your project.

This creates a .raven.yaml config file and optionally sets up
CI integration, policy, pre-commit hooks, and baseline.

Examples:
  raven init                          # Basic config only
  raven init --all                    # Full setup (CI + policy + hook + baseline)
  raven init --ci --pre-commit        # CI workflow + pre-commit hook
  raven init --policy --baseline      # Policy + empty baseline`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if withAll {
				withCI = true
				withPolicy = true
				withPreCommit = true
				withBaseline = true
			}

			configPath := ".raven.yaml"
			if _, err := os.Stat(configPath); err == nil {
				fmt.Printf("⚠️  %s already exists, skipping\n", configPath)
			} else {
				content := `# Raven Security Scanner Configuration
# https://github.com/raven-security/raven

rules:
  paths:
    - .
  exclude:
    - node_modules
    - vendor
    - dist
    - build
    - .git
    - "*.min.js"
  confidence: medium

output:
  format: pretty
  color: true
  show_code: true

severity:
  min: low
`
				if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
					return fmt.Errorf("writing config: %w", err)
				}
				fmt.Printf("✅ Created %s\n", configPath)
			}

			if withPolicy {
				policyPath := ".raven-policy.yaml"
				if _, err := os.Stat(policyPath); err == nil {
					fmt.Printf("⚠️  %s already exists, skipping\n", policyPath)
				} else {
					content := `# Raven Security Policy
# https://github.com/raven-security/raven

max_findings:
  critical: 0
  high: 0
  medium: 5

blocked_rules:
#  - raven-go-sqli-001

fail_on_new: false
`
					if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
						return fmt.Errorf("writing policy: %w", err)
					}
					fmt.Printf("✅ Created %s\n", policyPath)
				}
			}

			if withBaseline {
				baselinePath := ".raven-baseline.json"
				if _, err := os.Stat(baselinePath); err == nil {
					fmt.Printf("⚠️  %s already exists, skipping\n", baselinePath)
				} else {
					if err := os.WriteFile(baselinePath, []byte(`{"records":[]}`), 0644); err != nil {
						return fmt.Errorf("writing baseline: %w", err)
					}
					fmt.Printf("✅ Created %s\n", baselinePath)
				}
			}

			if withPreCommit {
				if err := hooks.InstallHook(); err != nil {
					fmt.Fprintf(os.Stderr, "⚠️  Could not install pre-commit hook: %v\n", err)
				}
			}

			if withCI {
				workflowDir := ".github/workflows"
				workflowPath := filepath.Join(workflowDir, "raven.yml")
				if _, err := os.Stat(workflowPath); err == nil {
					fmt.Printf("⚠️  %s already exists, skipping\n", workflowPath)
				} else {
					if err := os.MkdirAll(workflowDir, 0755); err != nil {
						return fmt.Errorf("creating .github/workflows: %w", err)
					}
					content := `name: Security Scan

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
    - uses: actions/checkout@v4
    - name: Run Raven Security Scan
      uses: raven-security/raven@v1
      with:
        format: sarif
        output: raven-results.sarif
        secrets: true
        deps: true
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v4
      if: always()
      with:
        sarif_file: raven-results.sarif
`
					if err := os.WriteFile(workflowPath, []byte(content), 0644); err != nil {
						return fmt.Errorf("writing workflow: %w", err)
					}
					fmt.Printf("✅ Created %s\n", workflowPath)
				}
			}

			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Println("  raven scan              # Scan your project")
			fmt.Println("  raven rules             # See available rules")
			fmt.Println("  raven rules validate    # Validate custom rules")
			fmt.Println("  raven ci                # CI mode")

			return nil
		},
	}

	cmd.Flags().BoolVar(&withCI, "ci", false, "Add GitHub Actions workflow")
	cmd.Flags().BoolVar(&withPolicy, "policy", false, "Add .raven-policy.yaml")
	cmd.Flags().BoolVar(&withPreCommit, "pre-commit", false, "Install pre-commit hook")
	cmd.Flags().BoolVar(&withBaseline, "baseline", false, "Add empty .raven-baseline.json")
	cmd.Flags().BoolVar(&withAll, "all", false, "Full setup (CI + policy + hook + baseline)")

	return cmd
}

func learnCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "learn <topic>",
		Short: "Learn about a security vulnerability",
		Long: `Get an explanation of a security vulnerability and how to fix it.

Examples:
  raven learn sqli
  raven learn xss
  raven learn secrets`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			topic := args[0]

			explanations := map[string]string{
				"sqli": `SQL Injection (SQLi)

What it is:
  When user input is inserted directly into SQL queries, attackers
  can manipulate the query to read, modify, or delete database data.

Example (VULNERABLE):
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  db.query(query);

Example (SAFE):
  db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);

How to fix:
  • Use parameterized queries (prepared statements)
  • Never concatenate user input into SQL
  • Use ORMs that handle escaping automatically
  • Validate and sanitize input

Impact:
  Data theft, data deletion, authentication bypass, RCE in some cases.`,
				"xss": `Cross-Site Scripting (XSS)

What it is:
  When user input is rendered in a web page without escaping,
  attackers can inject JavaScript that runs in other users' browsers.

Example (VULNERABLE):
  element.innerHTML = userInput;

Example (SAFE):
  element.textContent = userInput;

How to fix:
  • Use textContent instead of innerHTML
  • Sanitize with DOMPurify before rendering
  • Use framework auto-escaping (React, Vue)
  • Set CSP headers

Impact:
  Session hijacking, credential theft, defacement, keylogging.`,
				"secrets": `Hardcoded Secrets

What it is:
  API keys, passwords, tokens committed to source code.
  AI often generates example credentials that developers forget to remove.

Example (VULNERABLE):
  const API_KEY = "sk-fake";

Example (SAFE):
  const API_KEY = process.env.API_KEY;

How to fix:
  • Use environment variables
  • Use secret managers (AWS Secrets Manager, HashiCorp Vault)
  • Add .env to .gitignore
  • Rotate leaked credentials immediately

Impact:
  Unauthorized API access, data breaches, financial loss.`,
				"command": `Command Injection

What it is:
  When user input is passed to system shell commands,
  attackers can execute arbitrary commands on the server.

Example (VULNERABLE):
  execute("ping " + userHost);

Example (SAFE):
  execFile("ping", [req.params.host]);

How to fix:
  • Use parameterized execution (execFile, spawn with array)
  • Avoid shell=True in subprocess calls
  • Validate input against allowlist
  • Use higher-level libraries instead of shell commands

Impact:
  Remote code execution, full server compromise.`,
			}

			explanation, ok := explanations[topic]
			if !ok {
				fmt.Printf("Unknown topic: %s\n", topic)
				fmt.Println("Available topics: sqli, xss, secrets, command")
				return nil
			}

			fmt.Println(explanation)
			return nil
		},
	}
}
