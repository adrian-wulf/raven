package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize Raven in your project",
		Long: `Set up Raven configuration in your project.

This creates a raven.yaml config file and optionally copies
the built-in rules to your project for customization.

Examples:
  raven init`,
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := ".raven.yaml"

			if _, err := os.Stat(configPath); err == nil {
				return fmt.Errorf("raven.yaml already exists")
			}

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

fix:
  enabled: true
  auto_apply: false
  dry_run: true

severity:
  min: low
`
			if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
				return fmt.Errorf("writing config: %w", err)
			}

			fmt.Printf("✅ Created %s\n", configPath)
			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Println("  raven scan              # Scan your project")
			fmt.Println("  raven rules             # See available rules")
			fmt.Println("  raven ci                # CI mode")

			return nil
		},
	}
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
  const API_KEY = "sk-live-abc123...";

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
  exec("ping " + req.params.host);

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
