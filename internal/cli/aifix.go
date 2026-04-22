package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/raven-security/raven/internal/engine"
	"github.com/raven-security/raven/internal/llm"
	"github.com/spf13/cobra"
)

func aiFixCmd() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "fix-ai [paths...]",
		Short: "Fix security issues using AI",
		Long: `Use AI (LLM) to generate secure fixes for vulnerabilities.

This sends code snippets to an LLM API (OpenRouter, DeepSeek, etc.)
and applies the suggested fixes. You can review each fix before applying.

Requires: RAVEN_LLM_API_KEY or OPENROUTER_API_KEY environment variable.

Examples:
  raven fix-ai              # AI-fix all issues
  raven fix-ai ./src        # AI-fix specific directory
  raven fix-ai --dry-run    # Preview fixes without applying`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}

			// Check API key
			apiKey := os.Getenv("RAVEN_LLM_API_KEY")
			if apiKey == "" {
				apiKey = os.Getenv("OPENROUTER_API_KEY")
			}
			if apiKey == "" {
				fmt.Println(styles.Error.Render("❌ No LLM API key configured."))
				fmt.Println("   Set RAVEN_LLM_API_KEY or OPENROUTER_API_KEY environment variable.")
				fmt.Println("   Get a free key at https://openrouter.ai/keys")
				return fmt.Errorf("missing API key")
			}

			// Load rules and scan
			loader := engine.NewRulesLoader()
			rules, err := loader.Load()
			if err != nil {
				return fmt.Errorf("loading rules: %w", err)
			}

			scanConfig := engine.ScanConfig{
				Paths:       paths,
				Exclude:     cfg.Rules.Exclude,
				Confidence:  cfg.Rules.Confidence,
				MinSeverity: engine.Severity(cfg.Severity.Min),
			}

			scanner := engine.NewScanner(rules, scanConfig)
			result, err := scanner.Scan()
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			if len(result.Findings) == 0 {
				fmt.Println(styles.Success.Render("✅ No security issues found!"))
				return nil
			}

			// AI fix each finding
			client := llm.NewClient()
			fixed := 0
			skipped := 0
			failed := 0

			titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#6C5CE7"))

			for i, finding := range result.Findings {
				fmt.Printf("\n%s Finding %d/%d\n", titleStyle.Render("═══"), i+1, len(result.Findings))
				fmt.Printf("  [%s] %s\n", finding.Severity, finding.RuleName)
				fmt.Printf("  %s:%d\n", finding.File, finding.Line)
				fmt.Printf("  %s\n", finding.Message)

				if dryRun {
					fmt.Println("  (dry-run: skipping AI call)")
					continue
				}

				// Read the vulnerable code
				code, err := readLineRange(finding.File, finding.Line, 5)
				if err != nil {
					fmt.Printf("  ✗ Error reading file: %v\n", err)
					failed++
					continue
				}

				// Call LLM
				fmt.Println("  🤖 Asking AI for fix...")
				resp, err := client.GenerateFix(llm.FixRequest{
					Code:        code,
					Language:    engine.DetectLanguage(finding.File),
					VulnType:    finding.Category,
					Description: finding.RuleName,
					Message:     finding.Message,
				})
				if err != nil {
					fmt.Printf("  ✗ AI error: %v\n", err)
					failed++
					continue
				}

				// Show diff
				fmt.Println()
				fmt.Println("  Proposed fix:")
				fmt.Printf("  %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#55EFC4")).Render(resp.FixedCode))
				fmt.Println()
				fmt.Printf("  Explanation: %s\n", resp.Explanation)
				fmt.Printf("  Confidence: %.0f%%\n", resp.Confidence*100)

				// Ask user
				if !cfg.Fix.AutoApply {
					fmt.Print("  Apply this fix? [y/n/s]: ")
					var answer string
					fmt.Scanln(&answer)
					if strings.ToLower(answer) != "y" {
						fmt.Println("  ⏭️  Skipped.")
						skipped++
						continue
					}
				}

				// Apply fix
				if err := applyAIFix(finding, resp.FixedCode); err != nil {
					fmt.Printf("  ✗ Error applying fix: %v\n", err)
					failed++
					continue
				}

				fmt.Println("  ✅ Applied!")
				fixed++
			}

			fmt.Println()
			fmt.Println(titleStyle.Render("═══ Summary ═══"))
			fmt.Printf("  Fixed: %d | Skipped: %d | Failed: %d\n", fixed, skipped, failed)

			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview without applying fixes")

	return cmd
}

func readLineRange(file string, line, context int) (string, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(content), "\n")
	start := max(0, line-context-1)
	end := min(len(lines), line+context)

	var result []string
	for i := start; i < end; i++ {
		prefix := "  "
		if i == line-1 {
			prefix = "> "
		}
		result = append(result, prefix+lines[i])
	}

	return strings.Join(result, "\n"), nil
}

func applyAIFix(finding engine.Finding, fixedCode string) error {
	// Simple replacement: replace the finding line with fixed code
	content, err := os.ReadFile(finding.File)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	if finding.Line < 1 || finding.Line > len(lines) {
		return fmt.Errorf("line %d out of range", finding.Line)
	}

	// For now, just replace the line. In the future, could be smarter.
	lines[finding.Line-1] = fixedCode

	newContent := strings.Join(lines, "\n")
	return os.WriteFile(finding.File, []byte(newContent), 0644)
}
