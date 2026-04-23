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
	var providerName string

	cmd := &cobra.Command{
		Use:   "fix-ai [paths...]",
		Short: "Fix security issues using AI",
		Long: `Use AI (LLM) to generate secure fixes for vulnerabilities.

This sends code snippets to an LLM API and applies the suggested fixes.
You can review each fix before applying.

Supported providers (auto-detected from env):
  • openrouter    — RAVEN_LLM_API_KEY or OPENROUTER_API_KEY
  • nvidia        — NVIDIA_API_KEY (free tier: 40 req/min!)
  • openai        — OPENAI_API_KEY
  • anthropic     — ANTHROPIC_API_KEY (Claude)
  • groq          — GROQ_API_KEY (very fast)
  • deepseek      — DEEPSEEK_API_KEY
  • together      — TOGETHER_API_KEY
  • gemini        — GEMINI_API_KEY or GOOGLE_API_KEY
  • ollama        — OLLAMA_HOST (local, free)
  • azure         — AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT

Set RAVEN_LLM_PROVIDER to force a specific provider.

Examples:
  raven fix-ai                  # AI-fix all issues with auto-detected provider
  raven fix-ai --provider nvidia # Use NVIDIA NIM (free)
  raven fix-ai ./src            # AI-fix specific directory
  raven fix-ai --dry-run        # Preview fixes without applying`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}

			// Setup client
			var client *llm.Client
			var err error

			if providerName != "" {
				client, err = llm.NewClientWithProvider(providerName)
				if err != nil {
					fmt.Println(styles.Error.Render("❌ " + err.Error()))
					printProviderHelp()
					return err
				}
			} else {
				client = llm.NewClient()
			}

			// Test the client early
			providerName := client.ProviderName()
			if providerName == "none" || providerName == "unconfigured" {
				fmt.Println(styles.Error.Render("❌ No LLM provider configured."))
				printProviderHelp()
				return fmt.Errorf("no LLM provider configured")
			}

			fmt.Printf("🤖 Using provider: %s\n", styles.Info.Render(providerName))
			fmt.Println()

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
				fmt.Printf("  🤖 Asking %s for fix...\n", providerName)
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
	cmd.Flags().StringVar(&providerName, "provider", "", "LLM provider to use (overrides auto-detection)")

	return cmd
}

func printProviderHelp() {
	fmt.Println()
	fmt.Println("Available providers:")
	for _, name := range llm.AvailableProviders() {
		fmt.Printf("  • %s\n", name)
	}
	fmt.Println()
	fmt.Println("Quick start:")
	fmt.Println("  # Free NVIDIA NIM (40 req/min):")
	fmt.Println("  export NVIDIA_API_KEY=your-key")
	fmt.Println("  raven fix-ai")
	fmt.Println()
	fmt.Println("  # OpenRouter (many models):")
	fmt.Println("  export OPENROUTER_API_KEY=your-key")
	fmt.Println("  raven fix-ai")
	fmt.Println()
	fmt.Println("  # Local Ollama (completely free):")
	fmt.Println("  export OLLAMA_HOST=http://localhost:11434")
	fmt.Println("  raven fix-ai --provider ollama")
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
