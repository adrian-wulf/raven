package cli

import (
	"fmt"
	"os"

	"github.com/raven-security/raven/internal/engine"
	"github.com/raven-security/raven/internal/output"
	"github.com/spf13/cobra"
)

func scanCmd() *cobra.Command {
	var (
		format     string
		noColor    bool
		noCode     bool
		minSev     string
		confidence string
		fixFlag    bool
	)

	cmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan code for security vulnerabilities",
		Long: `Scan your project for security vulnerabilities.

Raven detects SQL injection, XSS, hardcoded secrets, and more.
It's designed for AI-generated code - it catches the mistakes
that LLMs commonly make.

Examples:
  raven scan                    # Scan current directory
  raven scan ./src              # Scan specific directory
  raven scan --fix              # Scan and auto-fix issues
  raven scan --format json      # Output as JSON
  raven scan --min-sev high     # Only show high/critical issues`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}

			// Load rules
			loader := engine.NewRulesLoader()
			rules, err := loader.Load()
			if err != nil {
				return fmt.Errorf("loading rules: %w", err)
			}
			if len(rules) == 0 {
				fmt.Println(styles.Warning.Render("Warning: No rules found. Run `raven init` to set up."))
				return nil
			}

			if verbose {
				fmt.Printf("Loaded %d rules\n", len(rules))
			}

			// Configure scanner
			scanConfig := engine.ScanConfig{
				Paths:       paths,
				Exclude:     cfg.Rules.Exclude,
				Confidence:  confidence,
				MinSeverity: engine.Severity(minSev),
			}

			scanner := engine.NewScanner(rules, scanConfig)
			result, err := scanner.Scan()
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Output results
			formatter := output.Formatter{
				Format:   format,
				Color:    !noColor,
				ShowCode: !noCode,
			}

			if err := formatter.Print(result); err != nil {
				return err
			}

			// Auto-fix if requested
			if fixFlag && result.HasFixes() {
				fmt.Println(styles.Info.Render("Applying fixes..."))
				applier := &engine.FixApplier{DryRun: false}
				fixed := 0
				for _, finding := range result.Findings {
					if finding.FixAvailable {
						if _, err := applier.Apply(finding); err == nil {
							fixed++
						}
					}
				}
				fmt.Printf("Fixed %d issues\n", fixed)
			}

			// Exit code for CI
			if len(result.Findings) > 0 {
				os.Exit(1)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "pretty", "Output format: pretty, json, sarif")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	cmd.Flags().BoolVar(&noCode, "no-code", false, "Hide code snippets")
	cmd.Flags().StringVar(&minSev, "min-sev", "low", "Minimum severity: critical, high, medium, low, info")
	cmd.Flags().StringVar(&confidence, "confidence", "medium", "Minimum confidence: high, medium, low")
	cmd.Flags().BoolVar(&fixFlag, "fix", false, "Auto-fix issues where possible")

	return cmd
}
