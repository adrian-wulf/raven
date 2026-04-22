package cli

import (
	"fmt"
	"os"

	"github.com/raven-security/raven/internal/engine"
	"github.com/raven-security/raven/internal/output"
	"github.com/spf13/cobra"
)

func ciCmd() *cobra.Command {
	var (
		format string
		outputFile string
		failOn string
	)

	cmd := &cobra.Command{
		Use:   "ci [paths...]",
		Short: "CI mode - scan and exit with error code on findings",
		Long: `Run Raven in CI/CD mode.

This is optimized for GitHub Actions, GitLab CI, and other CI systems:
  - Outputs SARIF for GitHub Advanced Security integration
  - Exits with code 1 if vulnerabilities are found
  - Can output to a file for artifact upload

Examples:
  raven ci                    # Scan current directory
  raven ci --format sarif     # Output SARIF format
  raven ci --output report.sarif
  raven ci --fail-on high     # Only fail on high/critical`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}

			loader := engine.NewRulesLoader()
			rules, err := loader.Load()
			if err != nil {
				return fmt.Errorf("loading rules: %w", err)
			}

			scanConfig := engine.ScanConfig{
				Paths:       paths,
				Exclude:     cfg.Rules.Exclude,
				MinSeverity: engine.Severity(failOn),
			}

			scanner := engine.NewScanner(rules, scanConfig)
			result, err := scanner.Scan()
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Output
			formatter := output.Formatter{
				Format:   format,
				Color:    false,
				ShowCode: false,
			}

			if outputFile != "" {
				old := os.Stdout
				f, _ := os.Create(outputFile)
				if f != nil {
					os.Stdout = f
					defer func() {
						os.Stdout = old
						f.Close()
					}()
				}
			}

			if err := formatter.Print(result); err != nil {
				return err
			}

			// Count findings at or above failOn severity
			failCount := 0
			minRank := engine.SeverityRank(engine.Severity(failOn))
			for _, f := range result.Findings {
				if engine.SeverityRank(f.Severity) >= minRank {
					failCount++
				}
			}

			if failCount > 0 {
				fmt.Fprintf(os.Stderr, "\n❌ Found %d %s+ severity issues\n", failCount, failOn)
				os.Exit(1)
			}

			fmt.Println("\n✅ No issues found at or above " + failOn + " severity")
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "sarif", "Output format: sarif, json, pretty")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file")
	cmd.Flags().StringVar(&failOn, "fail-on", "low", "Minimum severity to fail on")

	return cmd
}
