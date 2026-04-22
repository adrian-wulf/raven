package cli

import (
	"fmt"

	"github.com/raven-security/raven/internal/engine"
	"github.com/spf13/cobra"
)

func fixCmd() *cobra.Command {
	var (
		dryRun bool
		sev    string
	)

	cmd := &cobra.Command{
		Use:   "fix [paths...]",
		Short: "Auto-fix security issues",
		Long: `Automatically fix security issues where Raven knows how.

By default, this shows what would be fixed without making changes.
Use --apply to actually modify files.

Examples:
  raven fix               # Dry-run fixes
  raven fix --apply       # Actually apply fixes
  raven fix --sev high    # Only fix high/critical issues`,
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
				MinSeverity: engine.Severity(sev),
			}

			scanner := engine.NewScanner(rules, scanConfig)
			result, err := scanner.Scan()
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			applier := &engine.FixApplier{DryRun: dryRun}
			fixed := 0
			failed := 0

			for _, finding := range result.Findings {
				if !finding.FixAvailable {
					continue
				}

				newCode, err := applier.Apply(finding)
				if err != nil {
					failed++
					if verbose {
						fmt.Printf("  ✗ %s:%d - %v\n", finding.File, finding.Line, err)
					}
					continue
				}

				fixed++
				action := "Would fix"
				if !dryRun {
					action = "Fixed"
				}
				fmt.Printf("  ✓ %s %s:%d\n", action, finding.File, finding.Line)
				if verbose {
					fmt.Printf("    %s\n", newCode)
				}
			}

			fmt.Println()
			if dryRun {
				fmt.Printf("Would fix %d issues (use --apply to apply)\n", fixed)
			} else {
				fmt.Printf("Fixed %d issues\n", fixed)
			}
			if failed > 0 {
				fmt.Printf("Failed to fix %d issues\n", failed)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", true, "Show what would be fixed without modifying files")
	cmd.Flags().BoolVar(&dryRun, "apply", false, "Actually apply fixes (sets --dry-run=false)")
	cmd.Flags().StringVar(&sev, "sev", "low", "Minimum severity to fix")

	return cmd
}
