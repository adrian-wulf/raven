package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/raven-security/raven/internal/engine"
	"github.com/spf13/cobra"
)

func rulesCmd() *cobra.Command {
	var (
		lang   string
		sev    string
		detail bool
	)

	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List available security rules",
		Long: `List all security rules that Raven uses to detect vulnerabilities.

Examples:
  raven rules              # List all rules
  raven rules --lang go    # Only Go rules
  raven rules --sev high   # Only high/critical severity
  raven rules --detail     # Show full rule details`,
		RunE: func(cmd *cobra.Command, args []string) error {
			loader := engine.NewRulesLoader()
			rules, err := loader.Load()
			if err != nil {
				return fmt.Errorf("loading rules: %w", err)
			}

			sevColors := map[engine.Severity]string{
				engine.Critical: "#FF0000",
				engine.High:     "#FF6B6B",
				engine.Medium:   "#FDCB6E",
				engine.Low:      "#74B9FF",
				engine.Info:     "#A29BFE",
			}

			fmt.Println()
			title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#6C5CE7"))
			fmt.Println(title.Render(fmt.Sprintf("📋 Security Rules (%d total)", len(rules))))
			fmt.Println()

			for _, rule := range rules {
				// Filter by language
				if lang != "" && !contains(rule.Languages, lang) {
					continue
				}
				// Filter by severity
				if sev != "" && engine.SeverityRank(rule.Severity) < engine.SeverityRank(engine.Severity(sev)) {
					continue
				}

				color := sevColors[rule.Severity]
				sevBadge := lipgloss.NewStyle().
					Background(lipgloss.Color(color)).
					Foreground(lipgloss.Color("#FFFFFF")).
					Bold(true).
					Padding(0, 1).
					Render(strings.ToUpper(string(rule.Severity)))

				fmt.Printf("%s %s\n", sevBadge, rule.Name)
				fmt.Printf("  ID: %s\n", rule.ID)
				fmt.Printf("  Category: %s | Languages: %s | Confidence: %s\n",
					rule.Category, strings.Join(rule.Languages, ", "), rule.Confidence)

				if detail {
					fmt.Printf("  %s\n", rule.Description)
					if rule.Fix != nil {
						fmt.Printf("  Fix: %s\n", rule.Fix.Description)
					}
					if len(rule.References) > 0 {
						fmt.Printf("  References:\n")
						for _, ref := range rule.References {
							fmt.Printf("    - %s\n", ref)
						}
					}
				}
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&lang, "lang", "l", "", "Filter by language")
	cmd.Flags().StringVarP(&sev, "sev", "s", "", "Filter by minimum severity")
	cmd.Flags().BoolVarP(&detail, "detail", "d", false, "Show full rule details")

	return cmd
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
