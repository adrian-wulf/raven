package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/dlclark/regexp2"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/raven-security/raven/internal/ast"
	"github.com/raven-security/raven/internal/engine"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func rulesCmd() *cobra.Command {
	var (
		lang   string
		sev    string
		detail bool
		score  bool
	)

	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List available security rules",
		Long: `List all security rules that Raven uses to detect vulnerabilities.

Examples:
  raven rules              # List all rules
  raven rules --lang go    # Only Go rules
  raven rules --sev high   # Only high/critical severity
  raven rules --detail     # Show full rule details
  raven rules --score      # Show quality score for each rule`,
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

				if score {
					qs := engine.CalculateQualityScore(rule)
					scoreColor := "#00B894"
					if qs < 60 {
						scoreColor = "#E17055"
					} else if qs < 75 {
						scoreColor = "#FDCB6E"
					}
					scoreBadge := lipgloss.NewStyle().
						Background(lipgloss.Color(scoreColor)).
						Foreground(lipgloss.Color("#FFFFFF")).
						Bold(true).
						Padding(0, 1).
						Render(fmt.Sprintf("Q%d", qs))
					fmt.Printf("  %s Quality Score\n", scoreBadge)
				}

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
	cmd.Flags().BoolVar(&score, "score", false, "Show quality score for each rule")

	cmd.AddCommand(rulesValidateCmd())
	cmd.AddCommand(rulesSearchCmd())

	return cmd
}

func rulesValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [path]",
		Short: "Validate rule files",
		Long: `Validate Raven rule files for syntax errors and common mistakes.

Examples:
  raven rules validate              # Validate all loaded rules
  raven rules validate ./rules      # Validate rules in directory
  raven rules validate rule.yaml    # Validate single file`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var paths []string
			if len(args) > 0 {
				paths = args
			} else {
				paths = []string{"rules", "/usr/share/raven/rules"}
			}

			var total, valid, invalid int
			for _, path := range paths {
				info, err := os.Stat(path)
				if err != nil {
					continue
				}

				if !info.IsDir() {
					total++
					if v := validateRuleFile(path); v == nil {
						valid++
						fmt.Printf("✅ %s\n", path)
					} else {
						invalid++
						fmt.Printf("❌ %s: %v\n", path, v)
					}
					continue
				}

				filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
					if err != nil {
						return nil
					}
					// Skip hidden and disabled directories
					if info.IsDir() && (strings.HasPrefix(info.Name(), ".") || strings.HasPrefix(info.Name(), "_")) {
						return filepath.SkipDir
					}
					if info.IsDir() {
						return nil
					}
					ext := filepath.Ext(p)
					if ext != ".yaml" && ext != ".yml" {
						return nil
					}
					// Skip fixture files used for rule testing
					if strings.Contains(filepath.Base(p), ".fixture.") {
						return nil
					}
					total++
					if v := validateRuleFile(p); v == nil {
						valid++
						fmt.Printf("✅ %s\n", p)
					} else {
						invalid++
						fmt.Printf("❌ %s: %v\n", p, v)
					}
					return nil
				})
			}

			fmt.Println()
			if invalid == 0 {
				fmt.Printf("✅ All %d rule files valid\n", total)
			} else {
				fmt.Printf("⚠️  %d/%d rule files invalid\n", invalid, total)
				return fmt.Errorf("validation failed")
			}
			return nil
		},
	}
}

func validateRuleFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rule engine.Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	if rule.ID == "" {
		return fmt.Errorf("missing 'id' field")
	}
	if rule.Name == "" {
		return fmt.Errorf("missing 'name' field")
	}
	if rule.Severity == "" {
		return fmt.Errorf("missing 'severity' field")
	}
	if len(rule.Patterns) == 0 {
		return fmt.Errorf("no patterns defined")
	}

	// Collect languages to test AST queries against
	langsToTest := make(map[string]*ast.Language)
	for _, langName := range rule.Languages {
		if lang := ast.GetLanguageByName(langName); lang != nil {
			langsToTest[langName] = lang
		}
	}

	for i, p := range rule.Patterns {
		if p.Type == "" {
			return fmt.Errorf("pattern %d missing 'type'", i+1)
		}
		validTypes := map[string]bool{"regex": true, "literal": true, "ast-query": true, "ast": true, "taint": true}
		if !validTypes[p.Type] {
			return fmt.Errorf("pattern %d has invalid type: %s", i+1, p.Type)
		}
		if p.Type != "taint" && p.Pattern == "" && p.Query == "" {
			return fmt.Errorf("pattern %d missing 'pattern' or 'query'", i+1)
		}
		// Validate regex patterns compile (standard or regexp2 fallback)
		if p.Type == "regex" && p.Pattern != "" {
			if _, err := regexp.Compile(p.Pattern); err != nil {
				if _, err2 := regexp2.Compile(p.Pattern, regexp2.None); err2 != nil {
					return fmt.Errorf("pattern %d invalid regex: %w", i+1, err2)
				}
			}
		}
		// Validate AST queries compile against each supported language
		if (p.Type == "ast-query" || p.Type == "ast") && p.Query != "" {
			if len(langsToTest) == 0 {
				return fmt.Errorf("pattern %d is ast-query but rule has no valid languages", i+1)
			}
			for langName, langObj := range langsToTest {
				_, err := sitter.NewQuery([]byte(p.Query), langObj.Parser)
				if err != nil {
					return fmt.Errorf("pattern %d invalid ast-query for %s: %w", i+1, langName, err)
				}
			}
		}
	}
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func rulesSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search <keyword>",
		Short: "Search rules by name, id, category, or description",
		Long: `Search through all available rules.

Examples:
  raven rules search sql           # Rules matching "sql"
  raven rules search xss           # Rules matching "xss"
  raven rules search injection     # Rules matching "injection"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyword := strings.ToLower(args[0])

			loader := engine.NewRulesLoader()
			rules, err := loader.Load()
			if err != nil {
				return fmt.Errorf("loading rules: %w", err)
			}

			var matches []engine.Rule
			for _, rule := range rules {
				searchable := strings.ToLower(rule.ID + " " + rule.Name + " " + rule.Category + " " + rule.Description + " " + strings.Join(rule.Languages, " "))
				if strings.Contains(searchable, keyword) {
					matches = append(matches, rule)
				}
			}

			if len(matches) == 0 {
				fmt.Printf("No rules found for '%s'\n", keyword)
				return nil
			}

			fmt.Printf("Found %d rule(s) for '%s':\n\n", len(matches), keyword)
			for _, rule := range matches {
				fmt.Printf("  %s (%s)\n", rule.Name, rule.ID)
				fmt.Printf("    Severity: %s | Category: %s | Languages: %s\n",
					rule.Severity, rule.Category, strings.Join(rule.Languages, ", "))
				fmt.Printf("    %s\n", strings.TrimSpace(rule.Description))
				fmt.Println()
			}

			return nil
		},
	}
}
