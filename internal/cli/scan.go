package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/raven-security/raven/internal/baseline"
	"github.com/raven-security/raven/internal/deps"
	"github.com/raven-security/raven/internal/engine"
	"github.com/raven-security/raven/internal/framework"
	"github.com/raven-security/raven/internal/output"
	"github.com/raven-security/raven/internal/secrets"
	"github.com/raven-security/raven/internal/suppress"
	"github.com/spf13/cobra"
)

func scanCmd() *cobra.Command {
	var (
		format         string
		noColor        bool
		noCode         bool
		minSev         string
		confidence     string
		fixFlag        bool
		depsFlag       bool
		secretsFlag    bool
		baselinePath     string
		updateBaseline   bool
		noIgnoreComments bool
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
  raven scan --min-sev high     # Only show high/critical issues
  raven scan --baseline .raven-baseline.json  # Only report new issues
  raven scan --update-baseline                # Save current findings as baseline
  raven scan --no-ignore-comments             # Ignore inline suppression comments
  raven scan --secrets                        # Deep scan for hardcoded secrets`,
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

			// Detect frameworks
			fwDetector := framework.NewDetector(paths[0])
			detectedFrameworks, _ := fwDetector.Detect()
			var fwNames []string
			if len(detectedFrameworks) > 0 {
				for _, fw := range detectedFrameworks {
					fwNames = append(fwNames, fw.Name)
				}
				fmt.Fprintf(os.Stderr, "📦 Frameworks: %s\n\n", framework.FormatFrameworks(detectedFrameworks))
			}

			// Load baseline if specified
			var bl *baseline.Baseline
			if baselinePath != "" {
				loaded, err := baseline.Load(baselinePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: could not load baseline (%v), treating as empty\n", err)
					bl = baseline.New()
				} else {
					bl = loaded
					if verbose {
						fmt.Printf("Loaded baseline with %d findings\n", bl.Count())
					}
				}
			}

			// Configure scanner
			var suppressMap *suppress.Map
			if !noIgnoreComments {
				suppressMap = suppress.NewMap()
			}

			scanConfig := engine.ScanConfig{
				Paths:        paths,
				Exclude:      cfg.Rules.Exclude,
				Frameworks:   fwNames,
				Confidence:   confidence,
				MinSeverity:  engine.Severity(minSev),
				Baseline:     bl,
				Suppressions: suppressMap,
			}

			scanner := engine.NewScanner(rules, scanConfig)
			result, err := scanner.Scan()
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Secrets scanning
			if secretsFlag {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, "🔐 Scanning for secrets...")
				secretDetector := secrets.NewDetector()
				secretCount := 0
				for _, path := range paths {
					// Walk files and scan each
					filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
						if err != nil || info.IsDir() {
							return nil
						}
						ext := filepath.Ext(file)
						if ext != ".js" && ext != ".ts" && ext != ".go" && ext != ".py" && ext != ".php" && ext != ".rb" && ext != ".java" && ext != ".env" && ext != ".yaml" && ext != ".yml" && ext != ".json" {
							return nil
						}
						findings, err := secretDetector.Detect(file)
						if err != nil {
							return nil
						}
						for _, f := range findings {
							result.Findings = append(result.Findings, engine.Finding{
								RuleID:     f.RuleID,
								RuleName:   f.RuleName,
								Severity:   engine.Severity(f.Severity),
								Message:    "Hardcoded secret detected: " + f.Type,
								File:       f.File,
								Line:       f.Line,
								Column:     f.Column,
								Snippet:    f.Snippet,
								Confidence: "high",
							})
							secretCount++
						}
						return nil
					})
				}
				if secretCount > 0 {
					fmt.Fprintf(os.Stderr, "⚠️  Found %d secrets\n", secretCount)
				} else {
					fmt.Fprintln(os.Stderr, "✅ No secrets found")
				}
			}

			// Dependency scanning (before output so JSON includes vulns)
			var depVulns []deps.Vulnerability
			if depsFlag {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, "🔍 Scanning dependencies...")
				depScanner := deps.NewScanner()
				var err error
				depVulns, err = depScanner.Scan(paths[0])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Dependency scan error: %v\n", err)
				} else if len(depVulns) > 0 {
					fmt.Fprintf(os.Stderr, "⚠️  Found %d vulnerable dependencies:\n", len(depVulns))
					for _, v := range depVulns {
						fixed := v.FixedVersion
						if fixed == "" {
							fixed = "unknown"
						}
						fmt.Fprintf(os.Stderr, "  %s: %s@%s → %s\n", v.ID, v.Package, v.Version, fixed)
						fmt.Fprintf(os.Stderr, "    %s\n", v.Summary)
					}
				} else {
					fmt.Fprintln(os.Stderr, "✅ No known vulnerabilities in dependencies")
				}

				// Convert to engine.Vulnerability for JSON output
				for _, v := range depVulns {
					result.Vulnerabilities = append(result.Vulnerabilities, engine.Vulnerability{
						ID:           v.ID,
						Summary:      v.Summary,
						Severity:     v.Severity,
						Package:      v.Package,
						Version:      v.Version,
						FixedVersion: v.FixedVersion,
						References:   v.References,
					})
				}
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

			// Save baseline if requested
			if updateBaseline {
				outPath := ".raven-baseline.json"
				if baselinePath != "" {
					outPath = baselinePath
				}
				newBl := baseline.New()
				for _, f := range result.Findings {
					newBl.Records = append(newBl.Records, baseline.Record{
						RuleID:      f.RuleID,
						File:        f.File,
						Line:        f.Line,
						Column:      f.Column,
						SnippetHash: baseline.HashSnippet(f.Snippet),
						RuleName:    f.RuleName,
						Severity:    string(f.Severity),
						Snippet:     f.Snippet,
					})
				}
				if err := newBl.Save(outPath); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: could not save baseline: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "\n💾 Baseline saved to %s (%d findings)\n", outPath, newBl.Count())
				}
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
			var totalIssues int
			if bl != nil {
				totalIssues = len(result.NewFindings) + len(depVulns)
			} else {
				totalIssues = len(result.Findings) + len(depVulns)
			}
			if totalIssues > 0 {
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
	cmd.Flags().BoolVar(&depsFlag, "deps", false, "Scan dependencies for known vulnerabilities (OSV)")
	cmd.Flags().BoolVar(&secretsFlag, "secrets", false, "Deep scan for hardcoded secrets and high-entropy strings")
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "Path to baseline JSON (only report new findings)")
	cmd.Flags().BoolVar(&updateBaseline, "update-baseline", false, "Save current findings as baseline JSON")
	cmd.Flags().BoolVar(&noIgnoreComments, "no-ignore-comments", false, "Ignore inline suppression comments")

	return cmd
}
