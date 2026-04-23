package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/raven-security/raven/internal/engine"
	"github.com/raven-security/raven/internal/version"
)

type Formatter struct {
	Format   string
	Color    bool
	ShowCode bool
}

func (f *Formatter) Print(result *engine.Result) error {
	switch f.Format {
	case "json":
		return f.printJSON(result)
	case "sarif":
		return f.printSARIF(result)
	case "html":
		return f.printHTML(result)
	case "pretty":
		return f.printPretty(result)
	default:
		return f.printPretty(result)
	}
}

func (f *Formatter) printJSON(result *engine.Result) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func (f *Formatter) printPretty(result *engine.Result) error {
	if !f.Color {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	// Header
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#6C5CE7"))
	subtitle := lipgloss.NewStyle().Foreground(lipgloss.Color("#A29BFE"))

	fmt.Println()
	fmt.Println(title.Render("🐦‍⬛ Raven Security Scan"))
	fmt.Println(subtitle.Render(fmt.Sprintf("  %d files scanned in %s", result.FilesScanned, result.Duration)))
	fmt.Println()

	if len(result.Findings) == 0 {
		green := lipgloss.NewStyle().Foreground(lipgloss.Color("#55EFC4")).Bold(true)
		fmt.Println(green.Render("✅ No security issues found!"))
		fmt.Println()
		return nil
	}

	// Severity summary
	bySev := result.BySeverity()
	sevColors := map[engine.Severity]string{
		engine.Critical: "#FF0000",
		engine.High:     "#FF6B6B",
		engine.Medium:   "#FDCB6E",
		engine.Low:      "#74B9FF",
		engine.Info:     "#A29BFE",
	}

	fmt.Println("Summary:")
	for _, sev := range []engine.Severity{engine.Critical, engine.High, engine.Medium, engine.Low, engine.Info} {
		count := len(bySev[sev])
		if count > 0 {
			color := sevColors[sev]
			style := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true)
			fmt.Printf("  %s: %d\n", style.Render(string(sev)), count)
		}
	}
	if len(result.Vulnerabilities) > 0 {
		vulnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6B6B")).Bold(true)
		fmt.Printf("  %s: %d\n", vulnStyle.Render("vulnerable deps"), len(result.Vulnerabilities))
	}
	// Baseline diff info
	if len(result.NewFindings) > 0 || len(result.BaselineFindings) > 0 {
		newStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#55EFC4")).Bold(true)
		baseStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#A29BFE"))
		_ = baseStyle
		fmt.Printf("  %s: %d new, %d baseline\n", newStyle.Render("baseline diff"), len(result.NewFindings), len(result.BaselineFindings))
	}
	fmt.Println()

	// Findings
	for _, sev := range []engine.Severity{engine.Critical, engine.High, engine.Medium, engine.Low, engine.Info} {
		findings := bySev[sev]
		if len(findings) == 0 {
			continue
		}

		color := sevColors[sev]
		sevStyle := lipgloss.NewStyle().
			Background(lipgloss.Color(color)).
			Foreground(lipgloss.Color("#FFFFFF")).
			Bold(true).
			Padding(0, 1)

		for _, finding := range findings {
			// Severity badge + rule name
			fmt.Printf("%s %s\n", sevStyle.Render(strings.ToUpper(string(finding.Severity))), finding.RuleName)

			// Location
			locStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#636E72"))
			fmt.Printf("  %s\n", locStyle.Render(fmt.Sprintf("%s:%d:%d", f.shortenPath(finding.File), finding.Line, finding.Column)))

			// Message
			msgStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#DFE6E9"))
			fmt.Printf("  %s\n", msgStyle.Render(f.wrapText(finding.Message, 70)))

			// Code snippet
			if f.ShowCode && finding.Snippet != "" {
				codeStyle := lipgloss.NewStyle().
					Background(lipgloss.Color("#2D3436")).
					Foreground(lipgloss.Color("#DFE6E9")).
					Padding(0, 1).
					MarginLeft(2)
				fmt.Printf("  %s\n", codeStyle.Render(f.truncateSnippet(finding.Snippet)))
			}

			// Fix hint
			if finding.FixAvailable {
				fixStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#55EFC4"))
				fmt.Printf("  %s\n", fixStyle.Render("💡 Fix available: raven fix"))
			}

			fmt.Println()
		}
	}

	// Dependency vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		vulnTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6B6B"))
		fmt.Println(vulnTitle.Render("Vulnerable Dependencies:"))
		for _, v := range result.Vulnerabilities {
			fixed := v.FixedVersion
			if fixed == "" {
				fixed = "unknown"
			}
			fmt.Printf("  %s: %s@%s → %s\n", v.ID, v.Package, v.Version, fixed)
			if v.Summary != "" {
				sumStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#DFE6E9"))
				fmt.Printf("    %s\n", sumStyle.Render(v.Summary))
			}
		}
		fmt.Println()
	}

	return nil
}

func (f *Formatter) printSARIF(result *engine.Result) error {
	// Minimal SARIF v2.1.0
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":            "Raven",
						"version":         version.Version,
						"informationUri":  "https://github.com/raven-security/raven",
					},
				},
				"results": f.toSARIFResults(result),
			},
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}

func (f *Formatter) toSARIFResults(result *engine.Result) []map[string]interface{} {
	var results []map[string]interface{}

	for _, finding := range result.Findings {
		results = append(results, map[string]interface{}{
			"ruleId":  finding.RuleID,
			"message": map[string]interface{}{"text": finding.Message},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{"uri": finding.File},
						"region": map[string]interface{}{
							"startLine":   finding.Line,
							"startColumn": finding.Column,
						},
					},
				},
			},
			"level": f.severityToSARIF(finding.Severity),
		})
	}

	return results
}

func (f *Formatter) severityToSARIF(sev engine.Severity) string {
	switch sev {
	case engine.Critical, engine.High:
		return "error"
	case engine.Medium:
		return "warning"
	default:
		return "note"
	}
}

func (f *Formatter) shortenPath(path string) string {
	wd, _ := os.Getwd()
	rel, err := filepath.Rel(wd, path)
	if err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return path
}

func (f *Formatter) wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}

	var result strings.Builder
	words := strings.Fields(text)
	lineLen := 0

	for i, word := range words {
		if i > 0 && lineLen+len(word)+1 > width {
			result.WriteString("\n  ")
			lineLen = 0
		} else if i > 0 {
			result.WriteString(" ")
			lineLen++
		}
		result.WriteString(word)
		lineLen += len(word)
	}

	return result.String()
}

func (f *Formatter) truncateSnippet(snippet string) string {
	lines := strings.Split(snippet, "\n")
	if len(lines) > 3 {
		return strings.Join(lines[:3], "\n") + "..."
	}
	return snippet
}
