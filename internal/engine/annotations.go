package engine

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// RavenIgnore represents a parsed #raven-ignore annotation
type RavenIgnore struct {
	RuleIDs   []string // specific rule IDs to ignore
	CWEs      []string // CWE numbers to ignore
	Categories []string // category names to ignore
	Justification string // reason for ignoring
	LineStart int      // start line of block ignore (0 for single line)
	LineEnd   int      // end line of block ignore (0 for single line)
	AllRules  bool     // ignore all rules (*)
}

// AnnotationParser parses #raven-ignore comments from source files
type AnnotationParser struct {
	commentStyles map[string]string // language -> comment prefix
}

// NewAnnotationParser creates a new annotation parser
func NewAnnotationParser() *AnnotationParser {
	return &AnnotationParser{
		commentStyles: map[string]string{
			"go":         "//",
			"javascript": "//",
			"typescript": "//",
			"python":     "#",
			"java":       "//",
			"php":        "//",
			"ruby":       "#",
			"csharp":     "//",
			"rust":       "//",
			"kotlin":     "//",
			"swift":      "//",
			"c":          "//",
			"cpp":        "//",
			"dart":       "//",
			"elixir":     "#",
			"scala":      "//",
			"lua":        "--",
			"solidity":   "//",
			"bash":       "#",
			"dockerfile": "#",
			"terraform":  "#",
			"yaml":       "#",
		},
	}
}

// ParseFile extracts all #raven-ignore annotations from a file
func (ap *AnnotationParser) ParseFile(filepath string, language string) ([]RavenIgnore, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	commentPrefix := ap.commentStyles[language]
	if commentPrefix == "" {
		commentPrefix = "//" // default
	}

	var annotations []RavenIgnore
	scanner := bufio.NewScanner(file)
	lineNum := 0
	var blockIgnore *RavenIgnore

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Check for block end
		if blockIgnore != nil {
			if strings.Contains(trimmed, commentPrefix+" #raven-ignore-end") {
				blockIgnore.LineEnd = lineNum
				annotations = append(annotations, *blockIgnore)
				blockIgnore = nil
			}
			continue
		}

		// Check for block start
		if strings.Contains(trimmed, commentPrefix+" #raven-ignore-begin") {
			parsed := ap.parseAnnotationLine(trimmed, commentPrefix)
			parsed.LineStart = lineNum
			blockIgnore = &parsed
			continue
		}

		// Check for single-line ignore
		if strings.Contains(trimmed, commentPrefix+" #raven-ignore") {
			parsed := ap.parseAnnotationLine(trimmed, commentPrefix)
			parsed.LineStart = lineNum
			parsed.LineEnd = lineNum
			annotations = append(annotations, parsed)
		}
	}

	return annotations, scanner.Err()
}

// parseAnnotationLine parses a single #raven-ignore comment line
func (ap *AnnotationParser) parseAnnotationLine(line, commentPrefix string) RavenIgnore {
	rg := RavenIgnore{}

	// Extract content after #raven-ignore
	idx := strings.Index(line, "#raven-ignore")
	if idx == -1 {
		return rg
	}

	content := strings.TrimSpace(line[idx+len("#raven-ignore"):])

	// Remove -begin or -end suffix
	content = strings.TrimPrefix(content, "-begin")
	content = strings.TrimPrefix(content, "-end")
	content = strings.TrimSpace(content)

	// Split on -- for justification
	parts := strings.SplitN(content, "--", 2)
	targetPart := strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		rg.Justification = strings.TrimSpace(parts[1])
	}

	// Parse target identifiers
	if targetPart == "" || targetPart == "*" {
		rg.AllRules = true
		return rg
	}

	items := strings.Fields(targetPart)
	for _, item := range items {
		item = strings.TrimSpace(item)
		switch {
		case strings.HasPrefix(item, "CWE-"):
			rg.CWEs = append(rg.CWEs, item)
		case strings.HasPrefix(item, "cwe-"):
			rg.CWEs = append(rg.CWEs, strings.ToUpper(item))
		case item == "*":
			rg.AllRules = true
		default:
			rg.RuleIDs = append(rg.RuleIDs, item)
			rg.Categories = append(rg.Categories, item)
		}
	}

	return rg
}

// ShouldIgnore checks if a finding should be ignored based on annotations
func (rg *RavenIgnore) ShouldIgnore(finding Finding) bool {
	if rg.AllRules {
		return true
	}

	// Check rule ID
	for _, id := range rg.RuleIDs {
		if id == finding.RuleID {
			return true
		}
	}

	// Check CWE
	for _, cwe := range rg.CWEs {
		if cwe == finding.CWE {
			return true
		}
	}

	// Check category
	for _, cat := range rg.Categories {
		if strings.EqualFold(cat, string(finding.Category)) {
			return true
		}
	}

	return false
}

// IsInRange checks if a line number is within the ignore range
func (rg *RavenIgnore) IsInRange(line int) bool {
	return line >= rg.LineStart && line <= rg.LineEnd
}

// FilterFindings removes findings that have matching #raven-ignore annotations
func FilterFindings(findings []Finding, annotations map[string][]RavenIgnore) []Finding {
	var filtered []Finding
	for _, f := range findings {
		ignored := false
		if fileAnnotations, ok := annotations[f.File]; ok {
			for _, ann := range fileAnnotations {
				if ann.IsInRange(f.Line) && ann.ShouldIgnore(f) {
					ignored = true
					break
				}
			}
		}
		if !ignored {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GenerateIgnoreFile creates a template .raven-ignore file
func GenerateIgnoreFile(findings []Finding) string {
	var sb strings.Builder
	sb.WriteString("# Raven Ignore File\n")
	sb.WriteString("# Format: <file-path>:<line>:<rule-id> -- <justification>\n\n")

	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("%s:%d:%s -- ", f.File, f.Line, f.RuleID))
		sb.WriteString(fmt.Sprintf("Ignore %s: %s\n", f.RuleName, f.Message))
	}

	return sb.String()
}
