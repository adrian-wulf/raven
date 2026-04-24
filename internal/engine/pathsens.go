package engine

import (
	"regexp"
	"strings"
)

// PathAnalyzer performs basic path-sensitive analysis
type PathAnalyzer struct{}

// NewPathAnalyzer creates a new path analyzer
func NewPathAnalyzer() *PathAnalyzer {
	return &PathAnalyzer{}
}

// HasSanitizedPath checks if at least one code path to the finding sanitizes input
func (pa *PathAnalyzer) HasSanitizedPath(content []byte, line int, lang string) bool {
	conditions := FindBranchConditions(string(content), line, lang)
	for _, cond := range conditions {
		if cond.Sanitizes {
			return true
		}
	}
	return false
}

// BranchCondition represents an if/else branch
type BranchCondition struct {
	StartLine int
	EndLine   int
	Condition string
	HasElse   bool
	Sanitizes bool
}

// FindBranchConditions finds if/else branches around the given line
func FindBranchConditions(content string, line int, lang string) []BranchCondition {
	var conditions []BranchCondition
	lines := strings.Split(content, "\n")

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		ifIf := regexp.MustCompile(`^\s*if\s*\(`)
		if ifIf.MatchString(lines[i]) {
			end := findBlockEnd(lines, i)
			sanitizes := isSanitizingBranch(lines, i, end, lang)
			conditions = append(conditions, BranchCondition{
				StartLine: i + 1,
				EndLine:   end + 1,
				Condition: trimmed,
				HasElse:   hasElseBranch(lines, i, end),
				Sanitizes: sanitizes,
			})
		}
	}

	return conditions
}

func isSanitizingBranch(lines []string, start, end int, lang string) bool {
	for i := start; i <= end && i < len(lines); i++ {
		lower := strings.ToLower(lines[i])
		if strings.Contains(lower, "sanitize") || strings.Contains(lower, "validate") ||
			strings.Contains(lower, "escape") || strings.Contains(lower, "encode") ||
			strings.Contains(lower, "purify") || strings.Contains(lower, "clean") {
			return true
		}
		if strings.Contains(lower, "return") || strings.Contains(lower, "throw") ||
			strings.Contains(lower, "continue") || strings.Contains(lower, "break") {
			return true
		}
	}
	return false
}

func hasElseBranch(lines []string, start, end int) bool {
	for i := start; i <= end && i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "else") || strings.HasPrefix(trimmed, "} else") {
			return true
		}
	}
	return false
}

func findBlockEnd(lines []string, start int) int {
	braceCount := 0
	for i := start; i < len(lines); i++ {
		braceCount += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		if braceCount <= 0 && i > start {
			return i
		}
	}
	return len(lines) - 1
}
