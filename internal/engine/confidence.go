package engine

import (
	"regexp"
	"strings"
)

// ScoreConfidence calculates a confidence score (0.0-1.0) for a finding
func ScoreConfidence(finding Finding, content []byte, patternType string) float64 {
	score := 0.5

	// Pattern specificity
	switch patternType {
	case "taint":
		score += 0.45
	case "ast-query":
		score += 0.3
	case "regex":
		score += 0.1
	case "literal":
		score += 0.0
	}

	// Context depth
	contextScore := calculateContextDepth(content, finding.Line)
	score += contextScore * 0.1

	// Sink sensitivity
	sinkScore := calculateSinkSensitivity(string(finding.Category), finding.Snippet)
	score += sinkScore * 0.15

	// Validation scope
	if isInValidatedScope(string(content), finding.Line) {
		score -= 0.2 // Penalty for findings in validated code
	}

	// Test file penalty
	if strings.Contains(finding.File, "_test.") || strings.Contains(finding.File, "_spec.") {
		score -= 0.15
	}

	return clamp(score, 0.0, 1.0)
}

func calculateContextDepth(content []byte, line int) float64 {
	lines := strings.Split(string(content), "\n")
	if line < 1 || line > len(lines) {
		return 0
	}
	idx := line - 1
	depth := 0
	for i := max(0, idx-10); i < min(len(lines), idx+10); i++ {
		l := strings.TrimSpace(lines[i])
		if strings.Contains(l, "if ") && strings.Contains(l, "!= nil") {
			depth++
		}
		if strings.Contains(l, "if ") && (strings.Contains(l, "err ") || strings.Contains(l, "error")) {
			depth++
		}
		if strings.Contains(l, "validate") || strings.Contains(l, "Validate") {
			depth++
		}
		if strings.Contains(l, "check") || strings.Contains(l, "Check") {
			depth++
		}
		if strings.Contains(l, "guard") || strings.Contains(l, "Guard") {
			depth++
		}
	}
	return float64(depth) / 20.0
}

func calculateSinkSensitivity(category string, snippet string) float64 {
	switch category {
	case "sqli":
		if strings.Contains(snippet, "+") || strings.Contains(snippet, "${") {
			return 1.0
		}
		return 0.8
	case "xss":
		if strings.Contains(snippet, "innerHTML") || strings.Contains(snippet, "dangerouslySetInnerHTML") {
			return 1.0
		}
		return 0.7
	case "cmdi":
		return 0.9
	case "ssrf":
		return 0.8
	case "pathtraversal":
		return 0.7
	case "crypto":
		return 0.6
	default:
		return 0.5
	}
}

func isInValidatedScope(content string, line int) bool {
	lines := strings.Split(content, "\n")
	if line < 1 || line > len(lines) {
		return false
	}
	idx := line - 1
	validationPatterns := []string{
		`validated`, `sanitized`, `escaped`, `encoded`, `purified`,
		`DOMPurify`, `htmlspecialchars`, `encodeURIComponent`,
		`validator`, `joi\.`, `yup\.`, `zod\.`,
	}
	for i := max(0, idx-5); i <= idx; i++ {
		lower := strings.ToLower(lines[i])
		for _, p := range validationPatterns {
			matched, _ := regexp.MatchString(p, lower)
			if matched {
				return true
			}
		}
	}
	return false
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
