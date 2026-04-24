package engine

import (
	"regexp"
	"strings"
)

// FalsePositivePatterns per vulnerability class
var FalsePositivePatterns = map[string][]string{
	"secrets": {
		`test_key`, `example_key`, `dummy_key`, `fake_key`,
		`YOUR_KEY_HERE`, `INSERT_KEY_HERE`, `xxx`, `\*\*\*`,
		`password123`, `admin123`, `test123`, `changeme`,
	},
	"sqli": {
		`// test query`, `SELECT 1`, `SELECT count\(\*\)`,
		`DESCRIBE `, `EXPLAIN `, `SHOW TABLES`,
		`DROP TABLE IF EXISTS`, `CREATE TABLE IF NOT EXISTS`,
	},
	"xss": {
		`// intentionally`, `// demonstration`, `// example`,
		`document.createTextNode`, `textContent`, `innerText`,
		`// This is safe because`,
	},
	"crypto": {
		`// legacy support`, `// backward compatibility`,
		`// For testing only`, `// TODO.*crypto`,
	},
}

// FalsePositiveFilter uses multiple heuristics to score FP likelihood
type FalsePositiveFilter struct {
	threshold float64
}

// NewFalsePositiveFilter creates filter with given threshold (default 0.85)
func NewFalsePositiveFilter(threshold float64) *FalsePositiveFilter {
	if threshold <= 0 {
		threshold = 0.85
	}
	return &FalsePositiveFilter{threshold: threshold}
}

// ScoreFalsePositive calculates FP likelihood score (0.0-1.0)
// Returns: (score, shouldSuppress)
func (fpf *FalsePositiveFilter) ScoreFalsePositive(finding Finding, content []byte) (float64, bool) {
	var score float64

	score += isInTestContext(finding) * 0.30
	score += hasSafeVariableNames(finding) * 0.15
	score += hasValidationCheck(string(content), finding) * 0.15
	score += isCommonFalsePositivePattern(finding) * 0.20
	score += isInDocumentation(finding, string(content)) * 0.10
	score += isHardcodedSafeValue(finding) * 0.10
	score += hasSanitizationNearby(string(content), finding) * 0.10

	return score, score > fpf.threshold
}

func isInTestContext(finding Finding) float64 {
	lower := strings.ToLower(finding.File)
	if strings.Contains(lower, "_test.") || strings.Contains(lower, "_spec.") ||
		strings.Contains(lower, "/test/") || strings.Contains(lower, "/tests/") ||
		strings.Contains(lower, "/spec/") || strings.Contains(lower, "test_") {
		return 1.0
	}
	snippet := strings.ToLower(finding.Snippet)
	if strings.Contains(snippet, "test") && strings.Contains(snippet, "only") {
		return 0.5
	}
	return 0
}

func hasSafeVariableNames(finding Finding) float64 {
	safePrefixes := []string{"sanitized_", "safe_", "escaped_", "encoded_", "clean_", "validated_", "filtered_", "trusted_", "whitelist_"}
	snippet := strings.ToLower(finding.Snippet)
	for _, prefix := range safePrefixes {
		if strings.Contains(snippet, prefix) {
			return 1.0
		}
	}
	return 0
}

func hasValidationCheck(content string, finding Finding) float64 {
	lines := strings.Split(content, "\n")
	if finding.Line < 1 || finding.Line > len(lines) {
		return 0
	}
	idx := finding.Line - 1
	for i := max(0, idx-5); i <= idx; i++ {
		lower := strings.ToLower(lines[i])
		if strings.Contains(lower, "validate") || strings.Contains(lower, "sanitize") ||
			strings.Contains(lower, "escape") || strings.Contains(lower, "encode") ||
			strings.Contains(lower, "check") || strings.Contains(lower, "verify") ||
			strings.Contains(lower, "guard") || strings.Contains(lower, "assert") {
			return float64(6-(idx-i)) / 6.0
		}
	}
	return 0
}

func isCommonFalsePositivePattern(finding Finding) float64 {
	patterns := FalsePositivePatterns[finding.Category]
	if patterns == nil {
		patterns = FalsePositivePatterns["secrets"]
	}
	snippet := strings.ToLower(finding.Snippet)
	for _, p := range patterns {
		if strings.Contains(snippet, p) {
			return 1.0
		}
		re := regexp.MustCompile(p)
		if re.MatchString(snippet) {
			return 1.0
		}
	}
	return 0
}

func isInDocumentation(finding Finding, content string) float64 {
	lines := strings.Split(content, "\n")
	if finding.Line < 1 || finding.Line > len(lines) {
		return 0
	}
	line := lines[finding.Line-1]
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, `"""`) || strings.HasPrefix(trimmed, "'") {
		return 1.0
	}
	return 0
}

func isHardcodedSafeValue(finding Finding) float64 {
	safeValues := []string{
		`example.com`, `localhost`, `127.0.0.1`, `0.0.0.0`,
		`test@example.com`, `admin@example.com`,
		`/dev/null`, `/tmp/test`, `/tmp/`,
		`password123`, `admin`, `test`, `123456`, `changeme`,
		`public`, `readonly`, `static`,
	}
	snippet := strings.ToLower(finding.Snippet)
	for _, sv := range safeValues {
		if strings.Contains(snippet, sv) {
			return 1.0
		}
	}
	return 0
}

func hasSanitizationNearby(content string, finding Finding) float64 {
	lines := strings.Split(content, "\n")
	if finding.Line < 1 || finding.Line > len(lines) {
		return 0
	}
	idx := finding.Line - 1
	for i := max(0, idx-5); i <= min(len(lines)-1, idx+5); i++ {
		lower := strings.ToLower(lines[i])
		if strings.Contains(lower, "sanitize") || strings.Contains(lower, "escape") ||
			strings.Contains(lower, "encode") || strings.Contains(lower, "purify") ||
			strings.Contains(lower, "clean") || strings.Contains(lower, "strip") ||
			strings.Contains(lower, "validate") || strings.Contains(lower, "verify") {
			return float64(6-(idx-i)) / 6.0
		}
	}
	return 0
}
