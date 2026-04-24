package llm

import (
	"fmt"
	"regexp"
	"strings"
)

// FixValidator validates AI-generated fixes for correctness and security
type FixValidator struct{}

// NewFixValidator creates a new fix validator
func NewFixValidator() *FixValidator {
	return &FixValidator{}
}

// ValidationResult contains the result of fix validation
type ValidationResult struct {
	Valid            bool     `json:"valid"`
	Issues           []string `json:"issues,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	SyntaxOK         bool     `json:"syntax_ok"`
	VulnFixed        bool     `json:"vuln_fixed"`
	NoNewVulns       bool     `json:"no_new_vulns"`
	FunctionalityOK  bool     `json:"functionality_ok"`
}

// Validate checks an AI-generated fix for common issues
func (fv *FixValidator) Validate(originalCode, fixedCode, vulnType, language string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Check 1: Fix is not empty
	if strings.TrimSpace(fixedCode) == "" {
		result.Issues = append(result.Issues, "Fixed code is empty")
		result.Valid = false
	}

	// Check 2: Fix is different from original
	if strings.TrimSpace(originalCode) == strings.TrimSpace(fixedCode) {
		result.Issues = append(result.Issues, "Fixed code is identical to original")
		result.Valid = false
	}

	// Check 3: Basic syntax validation per language
	result.SyntaxOK = fv.checkSyntax(fixedCode, language)
	if !result.SyntaxOK {
		result.Warnings = append(result.Warnings, "Syntax validation inconclusive (may be a partial fix)")
	}

	// Check 4: Vulnerability-specific checks
	result.VulnFixed = fv.checkVulnerabilityFixed(fixedCode, vulnType, language)
	if !result.VulnFixed {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Vulnerability pattern (%s) may still be present in fix", vulnType))
	}

	// Check 5: No new obvious vulnerabilities introduced
	result.NoNewVulns = !fv.hasObviousNewVulnerability(fixedCode, language)
	if !result.NoNewVulns {
		result.Warnings = append(result.Warnings, "Fix may introduce new security issues")
	}

	// Check 6: Functionality preservation (basic heuristics)
	result.FunctionalityOK = fv.checkFunctionalityPreserved(originalCode, fixedCode, language)

	result.Valid = len(result.Issues) == 0 && result.VulnFixed && result.NoNewVulns
	return result
}

// checkSyntax performs basic syntax validation
func (fv *FixValidator) checkSyntax(code, language string) bool {
	// Check balanced braces
	braceCount := 0
	parenCount := 0
	inString := false
	var stringChar rune

	for _, ch := range code {
		switch ch {
		case '"', '\'', '`':
			if !inString {
				inString = true
				stringChar = ch
			} else if ch == stringChar {
				inString = false
			}
		case '{':
			if !inString { braceCount++ }
		case '}':
			if !inString { braceCount-- }
		case '(':
			if !inString { parenCount++ }
		case ')':
			if !inString { parenCount-- }
		}
	}

	return braceCount == 0 && parenCount == 0
}

// checkVulnerabilityFixed checks if the vulnerability pattern is still present
func (fv *FixValidator) checkVulnerabilityFixed(code, vulnType, language string) bool {
	codeLower := strings.ToLower(code)

	switch strings.ToLower(vulnType) {
	case "sqli", "sql-injection":
		// Check if string concatenation in SQL is still present
		dangerousPatterns := []string{
			`"select *`, `"insert into`, `"update `, `"delete from`, `"drop `,
			`" + `, `+ "`, `fmt.Sprintf`, `String.format`, `f"SELECT`, `f"select`,
		}
		for _, p := range dangerousPatterns {
			if strings.Contains(codeLower, strings.ToLower(p)) {
				// But parameterized queries are OK
				if strings.Contains(codeLower, "?") || strings.Contains(codeLower, "$1") ||
					strings.Contains(codeLower, "@p") || strings.Contains(codeLower, "%s") {
					// Check if %s is inside a format string with parameters
					continue
				}
				return false
			}
		}
		return true

	case "xss":
		dangerousPatterns := []string{
			`innerHTML`, `outerHTML`, `document.write(`, `.write(`,
			`dangerouslySetInnerHTML`, `eval(`, `Function(`,
		}
		for _, p := range dangerousPatterns {
			if strings.Contains(codeLower, strings.ToLower(p)) {
				return false
			}
		}
		return true

	case "cmdi", "command-injection":
		dangerousPatterns := []string{
			`shell=True`, `shell=true`, `shell = True`, `shell = true`,
			`os.system(`, `subprocess.call(`, `"sh", "-c"`, `"/bin/sh"`,
			`Runtime.getRuntime().exec(`, `ProcessBuilder(`,
		}
		for _, p := range dangerousPatterns {
			if strings.Contains(codeLower, strings.ToLower(p)) {
				return false
			}
		}
		return true

	case "secrets", "hardcoded-secrets":
		secretPatterns := regexp.MustCompile(`(?i)(password|secret|token|key|api_key)\s*=\s*["'][^"']{8,}["']`)
		return !secretPatterns.MatchString(code)

	default:
		return true // Unknown vuln type, assume OK
	}
}

// hasObviousNewVulnerability checks if the fix introduces obvious new vulns
func (fv *FixValidator) hasObviousNewVulnerability(code, language string) bool {
	codeLower := strings.ToLower(code)

	// Check for TODO/FIXME security comments
	if regexp.MustCompile(`(?i)(TODO|FIXME|HACK).*(security|vuln|insecure)`).MatchString(code) {
		return true
	}

	// Check for disabling security
	securityDisabling := []string{
		`insecureskipverify`, `verify = false`, `verify=False`,
		`ssl = false`, `tls_verify = false`, `validate = false`,
		`check_hostname = false`, `verify_ssl = false`,
	}
	for _, p := range securityDisabling {
		if strings.Contains(codeLower, p) {
			return true
		}
	}

	return false
}

// checkFunctionalityPreserved checks if the fix likely preserves functionality
func (fv *FixValidator) checkFunctionalityPreserved(original, fixed, language string) bool {
	// Extract function/method names from original
	funcPattern := regexp.MustCompile(`\b\w+\s*\(`)
	originalFuncs := funcPattern.FindAllString(original, -1)
	fixedFuncs := funcPattern.FindAllString(fixed, -1)

	// Check that key function calls are preserved
	 preservedCount := 0
	for _, fn := range originalFuncs {
		for _, ff := range fixedFuncs {
			if fn == ff {
				preservedCount++
				break
			}
		}
	}

	if len(originalFuncs) > 0 && preservedCount == 0 {
		return false // All function calls changed, might break functionality
	}

	return true
}
