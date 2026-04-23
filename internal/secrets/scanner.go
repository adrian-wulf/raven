package secrets

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
)

// Finding represents a detected secret.
type Finding struct {
	RuleID   string
	RuleName string
	Severity string
	File     string
	Line     int
	Column   int
	Snippet  string
	Match    string // the actual secret value
	Type     string // e.g. "api_key", "token", "high_entropy"
}

// Detector scans files for hardcoded secrets and high-entropy strings.
type Detector struct {
	entropyThreshold float64
	minLength        int
	maxLength        int
}

// NewDetector creates a secret detector with sensible defaults.
func NewDetector() *Detector {
	return &Detector{
		entropyThreshold: 4.2,
		minLength:        16,
		maxLength:        128,
	}
}

// Detect scans a single file for secrets.
func (d *Detector) Detect(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Pattern-based detection
		for _, p := range secretPatterns {
			for _, m := range p.findMatches(line, lineNum, path) {
				findings = append(findings, m)
			}
		}

		// Entropy-based detection for strings that look like secrets
		for _, match := range d.findHighEntropyStrings(line, lineNum, path) {
			findings = append(findings, match)
		}
	}

	return findings, scanner.Err()
}

// secretPattern defines a regex-based secret detector.
type secretPattern struct {
	Name    string
	Regex   *regexp.Regexp
	Severity string
	Type    string
}

var secretPatterns = []secretPattern{
	{
		Name:     "AWS Access Key ID",
		Regex:    regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		Severity: "critical",
		Type:     "aws_key",
	},
	{
		Name:     "AWS Secret Access Key",
		Regex:    regexp.MustCompile(`(?i)['"\s][0-9a-zA-Z/+]{40}['"\s]`),
		Severity: "critical",
		Type:     "aws_secret",
	},
	{
		Name:     "Generic API Key",
		Regex:    regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"\s]?([a-zA-Z0-9_\-]{16,})['"\s]?`),
		Severity: "high",
		Type:     "api_key",
	},
	{
		Name:     "Private Key",
		Regex:    regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Severity: "critical",
		Type:     "private_key",
	},
	{
		Name:     "GitHub Token",
		Regex:    regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`),
		Severity: "critical",
		Type:     "github_token",
	},
	{
		Name:     "Slack Token",
		Regex:    regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}([a-zA-Z0-9-]*)?`),
		Severity: "high",
		Type:     "slack_token",
	},
	{
		Name:     "JWT Token",
		Regex:    regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
		Severity: "high",
		Type:     "jwt",
	},
	{
		Name:     "Password in Code",
		Regex:    regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"\s]?([^'"\s]{8,})['"\s]?`),
		Severity: "high",
		Type:     "password",
	},
	{
		Name:     "Database Connection String",
		Regex:    regexp.MustCompile(`(?i)(mongodb|postgres|mysql)://[^:]+:[^@]+@`),
		Severity: "critical",
		Type:     "db_connection",
	},
}

func (p secretPattern) findMatches(line string, lineNum int, path string) []Finding {
	var findings []Finding
	matches := p.Regex.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		value := m[0]
		// Use last captured group as the actual value if available
		if len(m) > 1 && m[len(m)-1] != "" {
			value = m[len(m)-1]
		}
		if isExcludedValue(value) {
			continue
		}
		findings = append(findings, Finding{
			RuleID:   "raven-secret-" + p.Type,
			RuleName: p.Name,
			Severity: p.Severity,
			File:     path,
			Line:     lineNum,
			Column:   strings.Index(line, m[0]) + 1,
			Snippet:  strings.TrimSpace(line),
			Match:    value,
			Type:     p.Type,
		})
	}
	return findings
}

func (d *Detector) findHighEntropyStrings(line string, lineNum int, path string) []Finding {
	var findings []Finding

	// Look for quoted strings and assignment values
	re := regexp.MustCompile(`["']([a-zA-Z0-9!@#$%^&*+/=_\-]{16,})["']`)
	matches := re.FindAllStringSubmatchIndex(line, -1)

	for _, m := range matches {
		value := line[m[2]:m[3]]
		if len(value) < d.minLength || len(value) > d.maxLength {
			continue
		}
		if isExcludedValue(value) {
			continue
		}
		entropy := shannonEntropy(value)
		if entropy < d.entropyThreshold {
			continue
		}
		// Skip if already matched by a specific pattern
		alreadyFound := false
		for _, p := range secretPatterns {
			if p.Regex.MatchString(value) {
				alreadyFound = true
				break
			}
		}
		if alreadyFound {
			continue
		}

		findings = append(findings, Finding{
			RuleID:   "raven-secret-entropy",
			RuleName: "High-Entropy String (Possible Secret)",
			Severity: "medium",
			File:     path,
			Line:     lineNum,
			Column:   m[2] + 1,
			Snippet:  strings.TrimSpace(line),
			Match:    value,
			Type:     "high_entropy",
		})
	}

	return findings
}

// shannonEntropy calculates the entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isExcludedValue checks if a string is a known test/dummy value.
func isExcludedValue(s string) bool {
	lower := strings.ToLower(s)
	exclusions := []string{
		"your_key_here", "my_api_key", "sample_key", "dummy_",
		"password123", "abc123", "changeme",
		// raven-ignore-next-line: raven-gen-creds-001
		"default_password",
		"test_key", "test_secret", "test_token",
	}
	for _, ex := range exclusions {
		if lower == ex || strings.HasPrefix(lower, ex) || strings.HasSuffix(lower, ex) {
			return true
		}
	}
	return false
}
