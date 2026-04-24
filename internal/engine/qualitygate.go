package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// QualityGateConfig defines quality gate thresholds
type QualityGateConfig struct {
	MaxCritical      int                `yaml:"max_critical"`
	MaxHigh          int                `yaml:"max_high"`
	MaxMedium        int                `yaml:"max_medium"`
	MaxLow           int                `yaml:"max_low"`
	MaxTotal         int                `yaml:"max_total"`
	MaxSecrets       int                `yaml:"max_secrets"`
	FailOnNewSecrets bool               `yaml:"fail_on_new_secrets"`
	NewCode          NewCodeGate        `yaml:"new_code"`
	IgnorePatterns   []IgnorePattern    `yaml:"ignore_patterns"`
	RequireCWE       bool               `yaml:"require_cwe_mapping"`
	MinConfidence    float64            `yaml:"min_confidence"`
}

// NewCodeGate defines stricter thresholds for new code
type NewCodeGate struct {
	MaxCritical      int  `yaml:"max_critical"`
	MaxHigh          int  `yaml:"max_high"`
	MaxTotal         int  `yaml:"max_total"`
	FailOnNewSecrets bool `yaml:"fail_on_new_secrets"`
}

// IgnorePattern defines path-based rule exclusions (like Gosec)
type IgnorePattern struct {
	Path    string   `yaml:"path"`
	Rules   []string `yaml:"rules"`
	Reason  string   `yaml:"reason"`
}

// QualityGateResult is the result of quality gate evaluation
type QualityGateResult struct {
	Passed   bool     `json:"passed"`
	Violations []string `json:"violations"`
	Summary  GateSummary `json:"summary"`
}

// GateSummary contains counts per severity
type GateSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
	Secrets  int `json:"secrets"`
}

// QualityGateEvaluator evaluates findings against quality gates
type QualityGateEvaluator struct {
	config *QualityGateConfig
}

// NewQualityGateEvaluator creates evaluator from config file or defaults
func NewQualityGateEvaluator(configPath string) (*QualityGateEvaluator, error) {
	config := &QualityGateConfig{
		MaxCritical:   0,
		MaxHigh:       0,
		MaxMedium:     10,
		MaxLow:        50,
		MaxTotal:      100,
		MinConfidence: 0.0,
		NewCode: NewCodeGate{
			MaxCritical:      0,
			MaxHigh:          0,
			MaxTotal:         5,
			FailOnNewSecrets: true,
		},
	}

	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			data, err := os.ReadFile(configPath)
			if err != nil {
				return nil, err
			}
			if err := yaml.Unmarshal(data, config); err != nil {
				return nil, fmt.Errorf("invalid quality gate config: %w", err)
			}
		}
	}

	// Also check for .raven-policy.yaml
	if _, err := os.Stat(".raven-policy.yaml"); err == nil {
		data, err := os.ReadFile(".raven-policy.yaml")
		if err == nil {
			_ = yaml.Unmarshal(data, config)
		}
	}

	return &QualityGateEvaluator{config: config}, nil
}

// Evaluate checks findings against quality gates
func (qe *QualityGateEvaluator) Evaluate(findings []Finding) *QualityGateResult {
	result := &QualityGateResult{Passed: true}
	summary := GateSummary{}

	// Apply ignore patterns first
	filtered := qe.applyIgnorePatterns(findings)

	// Apply confidence filter
	if qe.config.MinConfidence > 0 {
		var confFiltered []Finding
		for _, f := range filtered {
			if f.ConfidenceScore >= qe.config.MinConfidence {
				confFiltered = append(confFiltered, f)
			}
		}
		filtered = confFiltered
	}

	// Count by severity
	for _, f := range filtered {
		summary.Total++
		switch f.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
		if f.Category == "secrets" || f.Category == "hardcoded-secrets" {
			summary.Secrets++
		}
	}

	// Check thresholds
	if qe.config.MaxCritical >= 0 && summary.Critical > qe.config.MaxCritical {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Critical findings: %d (max: %d)", summary.Critical, qe.config.MaxCritical))
		result.Passed = false
	}
	if qe.config.MaxHigh >= 0 && summary.High > qe.config.MaxHigh {
		result.Violations = append(result.Violations,
			fmt.Sprintf("High findings: %d (max: %d)", summary.High, qe.config.MaxHigh))
		result.Passed = false
	}
	if qe.config.MaxMedium >= 0 && summary.Medium > qe.config.MaxMedium {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Medium findings: %d (max: %d)", summary.Medium, qe.config.MaxMedium))
		result.Passed = false
	}
	if qe.config.MaxLow >= 0 && summary.Low > qe.config.MaxLow {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Low findings: %d (max: %d)", summary.Low, qe.config.MaxLow))
		result.Passed = false
	}
	if qe.config.MaxTotal >= 0 && summary.Total > qe.config.MaxTotal {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Total findings: %d (max: %d)", summary.Total, qe.config.MaxTotal))
		result.Passed = false
	}
	if qe.config.MaxSecrets >= 0 && summary.Secrets > qe.config.MaxSecrets {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Secret findings: %d (max: %d)", summary.Secrets, qe.config.MaxSecrets))
		result.Passed = false
	}
	if qe.config.FailOnNewSecrets && summary.Secrets > 0 {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Secrets detected: %d (zero tolerance policy)", summary.Secrets))
		result.Passed = false
	}

	result.Summary = summary
	return result
}

// applyIgnorePatterns filters findings based on ignore patterns
func (qe *QualityGateEvaluator) applyIgnorePatterns(findings []Finding) []Finding {
	if len(qe.config.IgnorePatterns) == 0 {
		return findings
	}

	var filtered []Finding
	for _, f := range findings {
		ignored := false
		for _, pattern := range qe.config.IgnorePatterns {
			matched, _ := filepath.Match(pattern.Path, f.File)
			if matched {
				// Check if rule matches
				for _, rule := range pattern.Rules {
					if rule == "*" || rule == f.RuleID || rule == string(f.Category) {
						ignored = true
						break
					}
				}
			}
			if ignored {
				break
			}
		}
		if !ignored {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// DefaultQualityGateConfig returns a default quality gate configuration
func DefaultQualityGateConfig() string {
	return `# Raven Quality Gate Configuration
# Place as .raven-policy.yaml in project root

# Maximum allowed findings per severity (use -1 to disable)
max_critical: 0
max_high: 0
max_medium: 10
max_low: 50
max_total: 100
max_secrets: 0

# Zero tolerance for secrets
fail_on_new_secrets: true

# New code thresholds (for PR scans)
new_code:
  max_critical: 0
  max_high: 0
  max_total: 5
  fail_on_new_secrets: true

# Path-based rule exclusions (Gosec-style)
ignore_patterns:
  - path: "*_test.go"
    rules: ["*"]
    reason: "Test files"
  - path: "vendor/**"
    rules: ["*"]
    reason: "Third-party code"
  - path: "**/*_test.py"
    rules: ["*"]
    reason: "Python test files"
  - path: "migrations/**"
    rules: ["sqli"]
    reason: "Database migrations use raw SQL by design"
  - path: "fixtures/**"
    rules: ["secrets"]
    reason: "Test fixtures with dummy data"

# Minimum confidence score (0.0-1.0)
min_confidence: 0.0

# Require CWE mapping for all findings
require_cwe: false
`
}
