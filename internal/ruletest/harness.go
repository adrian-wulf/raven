// Package ruletest provides a test harness for validating individual Raven rules
// against positive (vulnerable) and negative (safe) code fixtures.
package ruletest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raven-security/raven/internal/engine"
	"gopkg.in/yaml.v3"
)

// Fixture represents a single test case for a rule.
type Fixture struct {
	Name           string   `yaml:"name"`
	Source         string   `yaml:"source"`
	Language       string   `yaml:"language"`
	Frameworks     []string `yaml:"frameworks,omitempty"`
	ExpectFindings int      `yaml:"expect_findings"`
}

// RuleFixture represents a collection of fixtures for a single rule.
type RuleFixture struct {
	RuleID   string    `yaml:"rule_id"`
	Positive []Fixture `yaml:"positive,omitempty"`
	Negative []Fixture `yaml:"negative,omitempty"`
}

// RunRuleTest validates a single rule against its fixtures.
func RunRuleTest(t *testing.T, rulePath string, fixtures *RuleFixture) {
	if fixtures == nil {
		t.Skip("no fixtures provided")
	}

	rule, err := LoadRule(rulePath)
	if err != nil {
		t.Fatalf("loading rule %s: %v", rulePath, err)
	}

	for _, f := range fixtures.Positive {
		t.Run("positive/"+f.Name, func(t *testing.T) {
			findings := runFixture(t, rule, &f)
			if len(findings) == 0 {
				t.Errorf("expected at least 1 finding, got 0")
			}
			if f.ExpectFindings > 0 && len(findings) != f.ExpectFindings {
				t.Errorf("expected %d findings, got %d", f.ExpectFindings, len(findings))
			}
			for _, finding := range findings {
				if finding.RuleID != rule.ID {
					t.Errorf("finding has wrong rule_id: got %q, want %q", finding.RuleID, rule.ID)
				}
			}
		})
	}

	for _, f := range fixtures.Negative {
		t.Run("negative/"+f.Name, func(t *testing.T) {
			findings := runFixture(t, rule, &f)
			if len(findings) > 0 {
				t.Errorf("expected 0 findings, got %d: %v", len(findings), findings[0].Message)
			}
		})
	}
}

func runFixture(t *testing.T, rule *engine.Rule, f *Fixture) []engine.Finding {
	lang := f.Language
	if lang == "" {
		// Infer from rule languages
		for _, l := range rule.Languages {
			if l != "*" {
				lang = l
				break
			}
		}
	}

	filename := "test."
	switch lang {
	case "javascript", "typescript":
		filename += "js"
	case "python":
		filename += "py"
	case "go":
		filename += "go"
	case "java":
		filename += "java"
	case "php":
		filename += "php"
	case "rust":
		filename += "rs"
	case "csharp":
		filename += "cs"
	case "ruby":
		filename += "rb"
	case "swift":
		filename += "swift"
	case "kotlin":
		filename += "kt"
	case "c":
		filename += "c"
	case "cpp":
		filename += "cpp"
	default:
		filename += "txt"
	}

	config := engine.ScanConfig{
		Confidence:  "low",
		MinSeverity: engine.Low,
		Frameworks:  f.Frameworks,
	}
	if len(config.Frameworks) == 0 && len(rule.Frameworks) > 0 {
		config.Frameworks = rule.Frameworks
	}

	s := engine.NewScanner([]engine.Rule{*rule}, config)
	findings, err := s.ScanString([]byte(f.Source), filename, []engine.Rule{*rule})
	if err != nil {
		t.Fatalf("scanning fixture %q: %v", f.Name, err)
	}
	return findings
}

// LoadRule loads a single rule from a YAML file.
func LoadRule(path string) (*engine.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rule engine.Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, err
	}
	if rule.ID == "" {
		return nil, fmt.Errorf("rule has no id")
	}
	return &rule, nil
}

// DiscoverFixtures walks a directory and finds all rule fixture YAML files.
// A fixture file must be named <rule>.fixture.yaml and sit next to the rule.
func DiscoverFixtures(rulesDir string) (map[string]string, error) {
	fixtures := make(map[string]string)
	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".fixture.yaml") {
			base := strings.TrimSuffix(path, ".fixture.yaml")
			fixtures[base] = path
		}
		return nil
	})
	return fixtures, err
}

// LoadFixture loads a fixture YAML file.
func LoadFixture(path string) (*RuleFixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fixture RuleFixture
	if err := yaml.Unmarshal(data, &fixture); err != nil {
		return nil, err
	}
	return &fixture, nil
}
