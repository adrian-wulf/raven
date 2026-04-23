package ruletest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRules walks the rules/ directory and runs any discovered fixtures.
func TestRules(t *testing.T) {
	fixtures, err := DiscoverFixtures("../../rules")
	if err != nil {
		t.Fatalf("discovering fixtures: %v", err)
	}

	if len(fixtures) == 0 {
		t.Skip("no fixtures found")
	}

	for rulePath, fixturePath := range fixtures {
		fixturePath := fixturePath

		// Derive a clean test name from the rule path
		name := strings.TrimPrefix(rulePath, "../../rules/")
		name = strings.TrimSuffix(name, ".yaml")
		name = strings.ReplaceAll(name, "/", "-")

		t.Run(name, func(t *testing.T) {
			fixture, err := LoadFixture(fixturePath)
			if err != nil {
				t.Fatalf("loading fixture %s: %v", fixturePath, err)
			}
			RunRuleTest(t, rulePath, fixture)
		})
	}
}

// TestRuleValidation validates that every rule YAML in rules/ loads correctly
// and has valid patterns.
func TestRuleValidation(t *testing.T) {
	// Walk rules directory and validate every .yaml file
	files, err := filepath.Glob("../../rules/**/*.yaml")
	if err != nil {
		t.Fatalf("globbing rules: %v", err)
	}

	for _, path := range files {
		if strings.HasSuffix(path, ".fixture.yaml") {
			continue
		}

		name := strings.TrimPrefix(path, "../../rules/")
		name = strings.TrimSuffix(name, ".yaml")
		name = strings.ReplaceAll(name, "/", "-")

		t.Run(name, func(t *testing.T) {
			rule, err := LoadRule(path)
			if err != nil {
				t.Fatalf("loading rule: %v", err)
			}
			if rule.ID == "" {
				t.Error("rule has no id")
			}
			if rule.Name == "" {
				t.Error("rule has no name")
			}
			if len(rule.Patterns) == 0 {
				t.Error("rule has no patterns")
			}
			for i, p := range rule.Patterns {
				if p.Type == "" {
					t.Errorf("pattern %d has no type", i)
					continue
				}
				switch p.Type {
				case "regex", "literal":
					if p.Pattern == "" {
						t.Errorf("pattern %d (%s) has no pattern", i, p.Type)
					}
				case "ast-query":
					query := p.Query
					if query == "" {
						query = p.Pattern
					}
					if query == "" {
						t.Errorf("pattern %d (ast-query) has no query", i)
					}
				case "taint":
					if len(p.Sources) == 0 && len(p.Sinks) == 0 {
						t.Errorf("pattern %d (taint) has no sources or sinks", i)
					}
				default:
					t.Errorf("pattern %d has unknown type: %s", i, p.Type)
				}
			}
		})
	}
}
