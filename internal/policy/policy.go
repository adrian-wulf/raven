package policy

import (
	"fmt"
	"os"

	"github.com/raven-security/raven/internal/engine"
	"gopkg.in/yaml.v3"
)

// Policy defines security scanning policies for CI/CD
type Policy struct {
	MaxFindings    map[string]int `yaml:"max_findings,omitempty"`    // severity -> max count
	BlockedRules   []string       `yaml:"blocked_rules,omitempty"`   // rule IDs that always fail
	RequiredRules  []string       `yaml:"required_rules,omitempty"`  // rule IDs that must be active
	ExcludePaths   []string       `yaml:"exclude_paths,omitempty"`   // additional exclusions
	FailOnNew      bool           `yaml:"fail_on_new,omitempty"`     // only fail on new findings (baseline)
	AllowUntracked bool           `yaml:"allow_untracked,omitempty"` // don't fail on untracked files
}

// Load reads policy from .raven-policy.yaml or the given path
func Load(path string) (*Policy, error) {
	if path == "" {
		path = ".raven-policy.yaml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no policy = no restrictions
		}
		return nil, err
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}

	return &p, nil
}

// Result holds policy check results
type Result struct {
	Passed     bool
	Violations []string
}

// Check validates scan results against the policy
func (p *Policy) Check(result *engine.Result) *Result {
	r := &Result{Passed: true}
	if p == nil {
		return r
	}

	// Check max findings per severity
	bySev := result.BySeverity()
	for sev, max := range p.MaxFindings {
		count := len(bySev[engine.Severity(sev)])
		if count > max {
			r.Passed = false
			r.Violations = append(r.Violations,
				fmt.Sprintf("%s: found %d findings, max allowed is %d", sev, count, max))
		}
	}

	// Check blocked rules
	for _, finding := range result.Findings {
		for _, blocked := range p.BlockedRules {
			if finding.RuleID == blocked {
				r.Passed = false
				r.Violations = append(r.Violations,
					fmt.Sprintf("blocked rule %s triggered: %s", blocked, finding.Message))
			}
		}
	}

	// Check fail_on_new
	if p.FailOnNew && len(result.NewFindings) > 0 {
		r.Passed = false
		r.Violations = append(r.Violations,
			fmt.Sprintf("%d new findings detected against baseline", len(result.NewFindings)))
	}

	return r
}

// ExitCode returns the appropriate exit code
func (r *Result) ExitCode(findingsCount int) int {
	if !r.Passed {
		return 2 // policy violation
	}
	if findingsCount > 0 {
		return 1 // findings but within policy
	}
	return 0 // clean
}
