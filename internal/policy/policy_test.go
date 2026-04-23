package policy

import (
	"testing"

	"github.com/raven-security/raven/internal/engine"
)

func TestPolicyMaxFindings(t *testing.T) {
	p := &Policy{
		MaxFindings: map[string]int{
			"high": 2,
		},
	}

	// Under limit
	r := p.Check(&engine.Result{
		Findings: []engine.Finding{
			{Severity: engine.High},
			{Severity: engine.High},
		},
	})
	if !r.Passed {
		t.Error("expected to pass with 2 high findings")
	}

	// Over limit
	r = p.Check(&engine.Result{
		Findings: []engine.Finding{
			{Severity: engine.High},
			{Severity: engine.High},
			{Severity: engine.High},
		},
	})
	if r.Passed {
		t.Error("expected to fail with 3 high findings")
	}
}

func TestPolicyBlockedRules(t *testing.T) {
	p := &Policy{
		BlockedRules: []string{"R001"},
	}

	r := p.Check(&engine.Result{
		Findings: []engine.Finding{
			{RuleID: "R001", Message: "bad thing"},
		},
	})
	if r.Passed {
		t.Error("expected to fail on blocked rule")
	}
}

func TestPolicyFailOnNew(t *testing.T) {
	p := &Policy{
		FailOnNew: true,
	}

	r := p.Check(&engine.Result{
		NewFindings: []engine.Finding{
			{RuleID: "R001"},
		},
	})
	if r.Passed {
		t.Error("expected to fail on new findings")
	}
}

func TestExitCode(t *testing.T) {
	p := &Policy{}

	// Clean
	r := p.Check(&engine.Result{})
	if r.ExitCode(0) != 0 {
		t.Error("expected exit 0 for clean")
	}

	// Findings but within policy
	r = p.Check(&engine.Result{Findings: []engine.Finding{{Severity: engine.Low}}})
	if r.ExitCode(1) != 1 {
		t.Error("expected exit 1 for findings within policy")
	}

	// Policy violation
	p2 := &Policy{MaxFindings: map[string]int{"critical": 0}}
	r = p2.Check(&engine.Result{Findings: []engine.Finding{{Severity: engine.Critical}}})
	if r.ExitCode(1) != 2 {
		t.Error("expected exit 2 for policy violation")
	}
}
