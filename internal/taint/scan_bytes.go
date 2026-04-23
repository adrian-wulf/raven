package taint

import (
	"github.com/raven-security/raven/internal/ast"
)

// ScanBytes analyzes source code directly from bytes for taint vulnerabilities.
// This is useful for testing and in-memory scanning without writing temp files.
func (t *Tracker) ScanBytes(langName string, source []byte, rules []RuleInfo) ([]Finding, error) {
	lang := ast.GetLanguageByName(langName)
	if lang == nil {
		return nil, nil
	}

	pf, err := ast.ParseBytes(lang, source)
	if err != nil {
		return nil, err
	}
	defer pf.Close()

	var findings []Finding

	for _, rule := range rules {
		if !t.appliesToRule(rule) {
			continue
		}

		ruleFindings := t.analyzeRule(pf, rule)
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}
