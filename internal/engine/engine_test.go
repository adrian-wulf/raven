package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeduplicate(t *testing.T) {
	findings := []Finding{
		{RuleID: "R001", File: "a.js", Line: 1},
		{RuleID: "R001", File: "a.js", Line: 1},
		{RuleID: "R002", File: "a.js", Line: 1},
		{RuleID: "R001", File: "a.js", Line: 2},
	}
	unique := deduplicate(findings)
	if len(unique) != 3 {
		t.Errorf("expected 3 unique findings, got %d", len(unique))
	}
}

func TestIsExcluded(t *testing.T) {
	s := &Scanner{config: ScanConfig{Exclude: []string{"node_modules", "*.min.js"}}}
	cases := []struct {
		path     string
		expected bool
	}{
		{"/project/node_modules/foo.js", true},
		{"/project/src/app.min.js", true},
		{"/project/src/main.js", false},
		{"/project/dist/bundle.js", true},
	}
	for _, c := range cases {
		if got := s.isExcluded(c.path); got != c.expected {
			t.Errorf("isExcluded(%q) = %v, want %v", c.path, got, c.expected)
		}
	}
}

func TestHasSupportedExtension(t *testing.T) {
	s := &Scanner{}
	cases := []struct {
		path     string
		expected bool
	}{
		{"main.go", true},
		{"app.js", true},
		{"style.css", false},
		{"README.md", false},
	}
	for _, c := range cases {
		if got := s.hasSupportedExtension(c.path); got != c.expected {
			t.Errorf("hasSupportedExtension(%q) = %v, want %v", c.path, got, c.expected)
		}
	}
}

func TestCollectFiles(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "a.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(tmp, "b.js"), []byte("console.log(1)"), 0644)
	os.Mkdir(filepath.Join(tmp, "node_modules"), 0755)
	os.WriteFile(filepath.Join(tmp, "node_modules", "x.js"), []byte(""), 0644)

	s := &Scanner{config: ScanConfig{Paths: []string{tmp}}}
	files, err := s.collectFiles()
	if err != nil {
		t.Fatalf("collectFiles failed: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d: %v", len(files), files)
	}
}

func TestFilterRules(t *testing.T) {
	rules := []Rule{
		{ID: "R1", Severity: High, Confidence: "high", Languages: []string{"go"}},
		{ID: "R2", Severity: Low, Confidence: "medium", Languages: []string{"js"}},
		{ID: "R3", Severity: Critical, Confidence: "high", Frameworks: []string{"express"}},
	}

	s := &Scanner{
		rules: rules,
		config: ScanConfig{MinSeverity: High, Confidence: "high"},
	}
	filtered := s.filterRules()
	if len(filtered) != 1 || filtered[0].ID != "R1" {
		t.Errorf("expected only R1, got %v", filtered)
	}
}

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		sev      Severity
		expected int
	}{
		{Info, 1},
		{Low, 2},
		{Medium, 3},
		{High, 4},
		{Critical, 5},
		{"unknown", 0},
	}
	for _, c := range cases {
		if got := SeverityRank(c.sev); got != c.expected {
			t.Errorf("SeverityRank(%q) = %d, want %d", c.sev, got, c.expected)
		}
	}
}

func TestMeetsConfidence(t *testing.T) {
	s := &Scanner{config: ScanConfig{Confidence: "medium"}}
	cases := []struct {
		conf     string
		expected bool
	}{
		{"low", false},
		{"medium", true},
		{"high", true},
	}
	for _, c := range cases {
		if got := s.meetsConfidence(c.conf); got != c.expected {
			t.Errorf("meetsConfidence(%q) = %v, want %v", c.conf, got, c.expected)
		}
	}

	s2 := &Scanner{config: ScanConfig{Confidence: "high"}}
	if s2.meetsConfidence("low") {
		t.Error("expected low confidence to fail when requiring high")
	}
}

func TestResultBySeverity(t *testing.T) {
	r := &Result{
		Findings: []Finding{
			{RuleID: "R1", Severity: High},
			{RuleID: "R2", Severity: High},
			{RuleID: "R3", Severity: Low},
		},
	}
	bySev := r.BySeverity()
	if len(bySev[High]) != 2 {
		t.Errorf("expected 2 high findings, got %d", len(bySev[High]))
	}
	if len(bySev[Low]) != 1 {
		t.Errorf("expected 1 low finding, got %d", len(bySev[Low]))
	}
}
