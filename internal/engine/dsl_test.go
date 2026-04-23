package engine

import (
	"testing"
)

func TestExpandMetavars(t *testing.T) {
	cases := []struct {
		template string
		metavars map[string]string
		expected string
	}{
		{
			template: "Use $var instead of ${var}.innerHTML",
			metavars: map[string]string{"var": "elem"},
			expected: "Use elem instead of elem.innerHTML",
		},
		{
			template: "Call $func() safely",
			metavars: map[string]string{"func": "eval"},
			expected: "Call eval() safely",
		},
		{
			template: "No metavars here",
			metavars: map[string]string{},
			expected: "No metavars here",
		},
	}

	for _, c := range cases {
		got := expandMetavars(c.template, c.metavars)
		if got != c.expected {
			t.Errorf("expandMetavars(%q) = %q, want %q", c.template, got, c.expected)
		}
	}
}

func TestMatchRegexNamedCaptures(t *testing.T) {
	s := &Scanner{}
	content := []byte(`element.innerHTML = req.body.name`)
	pattern := `(?P<var>\w+)\.innerHTML\s*=\s*req\.body`

	matches := s.matchRegex(content, pattern, "test.js")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if matches[0].metavars["var"] != "element" {
		t.Errorf("expected metavars[var] = 'element', got %q", matches[0].metavars["var"])
	}
}

func TestMatchesWhereNotTestFile(t *testing.T) {
	s := &Scanner{}
	content := []byte("")

	// Test file should be rejected
	finding := Finding{File: "app_test.go", Line: 5}
	where := []WhereClause{{NotTestFile: true}}
	if s.matchesWhere(finding, where, content) {
		t.Error("expected test file to be rejected")
	}

	// Normal file should pass
	finding2 := Finding{File: "app.go", Line: 5}
	if !s.matchesWhere(finding2, where, content) {
		t.Error("expected normal file to pass")
	}
}

func TestMatchesWhereNotConstant(t *testing.T) {
	s := &Scanner{}

	cases := []struct {
		snippet  string
		expected bool // true = should pass (not constant = ok)
	}{
		{"req.body.name", true},
		{"\"hello world\"", false},
		{"123", false},
		{"`template string`", false},
	}

	for _, c := range cases {
		finding := Finding{Snippet: c.snippet}
		where := []WhereClause{{NotConstant: true}}
		got := s.matchesWhere(finding, where, []byte(c.snippet))
		if got != c.expected {
			t.Errorf("matchesWhere(%q, not-constant) = %v, want %v", c.snippet, got, c.expected)
		}
	}
}

func TestMatchesWhereNotSanitized(t *testing.T) {
	s := &Scanner{}

	// No sanitizer in code - should pass (report it)
	content := []byte(`function foo() {
		elem.innerHTML = input;
	}`)
	finding := Finding{File: "app.js", Line: 2}
	where := []WhereClause{{NotSanitized: []string{"DOMPurify.sanitize"}}}
	if !s.matchesWhere(finding, where, content) {
		t.Error("expected unsanitized input to pass where clause")
	}

	// Sanitizer nearby - should be filtered out
	content2 := []byte(`function foo() {
		const clean = DOMPurify.sanitize(input);
		elem.innerHTML = clean;
	}`)
	finding2 := Finding{File: "app.js", Line: 3}
	if s.matchesWhere(finding2, where, content2) {
		t.Error("expected sanitized input to be filtered out")
	}
}

func TestMatchesContextInside(t *testing.T) {
	s := &Scanner{}
	content := []byte(`function handler() {
		eval(userInput);
	}`)

	// Should match because content contains "function"
	inside := &Pattern{Type: "regex", Pattern: `function\s+\w+`}
	if !s.matchesContext(content, inside, nil) {
		t.Error("expected inside pattern to match")
	}

	// Should fail because content doesn't contain "class"
	inside2 := &Pattern{Type: "literal", Pattern: "class Foo"}
	if s.matchesContext(content, inside2, nil) {
		t.Error("expected inside pattern to not match")
	}
}

func TestMatchesContextNotInside(t *testing.T) {
	s := &Scanner{}
	content := []byte(`function handler() {
		eval(userInput);
	}`)

	// Should pass because content doesn't contain "try"
	notInside := &Pattern{Type: "literal", Pattern: "try {"}
	if !s.matchesContext(content, nil, notInside) {
		t.Error("expected not-inside pattern to pass")
	}

	// Should fail because content contains "function"
	notInside2 := &Pattern{Type: "regex", Pattern: `function\s+\w+`}
	if s.matchesContext(content, nil, notInside2) {
		t.Error("expected not-inside pattern to filter out")
	}
}

func TestIsConstant(t *testing.T) {
	cases := []struct {
		input    string
		expected bool
	}{
		{"\"hello\"", true},
		{"'world'", true},
		{"`template`", true},
		{"123", true},
		{"456", true},
		{"req.body", false},
		{"userInput", false},
		{"getUser()", false},
	}

	for _, c := range cases {
		got := isConstant("", c.input)
		if got != c.expected {
			t.Errorf("isConstant(%q) = %v, want %v", c.input, got, c.expected)
		}
	}
}
