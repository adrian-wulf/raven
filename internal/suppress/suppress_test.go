package suppress

import (
	"testing"
)

func TestParseLineIgnoreCurrent(t *testing.T) {
	entries := parseLine("// raven-ignore: R001", 5)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Line != 5 {
		t.Errorf("expected line 5, got %d", entries[0].Line)
	}
	if len(entries[0].Rules) != 1 || entries[0].Rules[0] != "R001" {
		t.Errorf("expected [R001], got %v", entries[0].Rules)
	}
	if entries[0].NextLine {
		t.Error("expected NextLine to be false")
	}
}

func TestParseLineIgnoreMultiple(t *testing.T) {
	entries := parseLine("// raven-ignore: R001, R002, R003", 1)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(entries[0].Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(entries[0].Rules))
	}
}

func TestParseLineIgnoreNextLine(t *testing.T) {
	entries := parseLine("// raven-ignore-next-line: R001", 10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entries[0].NextLine {
		t.Error("expected NextLine to be true")
	}
	if entries[0].Line != 10 {
		t.Errorf("expected line 10, got %d", entries[0].Line)
	}
}

func TestParseLineIgnoreNextLineAll(t *testing.T) {
	entries := parseLine("// raven-ignore-next-line", 3)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entries[0].NextLine {
		t.Error("expected NextLine to be true")
	}
	if len(entries[0].Rules) != 0 {
		t.Errorf("expected all rules suppressed, got %v", entries[0].Rules)
	}
}

func TestParseLineHashComment(t *testing.T) {
	entries := parseLine("# raven-ignore: R001", 1)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestParseLineNoComment(t *testing.T) {
	entries := parseLine("const x = 1;", 1)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseLineCaseInsensitive(t *testing.T) {
	entries := parseLine("// RAVEN-IGNORE: r001", 1)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestIsSuppressedCurrentLine(t *testing.T) {
	m := NewMap()
	m.entries["test.js"] = []Entry{
		{Line: 5, Rules: []string{"R001"}},
	}

	if !m.IsSuppressed("test.js", 5, "R001") {
		t.Error("expected R001 to be suppressed on line 5")
	}
	if m.IsSuppressed("test.js", 5, "R002") {
		t.Error("expected R002 NOT to be suppressed on line 5")
	}
	if m.IsSuppressed("test.js", 6, "R001") {
		t.Error("expected R001 NOT to be suppressed on line 6")
	}
}

func TestIsSuppressedNextLine(t *testing.T) {
	m := NewMap()
	m.entries["test.js"] = []Entry{
		{Line: 5, NextLine: true, Rules: []string{"R001"}},
	}

	if !m.IsSuppressed("test.js", 6, "R001") {
		t.Error("expected R001 to be suppressed on line 6 (next-line from 5)")
	}
	if m.IsSuppressed("test.js", 5, "R001") {
		t.Error("expected R001 NOT to be suppressed on line 5 itself")
	}
}

func TestIsSuppressedAllRules(t *testing.T) {
	m := NewMap()
	m.entries["test.js"] = []Entry{
		{Line: 5, NextLine: true, Rules: []string{}},
	}

	if !m.IsSuppressed("test.js", 6, "R001") {
		t.Error("expected all rules to be suppressed")
	}
	if !m.IsSuppressed("test.js", 6, "R999") {
		t.Error("expected all rules to be suppressed")
	}
}

func TestParseFile(t *testing.T) {
	m := NewMap()
	if err := m.ParseFile("suppress_test.go"); err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if m.Count() == 0 {
		t.Error("expected some suppressions in this test file")
	}
}

func TestExtractComment(t *testing.T) {
	cases := []struct {
		line     string
		expected string
	}{
		{"// raven-ignore: R001", "raven-ignore: R001"},
		{"const x = 1; // raven-ignore: R001", "raven-ignore: R001"},
		{"# raven-ignore: R001", "raven-ignore: R001"},
		{"/* raven-ignore: R001 */", "raven-ignore: R001"},
		{"const x = 1;", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := extractComment(c.line)
		if got != c.expected {
			t.Errorf("extractComment(%q) = %q, want %q", c.line, got, c.expected)
		}
	}
}
