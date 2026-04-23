package taint

import (
	"os"
	"testing"
)

func TestNewTracker(t *testing.T) {
	tracker := NewTracker("javascript")
	if tracker == nil {
		t.Fatal("NewTracker returned nil")
	}
	// config should have default sources/sinks for javascript
	if len(tracker.config.Sources) == 0 {
		t.Error("expected default sources for javascript")
	}
}

func TestNewTrackerUnsupported(t *testing.T) {
	tracker := NewTracker("cobol")
	if tracker == nil {
		t.Fatal("NewTracker returned nil")
	}
	// Should not panic, just use empty config
}

func TestScanFileUnsupported(t *testing.T) {
	tracker := NewTracker("javascript")
	findings, err := tracker.ScanFile("/tmp/readme.txt", nil)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unsupported file, got %d", len(findings))
	}
}

func TestScanFileJSSQLInjection(t *testing.T) {
	tracker := NewTracker("javascript")
	code := []byte(`
function handler(req, res) {
	var userId = req.body.id;
	db.query("SELECT * FROM users WHERE id = " + userId);
}
`)
	tmp := t.TempDir()
	path := tmp + "/test.js"
	if err := writeFile(path, code); err != nil {
		t.Fatalf("write file: %v", err)
	}

	rules := []RuleInfo{{
		ID:       "js-sqli",
		Name:     "SQL Injection",
		Severity: "high",
		Patterns: []RulePattern{{
			Type:    "taint",
			Sources: []string{"req.body", "req.params", "req.query"},
			Sinks:   []string{".query", ".execute"},
		}},
	}}

	findings, err := tracker.ScanFile(path, rules)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for SQL injection, got none")
	}
	if findings[0].File == "" {
		t.Error("expected File field to be populated")
	}
	if findings[0].RuleID != "js-sqli" {
		t.Errorf("expected rule js-sqli, got %s", findings[0].RuleID)
	}
}

func TestScanFileGoSQLInjection(t *testing.T) {
	tracker := NewTracker("go")
	code := []byte(`
package main

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
`)
	path := t.TempDir() + "/test.go"
	if err := writeFile(path, code); err != nil {
		t.Fatalf("write file: %v", err)
	}

	rules := []RuleInfo{{
		ID:       "go-sqli",
		Name:     "SQL Injection",
		Severity: "high",
		Patterns: []RulePattern{{
			Type:    "taint",
			Sources: []string{"r.FormValue", "r.URL.Query"},
			Sinks:   []string{".Query", ".QueryRow"},
		}},
	}}

	findings, err := tracker.ScanFile(path, rules)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for Go SQL injection, got none")
	}
	if findings[0].File == "" {
		t.Error("expected File field to be populated")
	}
}

func TestScanFileNoTaint(t *testing.T) {
	tracker := NewTracker("javascript")
	code := []byte(`
function handler(req, res) {
	var x = "safe string";
	db.query("SELECT * FROM users WHERE id = " + x);
}
`)
	path := t.TempDir() + "/safe.js"
	if err := writeFile(path, code); err != nil {
		t.Fatalf("write file: %v", err)
	}

	rules := []RuleInfo{{
		ID:       "js-sqli",
		Name:     "SQL Injection",
		Severity: "high",
		Patterns: []RulePattern{{
			Type:    "taint",
			Sources: []string{"req.body"},
			Sinks:   []string{".query"},
		}},
	}}

	findings, err := tracker.ScanFile(path, rules)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe code, got %d", len(findings))
	}
}

// TestInterProceduralTaint checks that taint is tracked through function calls
// when a function returns tainted data.
func TestInterProceduralTaint(t *testing.T) {
	tracker := NewTracker("javascript")
	code := []byte(`
function getUserInput(req) {
	return req.body.id;
}

function handler(req, res) {
	var userId = getUserInput(req);
	db.query("SELECT * FROM users WHERE id = " + userId);
}
`)
	path := t.TempDir() + "/interprocedural.js"
	if err := writeFile(path, code); err != nil {
		t.Fatalf("write file: %v", err)
	}

	rules := []RuleInfo{{
		ID:       "js-sqli-inter",
		Name:     "SQL Injection (Inter-procedural)",
		Severity: "high",
		Patterns: []RulePattern{{
			Type:    "taint",
			Sources: []string{"req.body", "req.params", "req.query"},
			Sinks:   []string{".query", ".execute"},
		}},
	}}

	findings, err := tracker.ScanFile(path, rules)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected inter-procedural findings, got none")
	}
	if findings[0].RuleID != "js-sqli-inter" {
		t.Errorf("expected rule js-sqli-inter, got %s", findings[0].RuleID)
	}
}

// TestInterProceduralTaintSafe checks that safe function returns don't trigger
func TestInterProceduralTaintSafe(t *testing.T) {
	tracker := NewTracker("javascript")
	code := []byte(`
function getConstant() {
	return "safe-value";
}

function handler(req, res) {
	var val = getConstant();
	db.query("SELECT * FROM users WHERE id = " + val);
}
`)
	path := t.TempDir() + "/safe_interprocedural.js"
	if err := writeFile(path, code); err != nil {
		t.Fatalf("write file: %v", err)
	}

	rules := []RuleInfo{{
		ID:       "js-sqli-inter",
		Name:     "SQL Injection (Inter-procedural)",
		Severity: "high",
		Patterns: []RulePattern{{
			Type:    "taint",
			Sources: []string{"req.body", "req.params", "req.query"},
			Sinks:   []string{".query", ".execute"},
		}},
	}}

	findings, err := tracker.ScanFile(path, rules)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe inter-procedural code, got %d", len(findings))
	}
}

func writeFile(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	f.Close()
	return err
}

// TestSanitizerFiltering checks that sanitized input doesn't trigger findings
func TestSanitizerFiltering(t *testing.T) {
	tracker := NewTracker("javascript")
	code := []byte(`
function handler(req, res) {
	var userId = DOMPurify.sanitize(req.body.id);
	db.query("SELECT * FROM users WHERE id = " + userId);
}
`)
	path := t.TempDir() + "/sanitized.js"
	if err := writeFile(path, code); err != nil {
		t.Fatalf("write file: %v", err)
	}

	rules := []RuleInfo{{
		ID:       "js-sqli-san",
		Name:     "SQL Injection (Sanitized)",
		Severity: "high",
		Patterns: []RulePattern{{
			Type:    "taint",
			Sources: []string{"req.body", "req.params", "req.query"},
			Sinks:   []string{".query", ".execute"},
		}},
	}}

	findings, err := tracker.ScanFile(path, rules)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for sanitized input, got %d", len(findings))
	}
}

// TestInterProceduralTaintPython checks that taint flows through function
// arguments to parameters and then to sinks inside the callee.
func TestInterProceduralTaintPython(t *testing.T) {
	tracker := NewTracker("python")
	code := []byte(`
def run_query(cursor, sql):
    cursor.execute(sql)

def handler(request):
    name = request.args.get('name')
    run_query(cursor, "SELECT * FROM users WHERE name = '" + name + "'")
`)
	path := t.TempDir() + "/interprocedural.py"
	if err := writeFile(path, code); err != nil {
		t.Fatalf("write file: %v", err)
	}

	rules := []RuleInfo{{
		ID:       "py-sqli-inter",
		Name:     "SQL Injection (Inter-procedural)",
		Severity: "high",
		Patterns: []RulePattern{{
			Type:    "taint",
			Sources: []string{"request.args", "request.form"},
			Sinks:   []string{".execute", ".executemany"},
		}},
	}}

	findings, err := tracker.ScanFile(path, rules)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected inter-procedural findings for Python, got none")
	}
	if findings[0].RuleID != "py-sqli-inter" {
		t.Errorf("expected rule py-sqli-inter, got %s", findings[0].RuleID)
	}
}

// TestInterProceduralTaintPythonScanBytes checks inter-procedural via ScanBytes.
func TestInterProceduralTaintPythonScanBytes(t *testing.T) {
	tracker := NewTracker("python")
	tracker.SetCurrentFile("/tmp/interprocedural.py")
	code := []byte(`
def run_query(cursor, sql):
    cursor.execute(sql)

def handler(request):
    name = request.args.get('name')
    run_query(conn, "SELECT * FROM users WHERE name = '" + name + "'")
`)

	rules := []RuleInfo{{
		ID:       "py-sqli-inter",
		Name:     "SQL Injection (Inter-procedural)",
		Severity: "high",
		Patterns: []RulePattern{{
			Type:    "taint",
			Sources: []string{"request.args", "request.form"},
			Sinks:   []string{".execute", ".executemany"},
		}},
	}}

	findings, err := tracker.ScanBytes("python", code, rules)
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected inter-procedural findings for Python ScanBytes, got none")
	}
}

func TestTrackerDjangoSchema(t *testing.T) {
	tracker := NewTracker("python")
	tracker.SetCurrentFile("/tmp/raven-benchmark/django/django/db/backends/base/schema.py")
	code := []byte(`
class BaseDatabaseSchemaEditor:
    def _alter_column_type_sql(self, model, old_field, new_field, new_type):
        return (
            (
                self.sql_alter_column_type
                % {
                    "column": self.quote_name(old_field.column),
                    "type": new_type,
                },
                [],
            ),
            [],
        )

    def _delete_composed_index(self, model, fields, *args):
        columns = [model._meta.get_field(field).column for field in fields]
        sql = self._create_index_sql(model, fields, suffix="_idx").remove_suffix("_idx")
        self.execute(sql)
`)

	rules := []RuleInfo{{
		ID:       "raven-ast-py-sqli-001",
		Name:     "SQL Injection via String Formatting",
		Severity: "critical",
		Patterns: []RulePattern{{
			Type:    "taint",
			Sources: []string{"request.args", "request.form", "request.json", "request.data", "request.headers", "request.cookies", "request.files", "sys.argv", "input"},
			Sinks:   []string{".execute", ".executemany", ".run"},
		}},
	}}

	findings, err := tracker.ScanBytes("python", code, rules)
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	for _, f := range findings {
		t.Logf("FINDING: %s at line %d: %s", f.RuleID, f.Line, f.Message)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
