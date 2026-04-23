package output

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/raven-security/raven/internal/engine"
	"github.com/raven-security/raven/internal/version"
)

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestPrintSARIFVersion(t *testing.T) {
	f := &Formatter{Format: "sarif", Color: false}
	result := &engine.Result{}

	out := captureStdout(func() {
		if err := f.Print(result); err != nil {
			t.Fatalf("Print failed: %v", err)
		}
	})

	var sarif map[string]interface{}
	if err := json.Unmarshal([]byte(out), &sarif); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	runs := sarif["runs"].([]interface{})
	tool := runs[0].(map[string]interface{})["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})

	if driver["version"] != version.Version {
		t.Errorf("expected version %s, got %v", version.Version, driver["version"])
	}
	if driver["name"] != "Raven" {
		t.Errorf("expected name Raven, got %v", driver["name"])
	}
}

func TestPrintJSON(t *testing.T) {
	f := &Formatter{Format: "json", Color: false}
	result := &engine.Result{
		Findings: []engine.Finding{
			{RuleID: "R001", File: "test.js", Line: 1, Severity: engine.High},
		},
	}

	out := captureStdout(func() {
		if err := f.Print(result); err != nil {
			t.Fatalf("Print failed: %v", err)
		}
	})

	var parsed engine.Result
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(parsed.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(parsed.Findings))
	}
}
