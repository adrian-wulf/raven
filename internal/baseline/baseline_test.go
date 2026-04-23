package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSaveRoundtrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "baseline.json")

	bl := New()
	bl.Records = append(bl.Records, Record{
		RuleID: "R001", File: "a.js", Line: 10, Column: 5, SnippetHash: "sha256:abc",
	})

	if err := bl.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(loaded.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(loaded.Records))
	}
	if loaded.Records[0].RuleID != "R001" {
		t.Errorf("expected R001, got %s", loaded.Records[0].RuleID)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/baseline.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestExactMatch(t *testing.T) {
	bl := New()
	bl.Records = append(bl.Records, Record{
		RuleID: "R001", File: "a.js", Line: 10, Column: 5, SnippetHash: "sha256:abc",
	})

	records := []Record{
		{RuleID: "R001", File: "a.js", Line: 10, Column: 5, SnippetHash: "sha256:xyz"},
		{RuleID: "R002", File: "a.js", Line: 10, Column: 5, SnippetHash: "sha256:abc"},
	}

	diff := bl.Diff(records)
	if len(diff.NewRecords) != 1 || len(diff.BaselineRecords) != 1 {
		t.Errorf("expected 1 new + 1 baseline, got %d new + %d baseline",
			len(diff.NewRecords), len(diff.BaselineRecords))
	}
}

func TestFuzzyMatchLineDrift(t *testing.T) {
	bl := New()
	bl.Records = append(bl.Records, Record{
		RuleID: "R001", File: "a.js", Line: 10, Column: 5,
		SnippetHash: HashSnippet("const x = 1"),
	})

	records := []Record{
		{RuleID: "R001", File: "a.js", Line: 13, Column: 5,
			SnippetHash: HashSnippet("const x = 1")},
	}

	diff := bl.Diff(records)
	if len(diff.BaselineRecords) != 1 {
		t.Errorf("expected fuzzy match within tolerance, got %d baseline findings", len(diff.BaselineRecords))
	}
}

func TestFuzzyMatchLineDriftTooFar(t *testing.T) {
	bl := New()
	bl.Records = append(bl.Records, Record{
		RuleID: "R001", File: "a.js", Line: 10, Column: 5,
		SnippetHash: HashSnippet("const x = 1"),
	})

	records := []Record{
		{RuleID: "R001", File: "a.js", Line: 20, Column: 5,
			SnippetHash: HashSnippet("const x = 1")},
	}

	diff := bl.Diff(records)
	if len(diff.NewRecords) != 1 {
		t.Errorf("expected no match outside tolerance, got %d new findings", len(diff.NewRecords))
	}
}

func TestDiffResultCounts(t *testing.T) {
	bl := New()
	bl.Records = append(bl.Records, Record{
		RuleID: "R001", File: "a.js", Line: 10, Column: 5, SnippetHash: "sha256:abc",
	})

	records := []Record{
		{RuleID: "R001", File: "a.js", Line: 10, Column: 5, SnippetHash: "sha256:abc"},
		{RuleID: "R002", File: "b.js", Line: 20, Column: 3, SnippetHash: "sha256:def"},
	}

	diff := bl.Diff(records)
	if len(diff.NewRecords) != 1 {
		t.Errorf("expected 1 new record, got %d", len(diff.NewRecords))
	}
	if len(diff.BaselineRecords) != 1 {
		t.Errorf("expected 1 baseline record, got %d", len(diff.BaselineRecords))
	}
	if len(diff.AllRecords) != 2 {
		t.Errorf("expected 2 total records, got %d", len(diff.AllRecords))
	}
}

func TestEmptyBaseline(t *testing.T) {
	bl := New()
	records := []Record{
		{RuleID: "R001", File: "a.js", Line: 1, SnippetHash: "sha256:x"},
	}
	diff := bl.Diff(records)
	if len(diff.NewRecords) != 1 {
		t.Errorf("expected all records to be new with empty baseline, got %d", len(diff.NewRecords))
	}
}

func TestSaveCreatesValidJSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "baseline.json")

	bl := New()
	bl.Records = append(bl.Records, Record{
		RuleID: "R001", File: "a.js", Line: 1, SnippetHash: "sha256:x", Snippet: "test",
	})
	if err := bl.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Size() == 0 {
		t.Error("saved baseline file is empty")
	}
}
