package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	BaselineVersion = "1.0"
	LineTolerance   = 5 // lines of drift allowed for fuzzy match
)

// Record represents a single finding stored in the baseline.
type Record struct {
	RuleID      string `json:"rule_id"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	SnippetHash string `json:"snippet_hash"`
	RuleName    string `json:"rule_name,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Snippet     string `json:"snippet,omitempty"` // kept for roundtrip fidelity
}

// Baseline is the full set of known/accepted findings.
type Baseline struct {
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Records     []Record  `json:"findings"`
}

// New creates an empty baseline.
func New() *Baseline {
	return &Baseline{
		Version:     BaselineVersion,
		GeneratedAt: time.Now().UTC(),
		Records:     []Record{},
	}
}

// Load reads a baseline from a JSON file.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline: %w", err)
	}
	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	return &bl, nil
}

// Save writes the baseline to a JSON file.
func (b *Baseline) Save(path string) error {
	b.GeneratedAt = time.Now().UTC()
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding baseline: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("writing baseline: %w", err)
	}
	return nil
}

// HashSnippet returns a short SHA256 of the snippet.
func HashSnippet(snippet string) string {
	h := sha256.New()
	h.Write([]byte(snippet))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}

// DiffResult holds the outcome of a baseline comparison.
type DiffResult struct {
	NewRecords      []Record // not in baseline
	BaselineRecords []Record // matched baseline
	AllRecords      []Record // all records
}

// Diff compares records against the baseline and splits them into new vs existing.
func (b *Baseline) Diff(records []Record) DiffResult {
	var newRecords, baselineRecords []Record

	for _, r := range records {
		if b.matches(r) {
			baselineRecords = append(baselineRecords, r)
		} else {
			newRecords = append(newRecords, r)
		}
	}

	return DiffResult{
		NewRecords:      newRecords,
		BaselineRecords: baselineRecords,
		AllRecords:      records,
	}
}

// matches checks whether a record is present in the baseline.
func (b *Baseline) matches(r Record) bool {
	for _, existing := range b.Records {
		if exactMatch(existing, r) || fuzzyMatch(existing, r) {
			return true
		}
	}
	return false
}

// exactMatch requires rule_id + file + line + column to match.
func exactMatch(a, b Record) bool {
	return a.RuleID == b.RuleID &&
		a.File == b.File &&
		a.Line == b.Line &&
		a.Column == b.Column
}

// fuzzyMatch allows line drift if the snippet hash matches.
func fuzzyMatch(a, b Record) bool {
	if a.RuleID != b.RuleID || a.File != b.File {
		return false
	}
	if a.SnippetHash != b.SnippetHash {
		return false
	}
	lineDiff := a.Line - b.Line
	if lineDiff < 0 {
		lineDiff = -lineDiff
	}
	return lineDiff <= LineTolerance
}

// Count returns the number of records in the baseline.
func (b *Baseline) Count() int {
	return len(b.Records)
}
