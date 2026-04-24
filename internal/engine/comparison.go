package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ScanBaseline represents a saved scan result for comparison
type ScanBaseline struct {
	Timestamp string             `json:"timestamp"`
	Version   string             `json:"version"`
	Findings  []BaselineFinding  `json:"findings"`
	Summary   ScanSummary        `json:"summary"`
}

// BaselineFinding is a simplified finding for baseline storage
type BaselineFinding struct {
	RuleID   string `json:"rule_id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Hash     string `json:"hash"` // content hash for change detection
}

// ScanComparisonResult shows differences between two scans
type ScanComparisonResult struct {
	NewFindings      []Finding `json:"new_findings"`
	FixedFindings    []Finding `json:"fixed_findings"`
	UnchangedFindings []Finding `json:"unchanged_findings"`
	NewCount         int       `json:"new_count"`
	FixedCount       int       `json:"fixed_count"`
	UnchangedCount   int       `json:"unchanged_count"`
	BaselineTime     string    `json:"baseline_time"`
	CurrentTime      string    `json:"current_time"`
}

// BaselineManager handles saving and comparing scan baselines
type BaselineManager struct {
	baselinePath string
}

// NewBaselineManager creates a baseline manager
func NewBaselineManager(path string) *BaselineManager {
	if path == "" {
		path = ".raven-baseline.json"
	}
	return &BaselineManager{baselinePath: path}
}

// SaveBaseline saves current scan results as baseline
func (bm *BaselineManager) SaveBaseline(findings []Finding, summary ScanSummary) error {
	baseline := ScanBaseline{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   "2.5.0",
		Summary:   summary,
	}

	for _, f := range findings {
		baseline.Findings = append(baseline.Findings, BaselineFinding{
			RuleID:   f.RuleID,
			File:     f.File,
			Line:     f.Line,
			Column:   f.Column,
			Category: string(f.Category),
			Message:  f.Message,
			Hash:     bm.hashFinding(f),
		})
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(bm.baselinePath, data, 0644)
}

// LoadBaseline loads a previously saved baseline
func (bm *BaselineManager) LoadBaseline() (*ScanBaseline, error) {
	data, err := os.ReadFile(bm.baselinePath)
	if err != nil {
		return nil, fmt.Errorf("baseline file not found: %w", err)
	}

	var baseline ScanBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("invalid baseline file: %w", err)
	}

	return &baseline, nil
}

// Compare compares current findings against baseline
func (bm *BaselineManager) Compare(currentFindings []Finding) (*ScanComparisonResult, error) {
	baseline, err := bm.LoadBaseline()
	if err != nil {
		return nil, err
	}

	result := &ScanComparisonResult{
		BaselineTime: baseline.Timestamp,
		CurrentTime:  time.Now().UTC().Format(time.RFC3339),
	}

	// Create lookup map for baseline findings
	baselineMap := make(map[string]BaselineFinding)
	for _, bf := range baseline.Findings {
		key := bm.findingKey(bf.RuleID, bf.File, bf.Line, bf.Category)
		baselineMap[key] = bf
	}

	// Check current findings against baseline
	currentMap := make(map[string]bool)
	for _, cf := range currentFindings {
		key := bm.findingKey(cf.RuleID, cf.File, cf.Line, string(cf.Category))
		currentMap[key] = true

		if _, exists := baselineMap[key]; exists {
			result.UnchangedFindings = append(result.UnchangedFindings, cf)
		} else {
			result.NewFindings = append(result.NewFindings, cf)
		}
	}

	// Check for fixed findings (in baseline but not in current)
	for _, bf := range baseline.Findings {
		key := bm.findingKey(bf.RuleID, bf.File, bf.Line, bf.Category)
		if !currentMap[key] {
			result.FixedFindings = append(result.FixedFindings, Finding{
				RuleID:   bf.RuleID,
				File:     bf.File,
				Line:     bf.Line,
				Category: bf.Category,
				Message:  bf.Message,
			})
		}
	}

	result.NewCount = len(result.NewFindings)
	result.FixedCount = len(result.FixedFindings)
	result.UnchangedCount = len(result.UnchangedFindings)

	return result, nil
}

// findingKey creates a unique key for a finding
func (bm *BaselineManager) findingKey(ruleID, file string, line int, category string) string {
	return fmt.Sprintf("%s:%s:%d:%s", ruleID, file, line, category)
}

// hashFinding creates a simple hash of a finding for change detection
func (bm *BaselineManager) hashFinding(f Finding) string {
	return fmt.Sprintf("%x", f.Line*f.Column+len(f.RuleID)+len(f.Message))
}

// HasBaseline checks if a baseline file exists
func (bm *BaselineManager) HasBaseline() bool {
	_, err := os.Stat(bm.baselinePath)
	return err == nil
}

// DeleteBaseline removes the baseline file
func (bm *BaselineManager) DeleteBaseline() error {
	return os.Remove(bm.baselinePath)
}

// PrintComparison prints comparison results in a readable format
func (result *ScanComparisonResult) PrintComparison() {
	fmt.Printf("\n📊 Scan Comparison (baseline: %s)\n", result.BaselineTime)
	fmt.Printf("   New: %d | Fixed: %d | Unchanged: %d\n\n", result.NewCount, result.FixedCount, result.UnchangedCount)

	if result.NewCount > 0 {
		fmt.Println("🔴 NEW Findings:")
		for _, f := range result.NewFindings {
			fmt.Printf("   [%s] %s:%d - %s\n", f.Severity, f.File, f.Line, f.RuleName)
		}
		fmt.Println()
	}

	if result.FixedCount > 0 {
		fmt.Println("🟢 FIXED Findings:")
		for _, f := range result.FixedFindings {
			fmt.Printf("   %s:%d - %s\n", f.File, f.Line, f.RuleName)
		}
		fmt.Println()
	}

	if result.UnchangedCount > 0 {
		fmt.Printf("⚪ Unchanged: %d findings\n", result.UnchangedCount)
	}
}
