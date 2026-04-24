package llm

import (
	"fmt"
	"strings"
)

// FixPatch represents a unified diff-style patch for a vulnerability fix
type FixPatch struct {
	OriginalCode string   // lines being replaced
	FixedCode    string   // replacement
	StartLine    int      // start line in original file
	EndLine      int      // end line in original file
	ContextLines int      // lines of context around change
	IsMultiFile  bool     // does fix require changes in other files?
	RelatedFiles []string // other files that need changes
	Explanation  string   // human-readable explanation
	Confidence   float64  // 0.0-1.0
}

// PatchGenerator creates unified diff patches from AI-generated fixes
type PatchGenerator struct{}

// NewPatchGenerator creates a new patch generator
func NewPatchGenerator() *PatchGenerator {
	return &PatchGenerator{}
}

// GeneratePatch creates a FixPatch from the original code and AI fix
func (pg *PatchGenerator) GeneratePatch(originalCode, fixedCode string, startLine, contextLines int) (*FixPatch, error) {
	if originalCode == "" || fixedCode == "" {
		return nil, fmt.Errorf("original and fixed code must not be empty")
	}

	originalLines := strings.Split(originalCode, "\n")
	endLine := startLine + len(originalLines) - 1

	return &FixPatch{
		OriginalCode: originalCode,
		FixedCode:    fixedCode,
		StartLine:    startLine,
		EndLine:      endLine,
		ContextLines: contextLines,
		IsMultiFile:  false,
		Confidence:   0.8,
	}, nil
}

// ToUnifiedDiff converts the patch to unified diff format
func (p *FixPatch) ToUnifiedDiff(filename string) string {
	var sb strings.Builder
	hunkStart := p.StartLine - p.ContextLines
	if hunkStart < 1 {
		hunkStart = 1
	}
	hunkSize := (p.EndLine - p.StartLine + 1) + 2*p.ContextLines

	sb.WriteString(fmt.Sprintf("--- %s\n", filename))
	sb.WriteString(fmt.Sprintf("+++ %s\n", filename))
	sb.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", hunkStart, hunkSize, hunkStart, hunkSize))

	// Original lines marked with -
	for _, line := range strings.Split(p.OriginalCode, "\n") {
		sb.WriteString("-" + line + "\n")
	}
	// Fixed lines marked with +
	for _, line := range strings.Split(p.FixedCode, "\n") {
		sb.WriteString("+" + line + "\n")
	}

	return sb.String()
}

// ValidatePatch checks if the patch can be applied cleanly
func (p *FixPatch) ValidatePatch(originalContent string) (bool, []string) {
	lines := strings.Split(originalContent, "\n")
	var issues []string

	if p.StartLine < 1 || p.StartLine > len(lines) {
		issues = append(issues, fmt.Sprintf("start line %d out of range (1-%d)", p.StartLine, len(lines)))
	}
	if p.EndLine < p.StartLine || p.EndLine > len(lines) {
		issues = append(issues, fmt.Sprintf("end line %d out of range", p.EndLine))
	}

	// Verify original code matches
	if p.StartLine > 0 && p.EndLine <= len(lines) {
		actualOriginal := strings.Join(lines[p.StartLine-1:p.EndLine], "\n")
		if strings.TrimSpace(actualOriginal) != strings.TrimSpace(p.OriginalCode) {
			issues = append(issues, "original code does not match file content at specified lines")
		}
	}

	return len(issues) == 0, issues
}

// ApplyPatch applies the patch to file content and returns new content
func ApplyPatch(content string, patch *FixPatch) (string, error) {
	lines := strings.Split(content, "\n")
	if patch.StartLine < 1 || patch.EndLine > len(lines) {
		return "", fmt.Errorf("patch line range %d-%d out of bounds (1-%d)", patch.StartLine, patch.EndLine, len(lines))
	}

	var result []string
	result = append(result, lines[:patch.StartLine-1]...)
	result = append(result, strings.Split(patch.FixedCode, "\n")...)
	result = append(result, lines[patch.EndLine:]...)

	return strings.Join(result, "\n"), nil
}
