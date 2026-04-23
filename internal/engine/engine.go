package engine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/raven-security/raven/internal/ast"
	"github.com/raven-security/raven/internal/baseline"
	"github.com/raven-security/raven/internal/suppress"
	"github.com/raven-security/raven/internal/taint"
	"github.com/raven-security/raven/internal/utils"
)

type Scanner struct {
	rules   []Rule
	config  ScanConfig
}

type ScanConfig struct {
	Paths        []string
	Exclude      []string
	Languages    []string
	Frameworks   []string
	Confidence   string
	MinSeverity  Severity
	Baseline     *baseline.Baseline // optional baseline for diff scanning
	Suppressions *suppress.Map      // optional inline comment suppressions
}

func NewScanner(rules []Rule, config ScanConfig) *Scanner {
	return &Scanner{
		rules:  rules,
		config: config,
	}
}

func (s *Scanner) Scan() (*Result, error) {
	start := time.Now()
	result := &Result{
		Findings: []Finding{},
		Target:   strings.Join(s.config.Paths, ", "),
	}

	// Collect files
	files, err := s.collectFiles()
	if err != nil {
		return nil, err
	}
	result.FilesScanned = len(files)

	// Parse suppression comments for all files before scanning
	if s.config.Suppressions != nil {
		for _, f := range files {
			s.config.Suppressions.ParseFile(f)
		}
	}

	// Filter rules by language
	activeRules := s.filterRules()
	result.RulesRun = len(activeRules)

	// Scan files concurrently
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // max 20 concurrent files

	for _, file := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(f string) {
			defer wg.Done()
			defer func() { <-sem }()

			findings, err := s.scanFile(f, activeRules)
			if err != nil {
				return
			}
			mu.Lock()
			result.Findings = append(result.Findings, findings...)
			mu.Unlock()
		}(file)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	// Deduplicate findings (same file + line + rule_id)
	result.Findings = deduplicate(result.Findings)

	// Apply baseline diff if configured
	if s.config.Baseline != nil {
		records := findingsToRecords(result.Findings)
		diff := s.config.Baseline.Diff(records)
		result.NewFindings = recordsToFindings(diff.NewRecords, result.Findings)
		result.BaselineFindings = recordsToFindings(diff.BaselineRecords, result.Findings)
		result.Findings = recordsToFindings(diff.AllRecords, result.Findings)
	}

	return result, nil
}

func findingsToRecords(findings []Finding) []baseline.Record {
	records := make([]baseline.Record, len(findings))
	for i, f := range findings {
		records[i] = baseline.Record{
			RuleID:      f.RuleID,
			File:        f.File,
			Line:        f.Line,
			Column:      f.Column,
			SnippetHash: baseline.HashSnippet(f.Snippet),
			RuleName:    f.RuleName,
			Severity:    string(f.Severity),
			Snippet:     f.Snippet,
		}
	}
	return records
}

func recordsToFindings(records []baseline.Record, source []Finding) []Finding {
	findings := make([]Finding, len(records))
	for i, r := range records {
		// Try to find full finding from source to preserve all fields
		findings[i] = Finding{
			RuleID:    r.RuleID,
			RuleName:  r.RuleName,
			Severity:  Severity(r.Severity),
			File:      r.File,
			Line:      r.Line,
			Column:    r.Column,
			Snippet:   r.Snippet,
		}
		// Enrich from source if exact match exists
		for _, f := range source {
			if f.RuleID == r.RuleID && f.File == r.File && f.Line == r.Line && f.Column == r.Column {
				findings[i] = f
				break
			}
		}
	}
	return findings
}

func deduplicate(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding
	for _, f := range findings {
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.RuleID)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}
	return unique
}

func (s *Scanner) collectFiles() ([]string, error) {
	var files []string

	for _, root := range s.config.Paths {
		err := utils.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip errors
			}
			if info.IsDir() {
				if s.isExcluded(path) {
					return filepath.SkipDir
				}
				return nil
			}
			if s.isExcluded(path) {
				return nil
			}
			if !s.hasSupportedExtension(path) {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return files, nil
}

func (s *Scanner) isExcluded(path string) bool {
	// Common auto-exclude patterns for test files, vendors, etc.
	autoExclude := []string{
		"_test.go", "_test.py", "_test.js", "_test.ts",
		"test_", "spec.", "mock", "fixture", "example",
		"node_modules", "vendor", "dist", "build", ".git",
		"*.min.js", "*.min.css", "*.bundle.js",
	}

	allPatterns := append(s.config.Exclude, autoExclude...)

	for _, pattern := range allPatterns {
		matched, _ := filepath.Match(pattern, filepath.Base(path))
		if matched {
			return true
		}
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

func (s *Scanner) hasSupportedExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	supported := []string{
		".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
		".py", ".pyw",
		".go",
		".php", ".phtml",
		".rs",
		".java", ".kt",
		".rb",
		".swift",
	}
	for _, s := range supported {
		if ext == s {
			return true
		}
	}
	// Also support files without extension that look like scripts
	if ext == "" {
		base := filepath.Base(path)
		for _, name := range []string{"Dockerfile", "Makefile", "nginx.conf", ".env"} {
			if strings.EqualFold(base, name) {
				return true
			}
		}
	}
	return false
}

func (s *Scanner) filterRules() []Rule {
	var filtered []Rule

	for _, rule := range s.rules {
		// Filter by confidence
		if !s.meetsConfidence(rule.Confidence) {
			continue
		}

		// Filter by severity
		if SeverityRank(rule.Severity) < SeverityRank(s.config.MinSeverity) {
			continue
		}

		// Filter by framework (if rule is framework-specific)
		if len(rule.Frameworks) > 0 {
			if !s.hasAnyFramework(rule.Frameworks) {
				continue
			}
		}

		filtered = append(filtered, rule)
	}

	return filtered
}

func (s *Scanner) hasAnyFramework(frameworks []string) bool {
	for _, fw := range frameworks {
		for _, detected := range s.config.Frameworks {
			if strings.EqualFold(fw, detected) {
				return true
			}
		}
	}
	return false
}

func (s *Scanner) meetsConfidence(conf string) bool {
	levels := map[string]int{"low": 1, "medium": 2, "high": 3}
	required := levels[s.config.Confidence]
	actual := levels[conf]
	return actual >= required
}

func (s *Scanner) scanFile(path string, rules []Rule) ([]Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lang := DetectLanguage(path)
	var findings []Finding

	// Phase 1: Regex-based scanning
	for _, rule := range rules {
		// Skip if rule doesn't apply to this language
		if len(rule.Languages) > 0 && !contains(rule.Languages, lang) && !contains(rule.Languages, "*") {
			continue
		}

		for _, pattern := range rule.Patterns {
			// Skip AST-only patterns in regex phase
			if pattern.Type == "ast-query" || pattern.Type == "taint" {
				continue
			}

			var matches []findingMatch

			switch pattern.Type {
			case "regex":
				matches = s.matchRegex(content, pattern.Pattern, path)
			case "literal":
				matches = s.matchLiteral(content, pattern.Pattern, path)
			}

			for _, m := range matches {
				finding := Finding{
					RuleID:       rule.ID,
					RuleName:     rule.Name,
					Severity:     rule.Severity,
					Category:     rule.Category,
					Message:      rule.Message,
					File:         path,
					Line:         m.line,
					Column:       m.column,
					Snippet:      m.snippet,
					Fix:          rule.Fix,
					FixAvailable: rule.Fix != nil,
					References:   rule.References,
					Confidence:   rule.Confidence,
				}
				findings = append(findings, finding)
			}
		}
	}

	// Phase 2: AST-based scanning (for supported languages)
	if ast.IsSupported(path) {
		pf, err := ast.Parse(path)
		if err == nil {
			defer pf.Close()

			// 2a: AST query rules
			for _, rule := range rules {
				if len(rule.Languages) > 0 && !contains(rule.Languages, lang) && !contains(rule.Languages, "*") {
					continue
				}
				if len(rule.Frameworks) > 0 && !s.hasAnyFramework(rule.Frameworks) {
					continue
				}

				for _, pattern := range rule.Patterns {
					if pattern.Type != "ast-query" {
						continue
					}

					queryStr := pattern.Query
					if queryStr == "" {
						queryStr = pattern.Pattern
					}

					matches, err := ast.Query(pf, queryStr)
					if err != nil {
						continue
					}

					for _, match := range matches {
						var primaryNode *ast.Capture
						for _, c := range match.Captures {
							if c.Name == "vuln" || c.Name == "sink" || c.Name == "danger" {
								primaryNode = &c
								break
							}
						}
						if primaryNode == nil && len(match.Captures) > 0 {
							primaryNode = &match.Captures[0]
						}
						if primaryNode == nil {
							continue
						}

						node := primaryNode.Node
						start := node.StartPoint()
						findings = append(findings, Finding{
							RuleID:       rule.ID,
							RuleName:     rule.Name,
							Severity:     rule.Severity,
							Category:     rule.Category,
							Message:      strings.TrimSpace(rule.Message),
							File:         path,
							Line:         int(start.Row) + 1,
							Column:       int(start.Column) + 1,
							Snippet:      extractSnippet(pf.Source, node),
							Confidence:   rule.Confidence,
							References:   rule.References,
							Fix:          rule.Fix,
							FixAvailable: rule.Fix != nil,
						})
					}
				}
			}

			// 2b: Taint analysis
			langName := lang
			if langName == "typescript" {
				langName = "javascript"
			}
			tracker := taint.NewTracker(langName)
			taintRules := convertRulesToTaint(rules)
			taintFindings, err := tracker.ScanFile(path, taintRules)
			if err == nil {
				for _, f := range taintFindings {
					findings = append(findings, Finding{
						RuleID:       f.RuleID,
						RuleName:     f.RuleName,
						Severity:     Severity(f.Severity),
						Category:     f.Category,
						Message:      f.Message,
						File:         path,
						Line:         f.Line,
						Column:       f.Column,
						Snippet:      f.Snippet,
						Confidence:   f.Confidence,
						References:   f.References,
					})
				}
			}
		}
	}

	// Filter out suppressed findings
	if s.config.Suppressions != nil {
		var filtered []Finding
		for _, f := range findings {
			if !s.config.Suppressions.IsSuppressed(f.File, f.Line, f.RuleID) {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	return findings, nil
}

type findingMatch struct {
	line    int
	column  int
	snippet string
}

func (s *Scanner) matchRegex(content []byte, pattern string, path string) []findingMatch {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	var matches []findingMatch
	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		loc := re.FindIndex(line)
		if loc == nil {
			continue
		}

		snippet := string(line)
		if len(snippet) > 120 {
			// Truncate but keep the match visible
			start := max(0, loc[0]-40)
			end := min(len(snippet), loc[1]+40)
			snippet = snippet[start:end]
			if start > 0 {
				snippet = "..." + snippet
			}
			if end < len(string(line)) {
				snippet = snippet + "..."
			}
		}

		matches = append(matches, findingMatch{
			line:    i + 1,
			column:  loc[0] + 1,
			snippet:  snippet,
		})
	}

	return matches
}

func (s *Scanner) matchLiteral(content []byte, pattern string, path string) []findingMatch {
	return s.matchRegex(content, regexp.QuoteMeta(pattern), path)
}

func DetectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".py", ".pyw":
		return "python"
	case ".go":
		return "go"
	case ".php", ".phtml":
		return "php"
	case ".rs":
		return "rust"
	case ".java":
		return "java"
	case ".kt":
		return "kotlin"
	case ".rb":
		return "ruby"
	case ".swift":
		return "swift"
	default:
		return ""
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func convertRulesToTaint(rules []Rule) []taint.RuleInfo {
	var result []taint.RuleInfo
	for _, r := range rules {
		var patterns []taint.RulePattern
		for _, p := range r.Patterns {
			patterns = append(patterns, taint.RulePattern{
				Type:    p.Type,
				Pattern: p.Pattern,
				Sources: p.Sources,
				Sinks:   p.Sinks,
			})
		}
		result = append(result, taint.RuleInfo{
			ID:         r.ID,
			Name:       r.Name,
			Severity:   string(r.Severity),
			Category:   r.Category,
			Message:    r.Message,
			Confidence: r.Confidence,
			References: r.References,
			Languages:  r.Languages,
			Frameworks: r.Frameworks,
			Patterns:   patterns,
		})
	}
	return result
}

func extractSnippet(source []byte, node interface{ StartByte() uint32; EndByte() uint32 }) string {
	start := node.StartByte()
	end := node.EndByte()
	if start >= uint32(len(source)) {
		return ""
	}
	if end > uint32(len(source)) {
		end = uint32(len(source))
	}
	snippet := string(source[start:end])
	lines := strings.Split(snippet, "\n")
	if len(lines) > 3 {
		return strings.Join(lines[:3], "\n") + "..."
	}
	return snippet
}

// FixApplier applies auto-fixes to files
type FixApplier struct {
	DryRun bool
}

func (fa *FixApplier) Apply(finding Finding) (string, error) {
	if finding.Fix == nil {
		return "", fmt.Errorf("no fix available")
	}

	content, err := os.ReadFile(finding.File)
	if err != nil {
		return "", err
	}

	re, err := regexp.Compile(finding.Fix.Pattern)
	if err != nil {
		return "", fmt.Errorf("invalid fix pattern: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	if finding.Line < 1 || finding.Line > len(lines) {
		return "", fmt.Errorf("line %d out of range", finding.Line)
	}

	line := lines[finding.Line-1]
	fixed := re.ReplaceAllString(line, finding.Fix.Replace)

	if fixed == line {
		return "", fmt.Errorf("fix pattern did not match on line %d", finding.Line)
	}

	if fa.DryRun {
		return fixed, nil
	}

	// Handle multi-line replacements
	if strings.Contains(fixed, "\n") {
		newLines := strings.Split(fixed, "\n")
		// Replace the original line with first new line, insert rest after
		lines[finding.Line-1] = newLines[0]
		for i := len(newLines) - 1; i > 0; i-- {
			lines = append(lines[:finding.Line], append([]string{newLines[i]}, lines[finding.Line:]...)...)
		}
	} else {
		lines[finding.Line-1] = fixed
	}

	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(finding.File, []byte(newContent), 0644); err != nil {
		return "", err
	}

	return fixed, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
