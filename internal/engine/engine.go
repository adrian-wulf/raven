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
)

type Scanner struct {
	rules   []Rule
	config  ScanConfig
}

type ScanConfig struct {
	Paths      []string
	Exclude    []string
	Languages  []string
	Confidence string
	MinSeverity Severity
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

	return result, nil
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
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
	for _, pattern := range s.config.Exclude {
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

		filtered = append(filtered, rule)
	}

	return filtered
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

	lang := detectLanguage(path)
	var findings []Finding

	for _, rule := range rules {
		// Skip if rule doesn't apply to this language
		if len(rule.Languages) > 0 && !contains(rule.Languages, lang) && !contains(rule.Languages, "*") {
			continue
		}

		for _, pattern := range rule.Patterns {
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

func detectLanguage(path string) string {
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

	// Find the specific line and apply fix
	lines := strings.Split(string(content), "\n")
	if finding.Line < 1 || finding.Line > len(lines) {
		return "", fmt.Errorf("line %d out of range", finding.Line)
	}

	line := lines[finding.Line-1]
	fixed := re.ReplaceAllString(line, finding.Fix.Replace)

	if fixed == line {
		return "", fmt.Errorf("fix pattern did not match")
	}

	if fa.DryRun {
		return fixed, nil
	}

	lines[finding.Line-1] = fixed
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
