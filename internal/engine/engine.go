package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/raven-security/raven/internal/ast"
	"github.com/raven-security/raven/internal/baseline"
	"github.com/raven-security/raven/internal/cache"
	"github.com/raven-security/raven/internal/suppress"
	"github.com/raven-security/raven/internal/taint"
	"github.com/raven-security/raven/internal/taint/crossfile"
	"github.com/raven-security/raven/internal/utils"
)

type Scanner struct {
	rules    []Rule
	config   ScanConfig
	regexCache map[string]*regexp.Regexp
}

type ScanConfig struct {
	Paths        []string
	Exclude      []string
	Languages    []string
	Frameworks   []string
	Confidence   string
	MinSeverity  Severity
	Baseline     *baseline.Baseline   // optional baseline for diff scanning
	Suppressions *suppress.Map        // optional inline comment suppressions
	Resolver     *crossfile.Resolver  // optional cross-file taint resolver
	Cache        *cache.Cache         // optional file hash cache
}

func NewScanner(rules []Rule, config ScanConfig) *Scanner {
	return &Scanner{
		rules:      rules,
		config:     config,
		regexCache: make(map[string]*regexp.Regexp),
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
		// Check cache first
		if s.config.Cache != nil && s.config.Cache.IsFresh(file) {
			cached := s.config.Cache.Get(file)
			var cachedFindings []Finding
			json.Unmarshal(cached, &cachedFindings)
			mu.Lock()
			result.Findings = append(result.Findings, cachedFindings...)
			mu.Unlock()
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(f string) {
			defer wg.Done()
			defer func() { <-sem }()

			findings, err := s.scanFile(f, activeRules)
			if err != nil {
				return
			}
			if s.config.Cache != nil {
				cachedData, _ := json.Marshal(findings)
				s.config.Cache.Store(f, cachedData)
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
		".cs",
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
				message := rule.Message
				fix := rule.Fix
				if len(m.metavars) > 0 {
					message = expandMetavars(message, m.metavars)
					if fix != nil {
						fixCopy := *fix
						fixCopy.Pattern = expandMetavars(fixCopy.Pattern, m.metavars)
						fixCopy.Replace = expandMetavars(fixCopy.Replace, m.metavars)
						fixCopy.Description = expandMetavars(fixCopy.Description, m.metavars)
						fix = &fixCopy
					}
				}

				finding := Finding{
					RuleID:       rule.ID,
					RuleName:     rule.Name,
					Severity:     rule.Severity,
					Category:     rule.Category,
					Message:      message,
					File:         path,
					Line:         m.line,
					Column:       m.column,
					Snippet:      m.snippet,
					Fix:          fix,
					FixAvailable: fix != nil,
					References:   rule.References,
					Confidence:   rule.Confidence,
					Metavars:     m.metavars,
				}

				// Apply where clauses
				if !s.matchesWhere(finding, pattern.Where, content) {
					continue
				}

				// Apply inside/not-inside patterns
				if !s.matchesContext(content, pattern.Inside, pattern.NotInside) {
					continue
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
						metavars := make(map[string]string)
						for _, c := range match.Captures {
							if c.Name == "vuln" || c.Name == "sink" || c.Name == "danger" {
								primaryNode = &c
							}
							metavars[c.Name] = extractSnippet(pf.Source, c.Node)
						}
						if primaryNode == nil && len(match.Captures) > 0 {
							primaryNode = &match.Captures[0]
						}
						if primaryNode == nil {
							continue
						}

						node := primaryNode.Node
						start := node.StartPoint()
						snippet := extractSnippet(pf.Source, node)

						message := expandMetavars(rule.Message, metavars)
						fix := rule.Fix
						if fix != nil {
							fixCopy := *fix
							fixCopy.Pattern = expandMetavars(fixCopy.Pattern, metavars)
							fixCopy.Replace = expandMetavars(fixCopy.Replace, metavars)
							fixCopy.Description = expandMetavars(fixCopy.Description, metavars)
							fix = &fixCopy
						}

						finding := Finding{
							RuleID:       rule.ID,
							RuleName:     rule.Name,
							Severity:     rule.Severity,
							Category:     rule.Category,
							Message:      strings.TrimSpace(message),
							File:         path,
							Line:         int(start.Row) + 1,
							Column:       int(start.Column) + 1,
							Snippet:      snippet,
							Confidence:   rule.Confidence,
							References:   rule.References,
							Fix:          fix,
							FixAvailable: fix != nil,
							Metavars:     metavars,
						}

						if !s.matchesWhere(finding, pattern.Where, content) {
							continue
						}
						if !s.matchesContext(content, pattern.Inside, pattern.NotInside) {
							continue
						}

						findings = append(findings, finding)
					}
				}
			}

			// 2b: Taint analysis
			langName := lang
			if langName == "typescript" {
				langName = "javascript"
			}
			tracker := taint.NewTracker(langName)
				if s.config.Resolver != nil {
					tracker.SetResolver(s.config.Resolver)
				}
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
	line     int
	column   int
	snippet  string
	metavars map[string]string
}

func (s *Scanner) matchRegex(content []byte, pattern string, path string) []findingMatch {
	if s.regexCache == nil {
		s.regexCache = make(map[string]*regexp.Regexp)
	}
	re, ok := s.regexCache[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return nil
		}
		s.regexCache[pattern] = re
	}

	var matches []findingMatch
	lines := bytes.Split(content, []byte("\n"))
	subexpNames := re.SubexpNames()

	for i, line := range lines {
		loc := re.FindIndex(line)
		if loc == nil {
			continue
		}

		snippet := string(line)
		if len(snippet) > 120 {
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

		// Extract named capture groups
		metavars := make(map[string]string)
		if len(subexpNames) > 1 {
			matchLocs := re.FindSubmatchIndex(line)
			if matchLocs != nil {
				for j, name := range subexpNames {
					if j == 0 || name == "" {
						continue
					}
					startIdx := matchLocs[2*j]
					endIdx := matchLocs[2*j+1]
					if startIdx >= 0 && endIdx >= 0 && endIdx <= len(line) {
						metavars[name] = string(line[startIdx:endIdx])
					}
				}
			}
		}

		matches = append(matches, findingMatch{
			line:     i + 1,
			column:   loc[0] + 1,
			snippet:  snippet,
			metavars: metavars,
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
	case ".cs":
		return "csharp"
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

// expandMetavars replaces $var and ${var} placeholders with values from metavars
func expandMetavars(template string, metavars map[string]string) string {
	result := template
	for name, value := range metavars {
		result = strings.ReplaceAll(result, "${"+name+"}", value)
		result = strings.ReplaceAll(result, "$"+name, value)
	}
	return result
}

// matchesWhere checks if a finding passes all where clauses
func (s *Scanner) matchesWhere(finding Finding, where []WhereClause, content []byte) bool {
	for _, clause := range where {
		if clause.NotConstant {
			// Check if the matched snippet looks like a constant (no variables, no function calls)
			if isConstant(string(content), finding.Snippet) {
				return false
			}
		}
		if len(clause.NotSanitized) > 0 {
			// Check if any sanitizer is called on the tainted data near this line
			if isSanitized(string(content), finding.Line, clause.NotSanitized) {
				return false
			}
		}
		if clause.NotTestFile {
			if strings.Contains(finding.File, "_test.") || strings.Contains(finding.File, "_spec.") ||
				strings.Contains(finding.File, "/test/") || strings.Contains(finding.File, "/tests/") {
				return false
			}
		}
		if clause.InsideFunction != "" {
			if !isInsideFunction(string(content), finding.Line, clause.InsideFunction) {
				return false
			}
		}
	}
	return true
}

// matchesContext checks inside/not-inside patterns against file content
func (s *Scanner) matchesContext(content []byte, inside, notInside *Pattern) bool {
	if inside != nil {
		var matched bool
		switch inside.Type {
		case "regex":
			re, err := regexp.Compile(inside.Pattern)
			if err == nil && !re.Match(content) {
				return false
			}
			matched = true
		case "literal":
			matched = bytes.Contains(content, []byte(inside.Pattern))
		}
		if !matched {
			return false
		}
	}
	if notInside != nil {
		switch notInside.Type {
		case "regex":
			re, err := regexp.Compile(notInside.Pattern)
			if err == nil && re.Match(content) {
				return false
			}
		case "literal":
			if bytes.Contains(content, []byte(notInside.Pattern)) {
				return false
			}
		}
	}
	return true
}

// isConstant checks if a snippet appears to be a constant value
func isConstant(content, snippet string) bool {
	trimmed := strings.TrimSpace(snippet)
	// If it's just a string literal, number, or boolean, it's constant
	if strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`) {
		return true
	}
	if strings.HasPrefix(trimmed, `'`) && strings.HasSuffix(trimmed, `'`) {
		return true
	}
	if strings.HasPrefix(trimmed, "`") && strings.HasSuffix(trimmed, "`") {
		return true
	}
	// Check for numeric constants
	if regexp.MustCompile(`^\d+$`).MatchString(trimmed) {
		return true
	}
	return false
}

// isSanitized checks if any sanitizer is called near the given line
func isSanitized(content string, lineNum int, sanitizers []string) bool {
	lines := strings.Split(content, "\n")
	start := max(0, lineNum-5)
	end := min(len(lines), lineNum+2)
	for i := start; i < end; i++ {
		for _, san := range sanitizers {
			if strings.Contains(lines[i], san) {
				return true
			}
		}
	}
	return false
}

// isInsideFunction checks if a line is inside a function matching the pattern
func isInsideFunction(content string, lineNum int, funcPattern string) bool {
	lines := strings.Split(content, "\n")
	// Scan backwards from the line to find function definition
	for i := lineNum - 2; i >= 0 && i >= lineNum-20; i-- {
		re, err := regexp.Compile(funcPattern)
		if err == nil && re.MatchString(lines[i]) {
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
