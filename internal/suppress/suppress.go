package suppress

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	// Matches: // raven-ignore: RULE1, RULE2
	//          # raven-ignore: RULE1, RULE2
	//          /* raven-ignore: RULE1 */
	ignorePattern = regexp.MustCompile(`(?i)\braven-ignore\s*:\s*([\w\-,\s]+)`)

	// Matches: // raven-ignore-next-line or // raven-ignore-next-line: RULE1
	ignoreNextPattern = regexp.MustCompile(`(?i)\braven-ignore-next-line(?:\s*:\s*([\w\-,\s]+))?`)
)

// Entry represents suppression rules for a specific line in a file.
type Entry struct {
	Line      int
	Rules     []string // empty = all rules suppressed
	NextLine  bool     // applies to the next line instead of current
	Reason    string   // optional reason after -- or #
}

// Map holds all suppressions indexed by file path.
type Map struct {
	entries map[string][]Entry // file -> entries
}

// NewMap creates an empty suppression map.
func NewMap() *Map {
	return &Map{entries: make(map[string][]Entry)}
}

// ParseFile scans a source file for raven-ignore comments.
func (m *Map) ParseFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if entries := parseLine(line, lineNum); len(entries) > 0 {
			m.entries[path] = append(m.entries[path], entries...)
		}
	}
	return scanner.Err()
}

// IsSuppressed checks if a finding at (file, line) for ruleID is suppressed.
func (m *Map) IsSuppressed(file string, line int, ruleID string) bool {
	for _, e := range m.entries[file] {
		if !e.NextLine && e.Line != line {
			continue
		}
		if e.NextLine && e.Line != line-1 {
			continue
		}
		// Empty rules list means suppress all
		if len(e.Rules) == 0 {
			return true
		}
		for _, r := range e.Rules {
			if strings.EqualFold(r, ruleID) {
				return true
			}
		}
	}
	return false
}

// Count returns total number of suppression entries.
func (m *Map) Count() int {
	total := 0
	for _, entries := range m.entries {
		total += len(entries)
	}
	return total
}

// parseLine extracts suppression entries from a single source line.
func parseLine(line string, lineNum int) []Entry {
	var entries []Entry

	// Extract comment text from common comment formats
	comment := extractComment(line)
	if comment == "" {
		return entries
	}

	// raven-ignore-next-line
	if matches := ignoreNextPattern.FindStringSubmatch(comment); matches != nil {
		e := Entry{Line: lineNum, NextLine: true}
		if matches[1] != "" {
			e.Rules = parseRuleList(matches[1])
		}
		entries = append(entries, e)
	}

	// raven-ignore (current line)
	if matches := ignorePattern.FindStringSubmatch(comment); matches != nil {
		e := Entry{Line: lineNum, Rules: parseRuleList(matches[1])}
		entries = append(entries, e)
	}

	return entries
}

// extractComment pulls the comment text from a source line.
func extractComment(line string) string {
	line = strings.TrimSpace(line)

	// Single-line comments: // or #
	if idx := strings.Index(line, "//"); idx >= 0 {
		return strings.TrimSpace(line[idx+2:])
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		return strings.TrimSpace(line[idx+1:])
	}

	// Multi-line comments: /* ... */
	if strings.HasPrefix(line, "/*") && strings.HasSuffix(line, "*/") {
		inner := line[2 : len(line)-2]
		return strings.TrimSpace(inner)
	}

	return ""
}

// parseRuleList splits a comma-separated list of rule IDs.
func parseRuleList(s string) []string {
	var rules []string
	for _, part := range strings.Split(s, ",") {
		r := strings.TrimSpace(part)
		if r != "" {
			rules = append(rules, r)
		}
	}
	return rules
}
