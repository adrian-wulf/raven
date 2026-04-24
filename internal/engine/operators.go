package engine

import (
	"regexp"
	"strings"
)

// RuleOperator defines Semgrep-style pattern operators
type RuleOperator struct {
	Pattern        string   `yaml:"pattern,omitempty"`          // Match pattern
	PatternEither  []string `yaml:"pattern-either,omitempty"`   // OR - match any
	PatternNot     string   `yaml:"pattern-not,omitempty"`      // Exclude matches
	PatternInside  string   `yaml:"pattern-inside,omitempty"`   // Only match inside context
	PatternNotInside string `yaml:"pattern-not-inside,omitempty"` // Exclude inside context
	Regex          string   `yaml:"regex,omitempty"`            // Regex pattern
	NotRegex       string   `yaml:"not-regex,omitempty"`        // Exclude regex
}

// OperatorMatcher executes Semgrep-style operators against code
type OperatorMatcher struct {
	content  string
	language string
	operators RuleOperator
}

// NewOperatorMatcher creates a new operator matcher
func NewOperatorMatcher(content string, language string, ops RuleOperator) *OperatorMatcher {
	return &OperatorMatcher{
		content:   content,
		language:  language,
		operators: ops,
	}
}

// Match executes all operators and returns matches
func (om *OperatorMatcher) Match() []OperatorMatch {
	var matches []OperatorMatch

	// Handle pattern-either (OR logic)
	if len(om.operators.PatternEither) > 0 {
		for _, pattern := range om.operators.PatternEither {
			if locs := om.findPattern(pattern); len(locs) > 0 {
				for _, loc := range locs {
					matches = append(matches, OperatorMatch{
						Pattern:   pattern,
						Line:      loc.Line,
						Column:    loc.Column,
						MatchText: loc.Text,
					})
				}
			}
		}
	} else if om.operators.Pattern != "" {
		// Single pattern
		if locs := om.findPattern(om.operators.Pattern); len(locs) > 0 {
			for _, loc := range locs {
				matches = append(matches, OperatorMatch{
					Pattern:   om.operators.Pattern,
					Line:      loc.Line,
					Column:    loc.Column,
					MatchText: loc.Text,
				})
			}
		}
	}

	// Handle regex
	if om.operators.Regex != "" {
		if locs := om.findRegex(om.operators.Regex); len(locs) > 0 {
			for _, loc := range locs {
				matches = append(matches, OperatorMatch{
					Pattern:   om.operators.Regex,
					Line:      loc.Line,
					Column:    loc.Column,
					MatchText: loc.Text,
				})
			}
		}
	}

	// Apply pattern-not (exclude)
	if om.operators.PatternNot != "" {
		matches = om.excludePattern(matches, om.operators.PatternNot)
	}

	// Apply pattern-not-inside (exclude context)
	if om.operators.PatternNotInside != "" {
		matches = om.excludeInside(matches, om.operators.PatternNotInside)
	}

	// Apply pattern-inside (require context)
	if om.operators.PatternInside != "" {
		matches = om.requireInside(matches, om.operators.PatternInside)
	}

	// Apply not-regex (exclude)
	if om.operators.NotRegex != "" {
		matches = om.excludeRegex(matches, om.operators.NotRegex)
	}

	return matches
}

// OperatorMatch represents a single match
type OperatorMatch struct {
	Pattern   string
	Line      int
	Column    int
	MatchText string
}

// patternLocation holds match location
type patternLocation struct {
	Line   int
	Column int
	Text   string
}

// findPattern finds all occurrences of a literal pattern
func (om *OperatorMatcher) findPattern(pattern string) []patternLocation {
	var locs []patternLocation
	lines := strings.Split(om.content, "\n")

	for i, line := range lines {
		if idx := strings.Index(line, pattern); idx >= 0 {
			locs = append(locs, patternLocation{
				Line:   i + 1,
				Column: idx + 1,
				Text:   pattern,
			})
		}
	}
	return locs
}

// findRegex finds all regex matches
func (om *OperatorMatcher) findRegex(rx string) []patternLocation {
	var locs []patternLocation
	re, err := regexp.Compile(rx)
	if err != nil {
		return locs
	}

	lines := strings.Split(om.content, "\n")
	for i, line := range lines {
		if locs2 := re.FindStringIndex(line); locs2 != nil {
			locs = append(locs, patternLocation{
				Line:   i + 1,
				Column: locs2[0] + 1,
				Text:   line[locs2[0]:locs2[1]],
			})
		}
	}
	return locs
}

// excludePattern removes matches that contain the exclude pattern
func (om *OperatorMatcher) excludePattern(matches []OperatorMatch, exclude string) []OperatorMatch {
	var filtered []OperatorMatch
	for _, m := range matches {
		// Check if the line containing this match has the exclude pattern
		lines := strings.Split(om.content, "\n")
		if m.Line > 0 && m.Line <= len(lines) {
			if !strings.Contains(lines[m.Line-1], exclude) {
				filtered = append(filtered, m)
			}
		}
	}
	return filtered
}

// excludeInside removes matches inside the given context pattern
func (om *OperatorMatcher) excludeInside(matches []OperatorMatch, context string) []OperatorMatch {
	ctxLocs := om.findPattern(context)
	if len(ctxLocs) == 0 {
		return matches // Context not found, nothing to exclude
	}

	var filtered []OperatorMatch
	for _, m := range matches {
		inside := false
		for _, ctx := range ctxLocs {
			if m.Line >= ctx.Line && m.Line <= ctx.Line+20 { // Within 20 lines of context
				inside = true
				break
			}
		}
		if !inside {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

// requireInside keeps only matches inside the given context pattern
func (om *OperatorMatcher) requireInside(matches []OperatorMatch, context string) []OperatorMatch {
	ctxLocs := om.findPattern(context)
	if len(ctxLocs) == 0 {
		return nil // Context not found, no matches
	}

	var filtered []OperatorMatch
	for _, m := range matches {
		for _, ctx := range ctxLocs {
			if m.Line >= ctx.Line && m.Line <= ctx.Line+20 {
				filtered = append(filtered, m)
				break
			}
		}
	}
	return filtered
}

// excludeRegex removes matches that match the exclude regex
func (om *OperatorMatcher) excludeRegex(matches []OperatorMatch, excludeRx string) []OperatorMatch {
	re, err := regexp.Compile(excludeRx)
	if err != nil {
		return matches
	}

	var filtered []OperatorMatch
	lines := strings.Split(om.content, "\n")
	for _, m := range matches {
		if m.Line > 0 && m.Line <= len(lines) {
			if !re.MatchString(lines[m.Line-1]) {
				filtered = append(filtered, m)
			}
		}
	}
	return filtered
}

// MetavariableRegex implements metavariable-regex operator
// It captures named groups from regex and validates them
func MetavariableRegex(content string, pattern string, metavariable string, validationRegex string) []patternLocation {
	var locs []patternLocation
	re, err := regexp.Compile(pattern)
	if err != nil {
		return locs
	}
	valRe, err := regexp.Compile(validationRegex)
	if err != nil {
		return locs
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		matches := re.FindStringSubmatchIndex(line)
		if matches == nil {
			continue
		}

		// Extract named captures
		names := re.SubexpNames()
		for j, name := range names {
			if name == metavariable && j < len(matches)/2 {
				start := matches[j*2]
				end := matches[j*2+1]
				if start >= 0 && end > start {
					value := line[start:end]
					if valRe.MatchString(value) {
						locs = append(locs, patternLocation{
							Line:   i + 1,
							Column: start + 1,
							Text:   value,
						})
					}
				}
			}
		}
	}
	return locs
}
