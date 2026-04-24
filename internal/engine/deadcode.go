package engine

import (
	"regexp"
	"strings"
)

// IsDeadCode detects if the given line is in unreachable/dead code
func IsDeadCode(content []byte, line int, lang string) bool {
	regions := findDeadCodeRegions(content, lang)
	for _, r := range regions {
		if line >= r[0] && line <= r[1] {
			return true
		}
	}
	return false
}

// findDeadCodeRegions returns all dead code line ranges
func findDeadCodeRegions(content []byte, lang string) [][2]int {
	var regions [][2]int
	lines := strings.Split(string(content), "\n")

	// Find code after return/break/continue/throw
	inDeadBlock := false
	blockStart := 0
	braceDepth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track brace depth
		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

		// Check for control flow statements
		controlFlow := regexp.MustCompile(`^\s*(return|break|continue|throw|goto)\b`)
		if controlFlow.MatchString(line) && !strings.HasSuffix(trimmed, "...") {
			if !inDeadBlock && braceDepth > 0 {
				inDeadBlock = true
				blockStart = i + 2 // Next line after return
			}
		}

		// End of block resets
		if trimmed == "}" && inDeadBlock && braceDepth <= 0 {
			if i >= blockStart {
				regions = append(regions, [2]int{blockStart, i})
			}
			inDeadBlock = false
			braceDepth = 0
		}
	}

	// Find commented-out code blocks (2+ consecutive commented lines that look like code)
	consecutiveComments := 0
	commentStart := 0
	codeLikeComment := regexp.MustCompile(`^\s*(//|#)\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[=(.]`)

	for i, line := range lines {
		if codeLikeComment.MatchString(line) {
			if consecutiveComments == 0 {
				commentStart = i
			}
			consecutiveComments++
		} else {
			if consecutiveComments >= 2 {
				regions = append(regions, [2]int{commentStart, i - 1})
			}
			consecutiveComments = 0
		}
	}
	if consecutiveComments >= 2 {
		regions = append(regions, [2]int{commentStart, len(lines) - 1})
	}

	return regions
}
