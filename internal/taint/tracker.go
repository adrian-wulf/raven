package taint

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/raven-security/raven/internal/ast"
)

// Finding represents a taint analysis finding
type Finding struct {
	RuleID     string
	RuleName   string
	Severity   string
	Category   string
	Message    string
	File       string
	Line       int
	Column     int
	Snippet    string
	Confidence string
	References []string
}

// RulePattern represents a taint pattern from a rule
type RulePattern struct {
	Type    string
	Pattern string
	Sources []string
	Sinks   []string
}

// Tracker performs intra-procedural taint analysis
type Tracker struct {
	config      LanguageConfig
	currentFile string
}

// NewTracker creates a taint tracker for the given language
func NewTracker(language string) *Tracker {
	config, ok := DefaultConfigs[language]
	if !ok {
		config = LanguageConfig{}
	}
	return &Tracker{config: config}
}

// ScanFile analyzes a file for taint vulnerabilities
func (t *Tracker) ScanFile(path string, rules []RuleInfo) ([]Finding, error) {
	t.currentFile = path
	if !ast.IsSupported(path) {
		return nil, nil
	}

	pf, err := ast.Parse(path)
	if err != nil {
		return nil, err
	}
	defer pf.Close()

	var findings []Finding

	// Process each taint rule
	for _, rule := range rules {
		if !t.appliesToRule(rule) {
			continue
		}

		ruleFindings := t.analyzeRule(pf, rule)
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}

// RuleInfo holds rule metadata for taint analysis
type RuleInfo struct {
	ID         string
	Name       string
	Severity   string
	Category   string
	Message    string
	Confidence string
	References []string
	Languages  []string
	Frameworks []string
	Patterns   []RulePattern
}

func (t *Tracker) appliesToRule(rule RuleInfo) bool {
	for _, p := range rule.Patterns {
		if p.Type == "taint" {
			return true
		}
	}
	return false
}

func (t *Tracker) analyzeRule(pf *ast.ParsedFile, rule RuleInfo) []Finding {
	var findings []Finding

	// Collect sources and sinks from all taint patterns in the rule
	var sources, sinks []string
	for _, p := range rule.Patterns {
		if p.Type != "taint" {
			continue
		}
		sources = append(sources, p.Sources...)
		sinks = append(sinks, p.Sinks...)
	}

	// Use default config sources/sinks if rule doesn't specify any
	if len(sources) == 0 {
		for _, s := range t.config.Sources {
			sources = append(sources, s.Pattern)
		}
	}
	if len(sinks) == 0 {
		for _, s := range t.config.Sinks {
			sinks = append(sinks, s.Pattern)
		}
	}
	if len(sources) == 0 || len(sinks) == 0 {
		return nil
	}

	// Build tainted variable map
	taintedVars := make(map[string]bool)

	// Walk AST to find sources and propagate taint
	root := pf.RootNode()
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}

		switch n.Type() {
		// JavaScript/TypeScript
		case "variable_declarator", "assignment_expression":
			t.propagateAssignment(n, pf.Source, sources, taintedVars)
		// Python
		case "assignment":
			t.propagateAssignment(n, pf.Source, sources, taintedVars)
		// Go
		case "short_var_declaration":
			t.propagateAssignment(n, pf.Source, sources, taintedVars)
		case "call_expression", "call":
			if f := t.checkSinkCall(n, pf.Source, sinks, sources, taintedVars, rule); f != nil {
				findings = append(findings, *f)
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(root)

	return findings
}

func (t *Tracker) propagateAssignment(n *sitter.Node, source []byte, sourcePatterns []string, taintedVars map[string]bool) {
	var nameNode, valueNode *sitter.Node

	switch n.Type() {
	case "variable_declarator":
		nameNode = n.ChildByFieldName("name")
		valueNode = n.ChildByFieldName("value")
	case "assignment_expression":
		nameNode = n.ChildByFieldName("left")
		valueNode = n.ChildByFieldName("right")
	case "assignment":
		// Python: assignment has identifier on left, value on right (usually child 0 and 2, with = as child 1)
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if child.Type() == "identifier" && nameNode == nil {
				nameNode = child
			} else if child.Type() != "=" && nameNode != nil && valueNode == nil {
				valueNode = child
			}
		}
	case "short_var_declaration":
		// Go: short_var_declaration has left and right children
		nameNode = n.ChildByFieldName("left")
		valueNode = n.ChildByFieldName("right")
	}

	if nameNode == nil || valueNode == nil {
		return
	}

	if t.isTaintedExpr(valueNode, source, sourcePatterns, taintedVars) {
		varName := nodeText(nameNode, source)
		if varName != "" {
			taintedVars[varName] = true
		}
	}
}

func (t *Tracker) isTaintedExpr(n *sitter.Node, source []byte, sourcePatterns []string, taintedVars map[string]bool) bool {
	if n == nil {
		return false
	}

	text := nodeText(n, source)

	switch n.Type() {
	case "identifier":
		return taintedVars[text]

	case "member_expression", "attribute":
		// Check if it's a direct source (e.g., req.body.name)
		for _, pattern := range sourcePatterns {
			if strings.Contains(text, pattern) {
				return true
			}
		}
		// Check if the object itself is tainted
		obj := n.ChildByFieldName("object")
		if obj == nil {
			// Python attribute doesn't have "object" field, try first child
			obj = n.Child(0)
		}
		if obj != nil && t.isTaintedExpr(obj, source, sourcePatterns, taintedVars) {
			return true
		}
		return false

	case "binary_expression", "binary_operator":
		left := n.ChildByFieldName("left")
		right := n.ChildByFieldName("right")
		if left == nil {
			// Python binary_operator: children are left, operator, right
			for i := 0; i < int(n.ChildCount()); i++ {
				child := n.Child(i)
				if child.Type() != "+" && child.Type() != "-" && child.Type() != "*" && child.Type() != "/" && child.Type() != "%" {
					if left == nil {
						left = child
					} else {
						right = child
					}
				}
			}
		}
		return t.isTaintedExpr(left, source, sourcePatterns, taintedVars) ||
			t.isTaintedExpr(right, source, sourcePatterns, taintedVars)

	case "template_string":
		// Check template substitutions
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if child.Type() == "template_substitution" {
				for j := 0; j < int(child.ChildCount()); j++ {
					if t.isTaintedExpr(child.Child(j), source, sourcePatterns, taintedVars) {
						return true
					}
				}
			}
		}
		return false

	case "string":
		// Python f-string: check interpolations
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if child.Type() == "interpolation" {
				for j := 0; j < int(child.ChildCount()); j++ {
					if t.isTaintedExpr(child.Child(j), source, sourcePatterns, taintedVars) {
						return true
					}
				}
			}
		}
		return false

	case "call_expression", "call":
		// Check if the function itself is a source (e.g., request.args.get('id'))
		fn := n.ChildByFieldName("function")
		if fn == nil {
			for i := 0; i < int(n.ChildCount()); i++ {
				child := n.Child(i)
				if child.Type() == "attribute" || child.Type() == "identifier" {
					fn = child
					break
				}
			}
		}
		if fn != nil {
			fnText := nodeText(fn, source)
			for _, pattern := range sourcePatterns {
				if strings.Contains(fnText, pattern) {
					return true
				}
			}
		}
		// Check if any argument is tainted (for propagation)
		args := n.ChildByFieldName("arguments")
		if args == nil {
			// Python uses argument_list
			for i := 0; i < int(n.ChildCount()); i++ {
				if n.Child(i).Type() == "argument_list" {
					args = n.Child(i)
					break
				}
			}
		}
		if args != nil {
			for i := 0; i < int(args.ChildCount()); i++ {
				if t.isTaintedExpr(args.Child(i), source, sourcePatterns, taintedVars) {
					return true
				}
			}
		}
		return false

	case "arguments", "argument_list":
		for i := 0; i < int(n.ChildCount()); i++ {
			if t.isTaintedExpr(n.Child(i), source, sourcePatterns, taintedVars) {
				return true
			}
		}
		return false
	}

	// For any other node type, check children recursively
	for i := 0; i < int(n.ChildCount()); i++ {
		if t.isTaintedExpr(n.Child(i), source, sourcePatterns, taintedVars) {
			return true
		}
	}
	return false
}

func (t *Tracker) checkSinkCall(n *sitter.Node, source []byte, sinkPatterns, sourcePatterns []string, taintedVars map[string]bool, rule RuleInfo) *Finding {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		// Python: call nodes use 'attribute' or 'identifier' as first non-arg child
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if child.Type() == "attribute" || child.Type() == "identifier" {
				fn = child
				break
			}
		}
	}
	if fn == nil {
		return nil
	}

	fnText := nodeText(fn, source)

	// Check if this call matches any sink pattern
	var matchedSink string
	for _, pattern := range sinkPatterns {
		if strings.Contains(fnText, pattern) {
			matchedSink = pattern
			break
		}
	}
	if matchedSink == "" {
		return nil
	}

	// Check if any argument is tainted
	args := n.ChildByFieldName("arguments")
	if args == nil {
		// Python: look for argument_list
		for i := 0; i < int(n.ChildCount()); i++ {
			if n.Child(i).Type() == "argument_list" {
				args = n.Child(i)
				break
			}
		}
	}
	if args == nil {
		return nil
	}

	isSQLSink := strings.Contains(strings.ToLower(matchedSink), ".query") || strings.Contains(strings.ToLower(matchedSink), ".execute") || strings.Contains(strings.ToLower(matchedSink), ".run")

	argIndex := 0
	for i := 0; i < int(args.ChildCount()); i++ {
		arg := args.Child(i)
		if arg.Type() == "(" || arg.Type() == ")" || arg.Type() == "," {
			continue
		}

		if isSQLSink && argIndex > 0 {
			// Skip non-first args for SQL sinks (they're parameters)
			break
		}

		if t.isTaintedExpr(arg, source, sourcePatterns, taintedVars) {
			start := n.StartPoint()
			return &Finding{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   rule.Severity,
				Category:   rule.Category,
				Message:    strings.TrimSpace(rule.Message),
				File:       t.currentFile,
				Line:       int(start.Row) + 1,
				Column:     int(start.Column) + 1,
				Snippet:    nodeText(n, source),
				Confidence: rule.Confidence,
				References: rule.References,
			}
		}
		argIndex++
	}

	return nil
}

func nodeText(n *sitter.Node, source []byte) string {
	if n == nil {
		return ""
	}
	start := n.StartByte()
	end := n.EndByte()
	if start >= uint32(len(source)) || end > uint32(len(source)) {
		return ""
	}
	return string(source[start:end])
}
