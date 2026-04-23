package taint

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/raven-security/raven/internal/ast"
	"github.com/raven-security/raven/internal/taint/crossfile"
)

// Finding represents a taint analysis finding
type Finding struct {
	RuleID     string
	RuleName   string
	Severity   string
	Category   string
	CWE        string
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

// FunctionSummary describes a function's taint behavior
type FunctionSummary struct {
	Name           string
	ReturnsTainted bool
	TaintedParams  []int // parameter indices that flow to sinks
}

// Tracker performs intra-procedural taint analysis
type Tracker struct {
	config      LanguageConfig
	currentFile string
	resolver    *crossfile.Resolver // optional cross-file resolver
}

// NewTracker creates a taint tracker for the given language
func NewTracker(language string) *Tracker {
	config, ok := DefaultConfigs[language]
	if !ok {
		config = LanguageConfig{}
	}
	return &Tracker{config: config}
}

// SetResolver sets the cross-file module resolver.
func (t *Tracker) SetResolver(r *crossfile.Resolver) {
	t.resolver = r
}

// SetCurrentFile sets the current file path for cross-file resolution.
func (t *Tracker) SetCurrentFile(path string) {
	t.currentFile = path
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
	CWE        string
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

	// Build function summaries for inter-procedural analysis
	summaries := t.buildFunctionSummaries(pf, sources, sinks)

	// Build tainted variable map
	taintedVars := make(map[string]bool)

	// Add cross-file tainted imports
	if t.resolver != nil {
		if mod, ok := t.resolver.GetModuleInfo(t.currentFile); ok {
			for _, imp := range mod.Imports {
				resolved, ok := t.resolver.ResolveImport(t.currentFile, imp.Source)
				if !ok {
					continue
				}
				resolvedMod, hasMod := t.resolver.GetModuleInfo(resolved)
				if !hasMod {
					continue
				}
				for _, exp := range resolvedMod.Exports {
					if !t.resolver.IsTaintedSource(resolved, exp.Name) {
						continue
					}
					for _, importedName := range imp.Names {
						if importedName == exp.Name {
							// Named import: e.g. import { getInput } from './utils'
							taintedVars[importedName] = true
						} else {
							// Whole module import: e.g. const utils = require('./utils')
							taintedVars[importedName+"."+exp.Name] = true
						}
					}
				}
			}
		}
	}

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
			t.propagateAssignment(n, pf.Source, sources, taintedVars, summaries)
		// Python
		case "assignment":
			t.propagateAssignment(n, pf.Source, sources, taintedVars, summaries)
		// Go
		case "short_var_declaration":
			t.propagateAssignment(n, pf.Source, sources, taintedVars, summaries)
		case "call_expression", "call":
			if f := t.checkSinkCall(n, pf.Source, sinks, sources, taintedVars, summaries, rule); f != nil {
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

func (t *Tracker) propagateAssignment(n *sitter.Node, source []byte, sourcePatterns []string, taintedVars map[string]bool, summaries map[string]*FunctionSummary) {
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

	if t.isTaintedExpr(valueNode, source, sourcePatterns, taintedVars, summaries) {
		varName := nodeText(nameNode, source)
		if varName != "" {
			taintedVars[varName] = true
		}
	}
}

func (t *Tracker) isTaintedExpr(n *sitter.Node, source []byte, sourcePatterns []string, taintedVars map[string]bool, summaries map[string]*FunctionSummary) bool {
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
		if obj != nil && t.isTaintedExpr(obj, source, sourcePatterns, taintedVars, summaries) {
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
		return t.isTaintedExpr(left, source, sourcePatterns, taintedVars, summaries) ||
			t.isTaintedExpr(right, source, sourcePatterns, taintedVars, summaries)

	case "template_string":
		// Check template substitutions
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if child.Type() == "template_substitution" {
				for j := 0; j < int(child.ChildCount()); j++ {
					if t.isTaintedExpr(child.Child(j), source, sourcePatterns, taintedVars, summaries) {
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
					if t.isTaintedExpr(child.Child(j), source, sourcePatterns, taintedVars, summaries) {
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
			// Check if the called function is a tainted import
			if taintedVars[fnText] {
				return true
			}
			parts := strings.Split(fnText, ".")
			for _, part := range parts {
				if taintedVars[part] {
					return true
				}
			}
			// Inter-procedural: check if called function returns tainted data
			if summary, ok := summaries[fnText]; ok && summary.ReturnsTainted {
				return true
			}
			// Also check without module prefix (e.g. utils.getInput -> getInput)
			if len(parts) > 1 {
				if summary, ok := summaries[parts[len(parts)-1]]; ok && summary.ReturnsTainted {
					return true
				}
			}
			// Sanitizer check: if this is a sanitizer call, the result is safe
			for _, san := range t.config.Sanitizers {
				if strings.Contains(fnText, san) || strings.Contains(san, fnText) {
					return false
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
				if t.isTaintedExpr(args.Child(i), source, sourcePatterns, taintedVars, summaries) {
					return true
				}
			}
		}
		return false

	case "arguments", "argument_list":
		for i := 0; i < int(n.ChildCount()); i++ {
			if t.isTaintedExpr(n.Child(i), source, sourcePatterns, taintedVars, summaries) {
				return true
			}
		}
		return false
	}

	// For any other node type, check children recursively
	for i := 0; i < int(n.ChildCount()); i++ {
		if t.isTaintedExpr(n.Child(i), source, sourcePatterns, taintedVars, summaries) {
			return true
		}
	}
	return false
}

func (t *Tracker) checkSinkCall(n *sitter.Node, source []byte, sinkPatterns, sourcePatterns []string, taintedVars map[string]bool, summaries map[string]*FunctionSummary, rule RuleInfo) *Finding {
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

		if t.isTaintedExpr(arg, source, sourcePatterns, taintedVars, summaries) {
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


// buildFunctionSummaries analyzes all functions in a file and determines
// which ones return tainted data or have tainted parameters flowing to sinks.
func (t *Tracker) buildFunctionSummaries(pf *ast.ParsedFile, sources, sinks []string) map[string]*FunctionSummary {
	summaries := make(map[string]*FunctionSummary)
	root := pf.RootNode()

	var findFunctions func(n *sitter.Node)
	findFunctions = func(n *sitter.Node) {
		if n == nil {
			return
		}

		var funcName string
		var body *sitter.Node

		switch n.Type() {
		case "function_declaration":
			if name := n.ChildByFieldName("name"); name != nil {
				funcName = nodeText(name, pf.Source)
			}
			body = n.ChildByFieldName("body")
		case "function":
			// Anonymous function or method
			if name := n.ChildByFieldName("name"); name != nil {
				funcName = nodeText(name, pf.Source)
			}
			body = n.ChildByFieldName("body")
		case "method_declaration":
			if name := n.ChildByFieldName("name"); name != nil {
				funcName = nodeText(name, pf.Source)
			}
			body = n.ChildByFieldName("body")
		case "func_literal":
			body = n.ChildByFieldName("body")
		}

		if body != nil && funcName != "" {
			summary := t.analyzeFunctionBody(body, pf.Source, sources, sinks)
			summary.Name = funcName
			summaries[funcName] = summary
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			findFunctions(n.Child(i))
		}
	}

	findFunctions(root)
	return summaries
}

// analyzeFunctionBody checks if a function returns tainted data or passes
// tainted params to sinks.
func (t *Tracker) analyzeFunctionBody(body *sitter.Node, source []byte, sources, sinks []string) *FunctionSummary {
	summary := &FunctionSummary{}

	// Build tainted vars for this function's parameters
	taintedVars := make(map[string]bool)
	parent := body.Parent()
	if parent != nil {
		params := parent.ChildByFieldName("parameters")
		if params == nil {
			// Try finding parameter list in parent
			for i := 0; i < int(parent.ChildCount()); i++ {
				child := parent.Child(i)
				if child.Type() == "formal_parameters" || child.Type() == "parameters" || child.Type() == "parameter_list" {
					params = child
					break
				}
			}
		}
		if params != nil {
			paramIdx := 0
			for i := 0; i < int(params.ChildCount()); i++ {
				param := params.Child(i)
				if param.Type() == "(" || param.Type() == ")" || param.Type() == "," {
					continue
				}
				var paramName string
				if param.Type() == "identifier" {
					paramName = nodeText(param, source)
				} else {
					// Try to find identifier inside parameter node
					for j := 0; j < int(param.ChildCount()); j++ {
						if param.Child(j).Type() == "identifier" {
							paramName = nodeText(param.Child(j), source)
							break
						}
					}
				}
				if paramName != "" {
					// Check if any source pattern matches this param
					for _, src := range sources {
						if strings.Contains(paramName, src) || strings.Contains(src, paramName) {
							taintedVars[paramName] = true
							summary.TaintedParams = append(summary.TaintedParams, paramIdx)
							break
						}
					}
				}
				paramIdx++
			}
		}
	}

	// Walk the body to check for returns with tainted data
	var checkReturns func(n *sitter.Node)
	checkReturns = func(n *sitter.Node) {
		if n == nil {
			return
		}

		switch n.Type() {
		case "return_statement":
			for i := 0; i < int(n.ChildCount()); i++ {
				child := n.Child(i)
				if child.Type() == "return" {
					continue
				}
				if t.isTaintedExpr(child, source, sources, taintedVars, nil) {
					summary.ReturnsTainted = true
					return
				}
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			checkReturns(n.Child(i))
		}
	}

	checkReturns(body)
	return summary
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
