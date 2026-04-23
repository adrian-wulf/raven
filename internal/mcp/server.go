package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/raven-security/raven/internal/engine"
	"github.com/raven-security/raven/internal/version"
)

// Server implements the Model Context Protocol for Raven
type Server struct {
	reader    *bufio.Reader
	writer    io.Writer
	writerMu  sync.Mutex
	rules     []engine.Rule
	rulesMu   sync.RWMutex
	documents map[string]string // uri -> content cache
}

// NewServer creates a new MCP server
func NewServer(reader io.Reader, writer io.Writer) *Server {
	loader := engine.NewRulesLoader()
	rules, _ := loader.Load()

	return &Server{
		reader:    bufio.NewReader(reader),
		writer:    writer,
		rules:     rules,
		documents: make(map[string]string),
	}
}

// Run starts the MCP server loop
func (s *Server) Run() error {
	for {
		req, err := s.readRequest()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			fmt.Fprintf(os.Stderr, "[raven-mcp] read error: %v\n", err)
			continue
		}

		if err := s.handleRequest(req); err != nil {
			fmt.Fprintf(os.Stderr, "[raven-mcp] handle error: %v\n", err)
		}
	}
}

func (s *Server) readRequest() (*Request, error) {
	contentLength := 0
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Content-Length: ") {
			fmt.Sscanf(line, "Content-Length: %d", &contentLength)
		}
	}

	if contentLength == 0 {
		return nil, fmt.Errorf("no content length")
	}

	body := make([]byte, contentLength)
	_, err := io.ReadFull(s.reader, body)
	if err != nil {
		return nil, err
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	return &req, nil
}

func (s *Server) writeResponse(resp *Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	s.writerMu.Lock()
	defer s.writerMu.Unlock()

	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
	if _, err := s.writer.Write([]byte(header)); err != nil {
		return err
	}
	if _, err := s.writer.Write(data); err != nil {
		return err
	}
	return nil
}

func (s *Server) sendNotification(method string, params interface{}) error {
	msg := Notification{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	s.writerMu.Lock()
	defer s.writerMu.Unlock()

	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
	if _, err := s.writer.Write([]byte(header)); err != nil {
		return err
	}
	if _, err := s.writer.Write(data); err != nil {
		return err
	}
	return nil
}

func (s *Server) handleRequest(req *Request) error {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "initialized":
		return nil // no response
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	case "resources/list":
		return s.handleResourcesList(req)
	case "resources/read":
		return s.handleResourcesRead(req)
	case "prompts/list":
		return s.handlePromptsList(req)
	case "notifications/roots/list_changed":
		return nil
	default:
		// Unknown method - return error
		return s.writeResponse(&Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &ErrorObject{
				Code:    -32601,
				Message: fmt.Sprintf("Method not found: %s", req.Method),
			},
		})
	}
}

func (s *Server) handleInitialize(req *Request) error {
	result := InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: ServerCapabilities{
			Tools: &ToolsCapability{
				ListChanged: false,
			},
			Resources: &ResourcesCapability{
				Subscribe:   false,
				ListChanged: false,
			},
		},
		ServerInfo: Implementation{
			Name:    "raven-mcp",
			Version: version.Version,
		},
	}

	return s.writeResponse(&Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	})
}

func (s *Server) handleToolsList(req *Request) error {
	tools := []Tool{
		{
			Name:        "raven_scan_workspace",
			Description: "Scan the entire workspace/directory for security vulnerabilities using Raven's 503+ rules. Returns findings with severity, rule ID, file location, and suggested fixes.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"path": {
						Type:        "string",
						Description: "Path to the workspace directory to scan (default: current directory)",
					},
					"severity": {
						Type:        "string",
						Description: "Minimum severity to report: critical, high, medium, low, info (default: low)",
						Enum:        []string{"critical", "high", "medium", "low", "info"},
					},
					"languages": {
						Type:        "string",
						Description: "Comma-separated list of languages to scan, e.g. 'javascript,python,go' (default: all)",
					},
				},
				Required: []string{},
			},
		},
		{
			Name:        "raven_scan_file",
			Description: "Scan a specific file for security vulnerabilities. Fast and focused analysis of a single source file.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"path": {
						Type:        "string",
						Description: "Absolute or relative path to the file to scan",
					},
					"severity": {
						Type:        "string",
						Description: "Minimum severity to report (default: low)",
						Enum:        []string{"critical", "high", "medium", "low", "info"},
					},
				},
				Required: []string{"path"},
			},
		},
		{
			Name:        "raven_scan_snippet",
			Description: "Scan a code snippet for security vulnerabilities. Useful for analyzing AI-generated code before accepting it. Provide the code and optionally the language.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"code": {
						Type:        "string",
						Description: "The code snippet to analyze",
					},
					"language": {
						Type:        "string",
						Description: "Programming language of the snippet: javascript, typescript, python, go, java, php, rust, ruby, kotlin, csharp, swift",
					},
				},
				Required: []string{"code"},
			},
		},
		{
			Name:        "raven_list_rules",
			Description: "List all available Raven security rules with their IDs, names, severities, and categories. Useful to understand what Raven can detect.",
			InputSchema: InputSchema{
				Type:       "object",
				Properties: map[string]Property{},
				Required:   []string{},
			},
		},
		{
			Name:        "raven_get_rule",
			Description: "Get detailed information about a specific security rule by its ID, including description, patterns, fix suggestions, and references.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"rule_id": {
						Type:        "string",
						Description: "The rule ID to look up, e.g. 'raven-sqli-001' or 'raven-secrets-aws-key'",
					},
				},
				Required: []string{"rule_id"},
			},
		},
		{
			Name:        "raven_explain_finding",
			Description: "Get a detailed security explanation of a finding, including why it's dangerous, how it can be exploited, and how to fix it. Pass the rule_id and optionally the code snippet.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"rule_id": {
						Type:        "string",
						Description: "The rule ID of the finding",
					},
					"code": {
						Type:        "string",
						Description: "The vulnerable code snippet for context",
					},
				},
				Required: []string{"rule_id"},
			},
		},
	}

	return s.writeResponse(&Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	})
}

func (s *Server) handleToolsCall(req *Request) error {
	var params CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.writeResponse(&Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &ErrorObject{
				Code:    -32602,
				Message: fmt.Sprintf("Invalid params: %v", err),
			},
		})
	}

	var result CallToolResult
	switch params.Name {
	case "raven_scan_workspace":
		result = s.toolScanWorkspace(params.Arguments)
	case "raven_scan_file":
		result = s.toolScanFile(params.Arguments)
	case "raven_scan_snippet":
		result = s.toolScanSnippet(params.Arguments)
	case "raven_list_rules":
		result = s.toolListRules()
	case "raven_get_rule":
		result = s.toolGetRule(params.Arguments)
	case "raven_explain_finding":
		result = s.toolExplainFinding(params.Arguments)
	default:
		result = CallToolResult{
			IsError: true,
			Content: []ContentItem{{
				Type: "text",
				Text: fmt.Sprintf("Unknown tool: %s", params.Name),
			}},
		}
	}

	return s.writeResponse(&Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	})
}

func (s *Server) toolScanWorkspace(args json.RawMessage) CallToolResult {
	var params struct {
		Path      string `json:"path"`
		Severity  string `json:"severity"`
		Languages string `json:"languages"`
	}
	json.Unmarshal(args, &params)

	if params.Path == "" {
		params.Path = "."
	}
	if params.Severity == "" {
		params.Severity = "low"
	}

	path, err := filepath.Abs(params.Path)
	if err != nil {
		return errorResult(fmt.Sprintf("Invalid path: %v", err))
	}

	info, err := os.Stat(path)
	if err != nil {
		return errorResult(fmt.Sprintf("Cannot access path: %v", err))
	}
	if !info.IsDir() {
		return errorResult(fmt.Sprintf("Path is not a directory: %s", path))
	}

	var langs []string
	if params.Languages != "" {
		for _, l := range strings.Split(params.Languages, ",") {
			langs = append(langs, strings.TrimSpace(l))
		}
	}

	var minSev engine.Severity
	switch params.Severity {
	case "critical":
		minSev = engine.Critical
	case "high":
		minSev = engine.High
	case "medium":
		minSev = engine.Medium
	case "low":
		minSev = engine.Low
	default:
		minSev = engine.Info
	}

	scanner := engine.NewScanner(s.rules, engine.ScanConfig{
		Paths:       []string{path},
		Languages:   langs,
		Confidence:  "low",
		MinSeverity: minSev,
	})

	result, err := scanner.Scan()
	if err != nil {
		return errorResult(fmt.Sprintf("Scan failed: %v", err))
	}

	if len(result.Findings) == 0 {
		return successResult(fmt.Sprintf("✅ No security issues found in %s\n\nScanned %d files with %d rules.",
			path, result.FilesScanned, result.RulesRun))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🐦‍⬛ Raven found **%d** security issue(s) in %s\n\n", len(result.Findings), path))
	sb.WriteString(fmt.Sprintf("📁 Files scanned: %d | 🔍 Rules run: %d\n\n", result.FilesScanned, result.RulesRun))

	bySev := result.BySeverity()
	for _, sev := range []engine.Severity{engine.Critical, engine.High, engine.Medium, engine.Low, engine.Info} {
		findings := bySev[sev]
		if len(findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("## %s (%d)\n\n", strings.ToUpper(string(sev)), len(findings)))
		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("- **%s** — %s\n", f.RuleID, f.Message))
			sb.WriteString(fmt.Sprintf("  📍 `%s:%d`\n", f.File, f.Line))
			if f.FixAvailable && f.Fix != nil {
				sb.WriteString(fmt.Sprintf("  💡 *Fix: %s*\n", f.Fix.Description))
			}
			sb.WriteString("\n")
		}
	}

	return successResult(sb.String())
}

func (s *Server) toolScanFile(args json.RawMessage) CallToolResult {
	var params struct {
		Path     string `json:"path"`
		Severity string `json:"severity"`
	}
	json.Unmarshal(args, &params)

	if params.Path == "" {
		return errorResult("Path is required")
	}
	if params.Severity == "" {
		params.Severity = "low"
	}

	path, err := filepath.Abs(params.Path)
	if err != nil {
		return errorResult(fmt.Sprintf("Invalid path: %v", err))
	}

	info, err := os.Stat(path)
	if err != nil {
		return errorResult(fmt.Sprintf("Cannot access file: %v", err))
	}
	if info.IsDir() {
		return errorResult(fmt.Sprintf("Path is a directory, not a file: %s", path))
	}

	var minSev engine.Severity
	switch params.Severity {
	case "critical":
		minSev = engine.Critical
	case "high":
		minSev = engine.High
	case "medium":
		minSev = engine.Medium
	case "low":
		minSev = engine.Low
	default:
		minSev = engine.Info
	}

	scanner := engine.NewScanner(s.rules, engine.ScanConfig{
		Paths:       []string{path},
		Confidence:  "low",
		MinSeverity: minSev,
	})

	result, err := scanner.Scan()
	if err != nil {
		return errorResult(fmt.Sprintf("Scan failed: %v", err))
	}

	if len(result.Findings) == 0 {
		return successResult(fmt.Sprintf("✅ No security issues found in `%s`", filepath.Base(path)))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🐦‍⬛ Found **%d** issue(s) in `%s`:\n\n", len(result.Findings), filepath.Base(path)))

	for _, f := range result.Findings {
		sb.WriteString(fmt.Sprintf("### %s — %s\n", f.RuleID, f.Message))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
		sb.WriteString(fmt.Sprintf("- **Line:** %d\n", f.Line))
		sb.WriteString(fmt.Sprintf("- **Category:** %s\n", f.Category))
		if f.FixAvailable && f.Fix != nil {
			sb.WriteString(fmt.Sprintf("- **Fix:** %s\n", f.Fix.Description))
		}
		if f.Snippet != "" {
			snippet := strings.TrimSpace(f.Snippet)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			sb.WriteString(fmt.Sprintf("\n```\n%s\n```\n", snippet))
		}
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}

func (s *Server) toolScanSnippet(args json.RawMessage) CallToolResult {
	var params struct {
		Code     string `json:"code"`
		Language string `json:"language"`
	}
	json.Unmarshal(args, &params)

	if params.Code == "" {
		return errorResult("Code is required")
	}

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "raven-mcp-*.tmp")
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to create temp file: %v", err))
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(params.Code); err != nil {
		return errorResult(fmt.Sprintf("Failed to write temp file: %v", err))
	}
	tmpFile.Close()

	// Detect language from code if not provided
	lang := params.Language
	if lang == "" {
		lang = detectLanguage(params.Code)
	}

	var langs []string
	if lang != "" {
		langs = []string{lang}
	}

	var activeRules []engine.Rule
	for _, rule := range s.rules {
		if len(langs) > 0 && len(rule.Languages) > 0 {
			match := false
			for _, rl := range rule.Languages {
				if strings.EqualFold(rl, lang) || rl == "*" {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		activeRules = append(activeRules, rule)
	}

	scanner := engine.NewScanner(activeRules, engine.ScanConfig{
		Paths:      []string{tmpFile.Name()},
		Confidence: "low",
	})

	result, err := scanner.Scan()
	if err != nil {
		return errorResult(fmt.Sprintf("Scan failed: %v", err))
	}

	if len(result.Findings) == 0 {
		return successResult("✅ No security issues detected in the provided code snippet.")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🐦‍⬛ Found **%d** security issue(s) in the code snippet:\n\n", len(result.Findings)))

	for _, f := range result.Findings {
		sb.WriteString(fmt.Sprintf("### %s — %s\n", f.RuleID, f.Message))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s | **Category:** %s\n", f.Severity, f.Category))
		if f.FixAvailable && f.Fix != nil {
			sb.WriteString(fmt.Sprintf("- **Suggested fix:** %s\n", f.Fix.Description))
		}
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}

func (s *Server) toolListRules() CallToolResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🐦‍⬛ Raven Rules (%d total)\n\n", len(s.rules)))

	// Group by category
	byCategory := make(map[string][]engine.Rule)
	for _, rule := range s.rules {
		byCategory[rule.Category] = append(byCategory[rule.Category], rule)
	}

	for cat, rules := range byCategory {
		sb.WriteString(fmt.Sprintf("## %s (%d)\n\n", cat, len(rules)))
		for _, rule := range rules {
			langs := strings.Join(rule.Languages, ", ")
			if langs == "" {
				langs = "all"
			}
			sb.WriteString(fmt.Sprintf("- `%s` — **%s** (%s) [%s]\n", rule.ID, rule.Name, rule.Severity, langs))
		}
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}

func (s *Server) toolGetRule(args json.RawMessage) CallToolResult {
	var params struct {
		RuleID string `json:"rule_id"`
	}
	json.Unmarshal(args, &params)

	if params.RuleID == "" {
		return errorResult("rule_id is required")
	}

	for _, rule := range s.rules {
		if rule.ID == params.RuleID {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("# %s\n\n", rule.Name))
			sb.WriteString(fmt.Sprintf("**ID:** `%s`\n\n", rule.ID))
			sb.WriteString(fmt.Sprintf("**Severity:** %s\n\n", rule.Severity))
			sb.WriteString(fmt.Sprintf("**Category:** %s\n\n", rule.Category))
			sb.WriteString(fmt.Sprintf("**Confidence:** %s\n\n", rule.Confidence))
			sb.WriteString(fmt.Sprintf("**Languages:** %s\n\n", strings.Join(rule.Languages, ", ")))
			if len(rule.Frameworks) > 0 {
				sb.WriteString(fmt.Sprintf("**Frameworks:** %s\n\n", strings.Join(rule.Frameworks, ", ")))
			}
			sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", rule.Description))
			sb.WriteString(fmt.Sprintf("**Message:** %s\n\n", rule.Message))

			if len(rule.Patterns) > 0 {
				sb.WriteString("**Patterns:**\n")
				for i, p := range rule.Patterns {
					sb.WriteString(fmt.Sprintf("%d. Type: `%s`\n", i+1, p.Type))
					if p.Pattern != "" {
						sb.WriteString(fmt.Sprintf("   Pattern: `%s`\n", truncate(p.Pattern, 100)))
					}
					if p.Query != "" {
						sb.WriteString(fmt.Sprintf("   AST Query: `%s`\n", truncate(p.Query, 100)))
					}
				}
				sb.WriteString("\n")
			}

			if rule.Fix != nil {
				sb.WriteString(fmt.Sprintf("**Auto-fix:** %s\n\n", rule.Fix.Description))
			}

			if len(rule.References) > 0 {
				sb.WriteString("**References:**\n")
				for _, ref := range rule.References {
					sb.WriteString(fmt.Sprintf("- %s\n", ref))
				}
			}

			return successResult(sb.String())
		}
	}

	return errorResult(fmt.Sprintf("Rule not found: %s", params.RuleID))
}

func (s *Server) toolExplainFinding(args json.RawMessage) CallToolResult {
	var params struct {
		RuleID string `json:"rule_id"`
		Code   string `json:"code"`
	}
	json.Unmarshal(args, &params)

	if params.RuleID == "" {
		return errorResult("rule_id is required")
	}

	for _, rule := range s.rules {
		if rule.ID == params.RuleID {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("# Security Analysis: %s\n\n", rule.Name))
			sb.WriteString(fmt.Sprintf("**Rule:** `%s` | **Severity:** %s | **Category:** %s\n\n", rule.ID, rule.Severity, rule.Category))

			sb.WriteString("## Why This Is Dangerous\n\n")
			sb.WriteString(rule.Description)
			sb.WriteString("\n\n")

			sb.WriteString("## Impact\n\n")
			sb.WriteString(rule.Message)
			sb.WriteString("\n\n")

			if rule.Fix != nil {
				sb.WriteString("## How To Fix\n\n")
				sb.WriteString(rule.Fix.Description)
				sb.WriteString("\n\n")
			}

			if len(rule.References) > 0 {
				sb.WriteString("## Learn More\n\n")
				for _, ref := range rule.References {
					sb.WriteString(fmt.Sprintf("- %s\n", ref))
				}
			}

			if params.Code != "" {
				sb.WriteString("\n## Your Code\n\n```\n")
				sb.WriteString(params.Code)
				sb.WriteString("\n```\n")
			}

			return successResult(sb.String())
		}
	}

	return errorResult(fmt.Sprintf("Rule not found: %s", params.RuleID))
}

func (s *Server) handleResourcesList(req *Request) error {
	resources := []Resource{
		{
			URI:         "raven://rules",
			Name:        "Raven Rules",
			Description: "Complete list of all Raven security rules",
			MIMEType:    "application/json",
		},
	}

	// Add individual rule resources
	for _, rule := range s.rules {
		resources = append(resources, Resource{
			URI:         fmt.Sprintf("raven://rules/%s", rule.ID),
			Name:        rule.Name,
			Description: fmt.Sprintf("%s — %s severity", rule.Description, rule.Severity),
			MIMEType:    "application/json",
		})
	}

	return s.writeResponse(&Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"resources": resources,
		},
	})
}

func (s *Server) handleResourcesRead(req *Request) error {
	var params ReadResourceParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.writeResponse(&Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &ErrorObject{
				Code:    -32602,
				Message: "Invalid params",
			},
		})
	}

	if params.URI == "raven://rules" {
		data, _ := json.MarshalIndent(s.rules, "", "  ")
		return s.writeResponse(&Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"contents": []ResourceContent{{
					URI:      params.URI,
					MIMEType: "application/json",
					Text:     string(data),
				}},
			},
		})
	}

	// Individual rule
	if strings.HasPrefix(params.URI, "raven://rules/") {
		ruleID := strings.TrimPrefix(params.URI, "raven://rules/")
		for _, rule := range s.rules {
			if rule.ID == ruleID {
				data, _ := json.MarshalIndent(rule, "", "  ")
				return s.writeResponse(&Response{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result: map[string]interface{}{
						"contents": []ResourceContent{{
							URI:      params.URI,
							MIMEType: "application/json",
							Text:     string(data),
						}},
					},
				})
			}
		}
	}

	return s.writeResponse(&Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Error: &ErrorObject{
			Code:    -32602,
			Message: fmt.Sprintf("Resource not found: %s", params.URI),
		},
	})
}

func (s *Server) handlePromptsList(req *Request) error {
	prompts := []Prompt{
		{
			Name:        "security-review",
			Description: "Review code for security vulnerabilities before committing",
			Arguments: []Argument{
				{
					Name:        "code",
					Description: "The code to review",
					Required:    true,
				},
				{
					Name:        "language",
					Description: "Programming language",
					Required:    false,
				},
			},
		},
	}

	return s.writeResponse(&Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"prompts": prompts,
		},
	})
}

// Helpers

func successResult(text string) CallToolResult {
	return CallToolResult{
		Content: []ContentItem{{
			Type: "text",
			Text: text,
		}},
	}
}

func errorResult(text string) CallToolResult {
	return CallToolResult{
		IsError: true,
		Content: []ContentItem{{
			Type: "text",
			Text: text,
		}},
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func detectLanguage(code string) string {
	// Quick heuristic detection
	if strings.Contains(code, "func ") && strings.Contains(code, "package ") {
		return "go"
	}
	if strings.Contains(code, "def ") && (strings.Contains(code, ":") || strings.Contains(code, "import ")) {
		return "python"
	}
	if strings.Contains(code, "function ") || strings.Contains(code, "const ") || strings.Contains(code, "let ") {
		return "javascript"
	}
	if strings.Contains(code, "public class ") || strings.Contains(code, "import java.") {
		return "java"
	}
	if strings.Contains(code, "<?php") {
		return "php"
	}
	if strings.Contains(code, "fn ") && strings.Contains(code, "->") {
		return "rust"
	}
	if strings.Contains(code, "class ") && strings.Contains(code, "end") {
		return "ruby"
	}
	if strings.Contains(code, "class ") && strings.Contains(code, "{") && strings.Contains(code, "public ") {
		return "csharp"
	}
	if strings.Contains(code, "func ") && strings.Contains(code, "->") && !strings.Contains(code, "package ") {
		return "swift"
	}
	if strings.Contains(code, "fun ") || strings.Contains(code, "val ") || strings.Contains(code, "var ") {
		return "kotlin"
	}
	return ""
}
