package lsp

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
)

// Message represents an LSP JSON-RPC message
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int            `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// Response represents an LSP JSON-RPC response
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *int        `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError represents an LSP error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// InitializeParams represents LSP initialize params
type InitializeParams struct {
	ProcessID             int                `json:"processId"`
	RootURI               string             `json:"rootUri"`
	RootPath              string             `json:"rootPath"`
	Capabilities          ClientCapabilities `json:"capabilities"`
	WorkspaceFolders      []WorkspaceFolder  `json:"workspaceFolders,omitempty"`
	InitializationOptions map[string]interface{} `json:"initializationOptions,omitempty"`
}

type ClientCapabilities struct {
	TextDocument TextDocumentClientCapabilities `json:"textDocument,omitempty"`
	Workspace    WorkspaceClientCapabilities    `json:"workspace,omitempty"`
}

type TextDocumentClientCapabilities struct {
	PublishDiagnostics PublishDiagnosticsCapability `json:"publishDiagnostics,omitempty"`
	CodeAction         CodeActionCapability         `json:"codeAction,omitempty"`
	Hover              HoverCapability              `json:"hover,omitempty"`
	CodeLens           CodeLensCapability           `json:"codeLens,omitempty"`
}

type PublishDiagnosticsCapability struct {
	RelatedInformation bool `json:"relatedInformation,omitempty"`
	VersionSupport     bool `json:"versionSupport,omitempty"`
}

type CodeActionCapability struct {
	DynamicRegistration bool                     `json:"dynamicRegistration,omitempty"`
	CodeActionLiteralSupport CodeActionLiteralSupport `json:"codeActionLiteralSupport,omitempty"`
}

type CodeActionLiteralSupport struct {
	CodeActionKind CodeActionKindSupport `json:"codeActionKind"`
}

type CodeActionKindSupport struct {
	ValueSet []string `json:"valueSet"`
}

type HoverCapability struct {
	DynamicRegistration bool     `json:"dynamicRegistration,omitempty"`
	ContentFormat       []string `json:"contentFormat,omitempty"`
}

type CodeLensCapability struct {
	DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
}

type WorkspaceClientCapabilities struct {
	WorkspaceFolders bool `json:"workspaceFolders,omitempty"`
}

type WorkspaceFolder struct {
	URI  string `json:"uri"`
	Name string `json:"name"`
}

type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities"`
	ServerInfo   ServerInfo         `json:"serverInfo,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ServerCapabilities struct {
	TextDocumentSync           int                  `json:"textDocumentSync"`
	CodeActionProvider         bool                 `json:"codeActionProvider"`
	HoverProvider              bool                 `json:"hoverProvider"`
	CodeLensProvider           *CodeLensOptions     `json:"codeLensProvider,omitempty"`
	DiagnosticProvider         *DiagnosticOptions   `json:"diagnosticProvider,omitempty"`
	WorkspaceSymbolProvider    bool                 `json:"workspaceSymbolProvider,omitempty"`
	Workspace                  *WorkspaceOptions    `json:"workspace,omitempty"`
}

type CodeLensOptions struct {
	ResolveProvider bool `json:"resolveProvider,omitempty"`
}

type DiagnosticOptions struct {
	Identifier            string `json:"identifier"`
	InterFileDependencies bool   `json:"interFileDependencies"`
	WorkspaceDiagnostics  bool   `json:"workspaceDiagnostics"`
}

type WorkspaceOptions struct {
	WorkspaceFolders WorkspaceFoldersOptions `json:"workspaceFolders"`
}

type WorkspaceFoldersOptions struct {
	Supported           bool `json:"supported"`
	ChangeNotifications bool `json:"changeNotifications"`
}

// Text document types
type TextDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

type TextDocumentIdentifier struct {
	URI string `json:"uri"`
}

type VersionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version int    `json:"version"`
}

type TextDocumentContentChangeEvent struct {
	Text string `json:"text"`
}

type DidOpenTextDocumentParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

type DidChangeTextDocumentParams struct {
	TextDocument   VersionedTextDocumentIdentifier `json:"textDocument"`
	ContentChanges []TextDocumentContentChangeEvent  `json:"contentChanges"`
}

type DidSaveTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

type DidCloseTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// Diagnostic types
type PublishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Version     int          `json:"version"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

type Diagnostic struct {
	Range              Range                          `json:"range"`
	Severity           int                            `json:"severity"`
	Code               string                         `json:"code"`
	Source             string                         `json:"source"`
	Message            string                         `json:"message"`
	RelatedInformation []DiagnosticRelatedInformation `json:"relatedInformation,omitempty"`
}

type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type DiagnosticRelatedInformation struct {
	Location Location `json:"location"`
	Message  string   `json:"message"`
}

type Location struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

// Code action types
type CodeActionParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Range        Range                  `json:"range"`
	Context      CodeActionContext      `json:"context"`
}

type CodeActionContext struct {
	Diagnostics []Diagnostic `json:"diagnostics"`
	Only        []string     `json:"only,omitempty"`
}

type CodeAction struct {
	Title   string         `json:"title"`
	Kind    string         `json:"kind"`
	Edit    *WorkspaceEdit `json:"edit,omitempty"`
	Command *Command       `json:"command,omitempty"`
}

type WorkspaceEdit struct {
	Changes map[string][]TextEdit `json:"changes"`
}

type TextEdit struct {
	Range   Range  `json:"range"`
	NewText string `json:"newText"`
}

type Command struct {
	Title     string        `json:"title"`
	Command   string        `json:"command"`
	Arguments []interface{} `json:"arguments"`
}

// Hover types
type HoverParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Position     Position               `json:"position"`
}

type Hover struct {
	Contents MarkupContent `json:"contents"`
	Range    *Range        `json:"range,omitempty"`
}

type MarkupContent struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// CodeLens types
type CodeLensParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

type CodeLens struct {
	Range   Range      `json:"range"`
	Command *Command   `json:"command,omitempty"`
}

// Document diagnostic types (pull model)
type DocumentDiagnosticParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

type DocumentDiagnosticReport struct {
	Kind     string       `json:"kind"`
	ResultID string       `json:"resultId,omitempty"`
	Items    []Diagnostic `json:"items,omitempty"`
}

// Show message notification
type ShowMessageParams struct {
	Type    int    `json:"type"`
	Message string `json:"message"`
}

const (
	MessageTypeError   = 1
	MessageTypeWarning = 2
	MessageTypeInfo    = 3
	MessageTypeLog     = 4
)

const (
	DiagnosticSeverityError       = 1
	DiagnosticSeverityWarning     = 2
	DiagnosticSeverityInformation = 3
	DiagnosticSeverityHint        = 4
)

// Server represents the Raven LSP server
type Server struct {
	reader      *bufio.Reader
	writer      io.Writer
	writerMu    sync.Mutex
	scanner     engine.Scanner
	documents   map[string]*documentState // uri -> content
	docMu       sync.RWMutex
	rules       []engine.Rule
	rootURI     string
	clientCaps  ClientCapabilities
}

type documentState struct {
	content  string
	version  int
	language string
	findings []engine.Finding
}

// NewServer creates a new LSP server
func NewServer(reader io.Reader, writer io.Writer) *Server {
	loader := engine.NewRulesLoader()
	rules, _ := loader.Load()

	return &Server{
		reader:    bufio.NewReader(reader),
		writer:    writer,
		documents: make(map[string]*documentState),
		rules:     rules,
	}
}

// Run starts the LSP server loop
func (s *Server) Run() error {
	for {
		msg, err := s.readMessage()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		if err := s.handleMessage(msg); err != nil {
			fmt.Fprintf(os.Stderr, "Error handling message: %v\n", err)
		}
	}
}

func (s *Server) readMessage() (*Message, error) {
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

	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
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

func (s *Server) writeNotification(method string, params interface{}) error {
	msg := struct {
		JSONRPC string      `json:"jsonrpc"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params"`
	}{
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

func (s *Server) handleMessage(msg *Message) error {
	switch msg.Method {
	case "initialize":
		return s.handleInitialize(msg)
	case "initialized":
		return nil // No response needed
	case "shutdown":
		return s.handleShutdown(msg)
	case "exit":
		os.Exit(0)
		return nil
	case "textDocument/didOpen":
		return s.handleDidOpen(msg)
	case "textDocument/didChange":
		return s.handleDidChange(msg)
	case "textDocument/didSave":
		return s.handleDidSave(msg)
	case "textDocument/didClose":
		return s.handleDidClose(msg)
	case "textDocument/codeAction":
		return s.handleCodeAction(msg)
	case "textDocument/hover":
		return s.handleHover(msg)
	case "textDocument/codeLens":
		return s.handleCodeLens(msg)
	case "textDocument/diagnostic":
		return s.handleDocumentDiagnostic(msg)
	default:
		if msg.ID != nil {
			return s.writeResponse(&Response{
				JSONRPC: "2.0",
				ID:      msg.ID,
				Error: &RPCError{
					Code:    -32601,
					Message: fmt.Sprintf("Method not found: %s", msg.Method),
				},
			})
		}
		return nil
	}
}

func (s *Server) handleInitialize(msg *Message) error {
	var params InitializeParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.rootURI = params.RootURI
	s.clientCaps = params.Capabilities

	result := InitializeResult{
		Capabilities: ServerCapabilities{
			TextDocumentSync:   1, // Full document sync
			CodeActionProvider: true,
			HoverProvider:      true,
			CodeLensProvider: &CodeLensOptions{
				ResolveProvider: false,
			},
			DiagnosticProvider: &DiagnosticOptions{
				Identifier:            "raven",
				InterFileDependencies: false,
				WorkspaceDiagnostics:  false,
			},
			Workspace: &WorkspaceOptions{
				WorkspaceFolders: WorkspaceFoldersOptions{
					Supported:           true,
					ChangeNotifications: false,
				},
			},
		},
		ServerInfo: ServerInfo{
			Name:    "raven-lsp",
			Version: "1.14.0",
		},
	}

	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  result,
	}

	return s.writeResponse(resp)
}

func (s *Server) handleShutdown(msg *Message) error {
	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  nil,
	}
	return s.writeResponse(resp)
}

func (s *Server) handleDidOpen(msg *Message) error {
	var params DidOpenTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.docMu.Lock()
	s.documents[params.TextDocument.URI] = &documentState{
		content:  params.TextDocument.Text,
		version:  params.TextDocument.Version,
		language: params.TextDocument.LanguageID,
	}
	s.docMu.Unlock()

	return s.scanDocument(params.TextDocument.URI, params.TextDocument.Text, params.TextDocument.Version)
}

func (s *Server) handleDidChange(msg *Message) error {
	var params DidChangeTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	if len(params.ContentChanges) > 0 {
		content := params.ContentChanges[0].Text

		s.docMu.Lock()
		if state, ok := s.documents[params.TextDocument.URI]; ok {
			state.content = content
			state.version = params.TextDocument.Version
		} else {
			s.documents[params.TextDocument.URI] = &documentState{
				content: content,
				version: params.TextDocument.Version,
			}
		}
		s.docMu.Unlock()

		// Scan on change for small files (<1000 lines) to provide real-time feedback
		if strings.Count(content, "\n") < 1000 {
			return s.scanDocument(params.TextDocument.URI, content, params.TextDocument.Version)
		}
	}

	return nil
}

func (s *Server) handleDidSave(msg *Message) error {
	var params DidSaveTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.docMu.RLock()
	state, ok := s.documents[params.TextDocument.URI]
	s.docMu.RUnlock()
	if !ok {
		return nil
	}

	return s.scanDocument(params.TextDocument.URI, state.content, state.version)
}

func (s *Server) handleDidClose(msg *Message) error {
	var params DidCloseTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.docMu.Lock()
	delete(s.documents, params.TextDocument.URI)
	s.docMu.Unlock()

	// Clear diagnostics for closed document
	return s.writeNotification("textDocument/publishDiagnostics", PublishDiagnosticsParams{
		URI:         params.TextDocument.URI,
		Version:     0,
		Diagnostics: []Diagnostic{},
	})
}

func (s *Server) scanDocument(uri, content string, version int) error {
	// Write content to temp file for scanning
	tmpFile, err := os.CreateTemp("", "raven-lsp-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		return err
	}
	tmpFile.Close()

	// Determine language from URI
	ext := filepath.Ext(uri)
	lang := languageFromExt(ext)

	// Filter rules by language
	var activeRules []engine.Rule
	for _, rule := range s.rules {
		if len(rule.Languages) > 0 && !contains(rule.Languages, lang) && !contains(rule.Languages, "*") {
			continue
		}
		activeRules = append(activeRules, rule)
	}

	scanner := engine.NewScanner(activeRules, engine.ScanConfig{
		Paths:      []string{tmpFile.Name()},
		Confidence: "low",
	})

	result, err := scanner.Scan()
	if err != nil {
		return err
	}

	// Convert findings to diagnostics with better positioning
	var diagnostics []Diagnostic
	lines := strings.Split(content, "\n")

	for _, finding := range result.Findings {
		severity := DiagnosticSeverityInformation
		switch finding.Severity {
		case engine.Critical, engine.High:
			severity = DiagnosticSeverityError
		case engine.Medium:
			severity = DiagnosticSeverityWarning
		case engine.Low:
			severity = DiagnosticSeverityInformation
		}

		lineIdx := finding.Line - 1
		if lineIdx < 0 {
			lineIdx = 0
		}
		if lineIdx >= len(lines) {
			lineIdx = len(lines) - 1
		}

		lineText := ""
		if lineIdx < len(lines) {
			lineText = lines[lineIdx]
		}

		// Try to find the actual vulnerable substring in the line
		startChar, endChar := computeRange(lineText, finding.Snippet, finding.Column)

		diag := Diagnostic{
			Range: Range{
				Start: Position{Line: lineIdx, Character: startChar},
				End:   Position{Line: lineIdx, Character: endChar},
			},
			Severity: severity,
			Code:     finding.RuleID,
			Source:   "raven",
			Message:  fmt.Sprintf("[%s] %s", finding.Severity, finding.Message),
		}

		// Add related information with fix suggestion if available
		if finding.FixAvailable && finding.Fix != nil {
			diag.RelatedInformation = append(diag.RelatedInformation, DiagnosticRelatedInformation{
				Location: Location{
					URI: uri,
					Range: Range{
						Start: Position{Line: lineIdx, Character: 0},
						End:   Position{Line: lineIdx, Character: len(lineText)},
					},
				},
				Message: fmt.Sprintf("💡 Fix: %s", finding.Fix.Description),
			})
		}

		diagnostics = append(diagnostics, diag)
	}

	// Store findings for hover/codeLens
	s.docMu.Lock()
	if state, ok := s.documents[uri]; ok {
		state.findings = result.Findings
	}
	s.docMu.Unlock()

	// Publish diagnostics
	return s.writeNotification("textDocument/publishDiagnostics", PublishDiagnosticsParams{
		URI:         uri,
		Version:     version,
		Diagnostics: diagnostics,
	})
}

func (s *Server) handleCodeAction(msg *Message) error {
	var params CodeActionParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	var actions []CodeAction

	for _, diag := range params.Context.Diagnostics {
		if diag.Source != "raven" {
			continue
		}

		// Find the rule and its fix
		var fix *engine.Fix
		for _, rule := range s.rules {
			if rule.ID == diag.Code && rule.Fix != nil {
				fix = rule.Fix
				break
			}
		}

		if fix != nil {
			actions = append(actions, CodeAction{
				Title: fmt.Sprintf("🔒 %s", fix.Description),
				Kind:  "quickfix",
				Edit: &WorkspaceEdit{
					Changes: map[string][]TextEdit{
						params.TextDocument.URI: {{
							Range:   diag.Range,
							NewText: fix.Replace,
						}},
					},
				},
			})
		} else {
			actions = append(actions, CodeAction{
				Title: fmt.Sprintf("🔒 Fix %s", diag.Code),
				Kind:  "quickfix",
				Command: &Command{
					Title:   "Fix with Raven",
					Command: "raven.fix",
					Arguments: []interface{}{
						params.TextDocument.URI,
						diag.Range.Start.Line,
						diag.Code,
					},
				},
			})
		}

		// Add "Learn more" action
		actions = append(actions, CodeAction{
			Title: fmt.Sprintf("📖 Learn about %s", diag.Code),
			Kind:  "quickfix",
			Command: &Command{
				Title:   "Open Raven Rule Documentation",
				Command: "raven.openRule",
				Arguments: []interface{}{
					diag.Code,
				},
			},
		})
	}

	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  actions,
	}

	return s.writeResponse(resp)
}

func (s *Server) handleHover(msg *Message) error {
	var params HoverParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.docMu.RLock()
	state, ok := s.documents[params.TextDocument.URI]
	s.docMu.RUnlock()

	if !ok || len(state.findings) == 0 {
		return s.writeResponse(&Response{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  Hover{Contents: MarkupContent{Kind: "markdown", Value: ""}},
		})
	}

	// Find if cursor is on a finding
	line := params.Position.Line + 1 // 0-based to 1-based
	var matchedFinding *engine.Finding
	for _, f := range state.findings {
		if f.Line == line {
			matchedFinding = &f
			break
		}
	}

	if matchedFinding == nil {
		return s.writeResponse(&Response{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  Hover{Contents: MarkupContent{Kind: "markdown", Value: ""}},
		})
	}

	// Find the rule for details
	var rule *engine.Rule
	for _, r := range s.rules {
		if r.ID == matchedFinding.RuleID {
			rule = &r
			break
		}
	}

	var value strings.Builder
	value.WriteString(fmt.Sprintf("## 🐦‍⬛ %s\n\n", matchedFinding.RuleName))
	value.WriteString(fmt.Sprintf("**ID:** `%s`\n\n", matchedFinding.RuleID))
	value.WriteString(fmt.Sprintf("**Severity:** `%s` | **Category:** %s\n\n", matchedFinding.Severity, matchedFinding.Category))

	if rule != nil {
		value.WriteString(fmt.Sprintf("**Description:** %s\n\n", rule.Description))
	}

	value.WriteString(fmt.Sprintf("**Issue:** %s\n\n", matchedFinding.Message))

	if matchedFinding.FixAvailable && matchedFinding.Fix != nil {
		value.WriteString(fmt.Sprintf("**💡 Fix:** %s\n\n", matchedFinding.Fix.Description))
	}

	if rule != nil && len(rule.References) > 0 {
		value.WriteString("**References:**\n")
		for _, ref := range rule.References {
			value.WriteString(fmt.Sprintf("- %s\n", ref))
		}
	}

	hover := Hover{
		Contents: MarkupContent{
			Kind:  "markdown",
			Value: value.String(),
		},
		Range: &Range{
			Start: Position{Line: params.Position.Line, Character: 0},
			End:   Position{Line: params.Position.Line, Character: 100},
		},
	}

	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  hover,
	}

	return s.writeResponse(resp)
}

func (s *Server) handleCodeLens(msg *Message) error {
	var params CodeLensParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.docMu.RLock()
	state, ok := s.documents[params.TextDocument.URI]
	s.docMu.RUnlock()

	var lenses []CodeLens
	if ok && len(state.findings) > 0 {
		// Count by severity
		criticalHigh := 0
		medium := 0
		low := 0
		for _, f := range state.findings {
			switch f.Severity {
			case engine.Critical, engine.High:
				criticalHigh++
			case engine.Medium:
				medium++
			default:
				low++
			}
		}

		var title string
		if criticalHigh > 0 {
			title = fmt.Sprintf("🔒 Raven: %d critical/high findings", criticalHigh)
		} else if medium > 0 {
			title = fmt.Sprintf("🔒 Raven: %d medium findings", medium)
		} else {
			title = fmt.Sprintf("🔒 Raven: %d findings", len(state.findings))
		}

		lenses = append(lenses, CodeLens{
			Range: Range{
				Start: Position{Line: 0, Character: 0},
				End:   Position{Line: 0, Character: 0},
			},
			Command: &Command{
				Title:   title,
				Command: "raven.showFindings",
				Arguments: []interface{}{
					params.TextDocument.URI,
				},
			},
		})
	} else {
		lenses = append(lenses, CodeLens{
			Range: Range{
				Start: Position{Line: 0, Character: 0},
				End:   Position{Line: 0, Character: 0},
			},
			Command: &Command{
				Title:   "🔒 Raven: No issues found",
				Command: "raven.noOp",
			},
		})
	}

	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  lenses,
	}

	return s.writeResponse(resp)
}

func (s *Server) handleDocumentDiagnostic(msg *Message) error {
	var params DocumentDiagnosticParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.docMu.RLock()
	state, ok := s.documents[params.TextDocument.URI]
	s.docMu.RUnlock()

	var diagnostics []Diagnostic
	if ok {
		lines := strings.Split(state.content, "\n")
		for _, finding := range state.findings {
			severity := DiagnosticSeverityInformation
			switch finding.Severity {
			case engine.Critical, engine.High:
				severity = DiagnosticSeverityError
			case engine.Medium:
				severity = DiagnosticSeverityWarning
			case engine.Low:
				severity = DiagnosticSeverityInformation
			}

			lineIdx := finding.Line - 1
			if lineIdx < 0 {
				lineIdx = 0
			}
			lineText := ""
			if lineIdx < len(lines) {
				lineText = lines[lineIdx]
			}
			startChar, endChar := computeRange(lineText, finding.Snippet, finding.Column)

			diagnostics = append(diagnostics, Diagnostic{
				Range: Range{
					Start: Position{Line: lineIdx, Character: startChar},
					End:   Position{Line: lineIdx, Character: endChar},
				},
				Severity: severity,
				Code:     finding.RuleID,
				Source:   "raven",
				Message:  fmt.Sprintf("[%s] %s", finding.Severity, finding.Message),
			})
		}
	}

	report := DocumentDiagnosticReport{
		Kind:  "full",
		Items: diagnostics,
	}

	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  report,
	}

	return s.writeResponse(resp)
}

// Helpers

func languageFromExt(ext string) string {
	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".tsx":
		return "tsx"
	case ".py", ".pyw":
		return "python"
	case ".go":
		return "go"
	case ".php":
		return "php"
	case ".rs":
		return "rust"
	case ".java":
		return "java"
	case ".kt":
		return "kotlin"
	case ".cs":
		return "csharp"
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

// computeRange tries to find the best character range for a diagnostic
func computeRange(lineText, snippet string, column int) (start, end int) {
	if lineText == "" {
		return 0, 0
	}

	// If we have a snippet, try to find it in the line
	if snippet != "" {
		cleanSnippet := strings.TrimSpace(snippet)
		// Try exact match
		if idx := strings.Index(lineText, cleanSnippet); idx >= 0 {
			return idx, idx + len(cleanSnippet)
		}
		// Try first line of multiline snippet
		firstLine := strings.Split(cleanSnippet, "\n")[0]
		firstLine = strings.TrimSpace(firstLine)
		if idx := strings.Index(lineText, firstLine); idx >= 0 {
			return idx, idx + len(firstLine)
		}
	}

	// Fallback to column hint
	if column > 0 {
		start = column - 1
		if start >= len(lineText) {
			start = 0
		}
		end = start + 20
		if end > len(lineText) {
			end = len(lineText)
		}
		return start, end
	}

	// Default: highlight first non-whitespace chars
	for i, ch := range lineText {
		if ch != ' ' && ch != '\t' {
			return i, min(i+20, len(lineText))
		}
	}

	return 0, min(20, len(lineText))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
