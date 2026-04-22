package lsp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	ProcessID int    `json:"processId"`
	RootURI   string `json:"rootUri"`
	RootPath  string `json:"rootPath"`
}

// InitializeResult represents LSP initialize result
type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities"`
}

// ServerCapabilities represents LSP server capabilities
type ServerCapabilities struct {
	TextDocumentSync   int                  `json:"textDocumentSync"`
	CodeActionProvider bool                 `json:"codeActionProvider"`
	HoverProvider      bool                 `json:"hoverProvider"`
	DiagnosticProvider *DiagnosticOptions   `json:"diagnosticProvider,omitempty"`
}

// DiagnosticOptions represents diagnostic options
type DiagnosticOptions struct {
	Identifier            string `json:"identifier"`
	InterFileDependencies bool   `json:"interFileDependencies"`
	WorkspaceDiagnostics  bool   `json:"workspaceDiagnostics"`
}

// TextDocumentItem represents a text document
type TextDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

// TextDocumentIdentifier represents a text document identifier
type TextDocumentIdentifier struct {
	URI string `json:"uri"`
}

// VersionedTextDocumentIdentifier represents a versioned text document
type VersionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version int    `json:"version"`
}

// TextDocumentContentChangeEvent represents a content change
type TextDocumentContentChangeEvent struct {
	Text string `json:"text"`
}

// DidOpenTextDocumentParams represents didOpen params
type DidOpenTextDocumentParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

// DidChangeTextDocumentParams represents didChange params
type DidChangeTextDocumentParams struct {
	TextDocument   VersionedTextDocumentIdentifier `json:"textDocument"`
	ContentChanges []TextDocumentContentChangeEvent  `json:"contentChanges"`
}

// DidSaveTextDocumentParams represents didSave params
type DidSaveTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// PublishDiagnosticsParams represents diagnostics to publish
type PublishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Version     int          `json:"version"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// Diagnostic represents a single diagnostic
type Diagnostic struct {
	Range          Range      `json:"range"`
	Severity       int        `json:"severity"`
	Code           string     `json:"code"`
	Source         string     `json:"source"`
	Message        string     `json:"message"`
	RelatedInformation []DiagnosticRelatedInformation `json:"relatedInformation,omitempty"`
}

// Range represents a range in a document
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Position represents a position in a document
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// DiagnosticRelatedInformation represents related diagnostic info
type DiagnosticRelatedInformation struct {
	Location Location `json:"location"`
	Message  string   `json:"message"`
}

// Location represents a location in a document
type Location struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

// CodeActionParams represents code action params
type CodeActionParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Range        Range                  `json:"range"`
	Context      CodeActionContext      `json:"context"`
}

// CodeActionContext represents code action context
type CodeActionContext struct {
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// CodeAction represents a code action
type CodeAction struct {
	Title   string      `json:"title"`
	Kind    string      `json:"kind"`
	Edit    *WorkspaceEdit `json:"edit,omitempty"`
	Command *Command       `json:"command,omitempty"`
}

// WorkspaceEdit represents a workspace edit
type WorkspaceEdit struct {
	Changes map[string][]TextEdit `json:"changes"`
}

// TextEdit represents a text edit
type TextEdit struct {
	Range   Range  `json:"range"`
	NewText string `json:"newText"`
}

// Command represents a command
type Command struct {
	Title     string        `json:"title"`
	Command   string        `json:"command"`
	Arguments []interface{} `json:"arguments"`
}

// HoverParams represents hover params
type HoverParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Position     Position               `json:"position"`
}

// Hover represents hover result
type Hover struct {
	Contents MarkupContent `json:"contents"`
	Range    *Range        `json:"range,omitempty"`
}

// MarkupContent represents markup content
type MarkupContent struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

const (
	DiagnosticSeverityError       = 1
	DiagnosticSeverityWarning     = 2
	DiagnosticSeverityInformation = 3
	DiagnosticSeverityHint        = 4
)

// Server represents the Raven LSP server
type Server struct {
	reader    *bufio.Reader
	writer    io.Writer
	scanner   engine.Scanner
	documents map[string]string // uri -> content
	rules     []engine.Rule
}

// NewServer creates a new LSP server
func NewServer(reader io.Reader, writer io.Writer) *Server {
	loader := engine.NewRulesLoader()
	rules, _ := loader.Load()

	return &Server{
		reader:    bufio.NewReader(reader),
		writer:    writer,
		documents: make(map[string]string),
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
	// Read headers
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

	// Read body
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

func (s *Server) writeMessage(resp *Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}

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
	case "textDocument/codeAction":
		return s.handleCodeAction(msg)
	case "textDocument/hover":
		return s.handleHover(msg)
	default:
		// Ignore unknown methods
		return nil
	}
}

func (s *Server) handleInitialize(msg *Message) error {
	result := InitializeResult{
		Capabilities: ServerCapabilities{
			TextDocumentSync:   1, // Full document sync
			CodeActionProvider: true,
			HoverProvider:      true,
			DiagnosticProvider: &DiagnosticOptions{
				Identifier:            "raven",
				InterFileDependencies: false,
				WorkspaceDiagnostics:  false,
			},
		},
	}

	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  result,
	}

	return s.writeMessage(resp)
}

func (s *Server) handleShutdown(msg *Message) error {
	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  nil,
	}
	return s.writeMessage(resp)
}

func (s *Server) handleDidOpen(msg *Message) error {
	var params DidOpenTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.documents[params.TextDocument.URI] = params.TextDocument.Text
	return s.scanDocument(params.TextDocument.URI, params.TextDocument.Text, params.TextDocument.Version)
}

func (s *Server) handleDidChange(msg *Message) error {
	var params DidChangeTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	if len(params.ContentChanges) > 0 {
		s.documents[params.TextDocument.URI] = params.ContentChanges[0].Text
	}

	return nil
}

func (s *Server) handleDidSave(msg *Message) error {
	var params DidSaveTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	content, ok := s.documents[params.TextDocument.URI]
	if !ok {
		return nil
	}

	return s.scanDocument(params.TextDocument.URI, content, 0)
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
	lang := ""
	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs":
		lang = "javascript"
	case ".ts", ".tsx":
		lang = "typescript"
	case ".py":
		lang = "python"
	case ".go":
		lang = "go"
	case ".php":
		lang = "php"
	case ".rs":
		lang = "rust"
	case ".java":
		lang = "java"
	}

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

	// Convert findings to diagnostics
	var diagnostics []Diagnostic
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

		diagnostics = append(diagnostics, Diagnostic{
			Range: Range{
				Start: Position{Line: finding.Line - 1, Character: finding.Column - 1},
				End:   Position{Line: finding.Line - 1, Character: finding.Column + 20},
			},
			Severity: severity,
			Code:     finding.RuleID,
			Source:   "raven",
			Message:  fmt.Sprintf("[%s] %s", finding.Severity, finding.Message),
		})
	}

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

	// Generate fix actions for each diagnostic
	for _, diag := range params.Context.Diagnostics {
		if diag.Source != "raven" {
			continue
		}

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

	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  actions,
	}

	return s.writeMessage(resp)
}

func (s *Server) handleHover(msg *Message) error {
	var params HoverParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	hover := Hover{
		Contents: MarkupContent{
			Kind:  "markdown",
			Value: "**🐦‍⬛ Raven Security Scanner**\n\nHover over a vulnerability to see details.",
		},
	}

	resp := &Response{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  hover,
	}

	return s.writeMessage(resp)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
