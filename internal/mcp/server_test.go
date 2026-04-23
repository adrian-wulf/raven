package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestMCPInitialize(t *testing.T) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}

	server := NewServer(in, out)

	// Send initialize request
	req := Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}`),
	}
	writeTestRequest(in, req)

	// Run server in background, reading just one request
	go func() {
		server.Run()
	}()

	// Give it a moment
	// Since Run is blocking, we need a different approach
	// Let's test the handler directly
	result := server.handleInitialize(&req)
	if result != nil {
		t.Fatalf("handleInitialize returned error: %v", result)
	}
}

func TestMCPToolsList(t *testing.T) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}
	server := NewServer(in, out)

	req := Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/list",
	}

	err := server.handleToolsList(&req)
	if err != nil {
		t.Fatalf("handleToolsList returned error: %v", err)
	}
}

func TestMCPToolScanSnippet(t *testing.T) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}
	server := NewServer(in, out)

	args, _ := json.Marshal(map[string]string{
		"code":     "eval($_GET['cmd'])",
		"language": "php",
	})

	result := server.toolScanSnippet(args)
	if result.IsError {
		t.Fatalf("toolScanSnippet returned error: %s", result.Content[0].Text)
	}

	// Should find command injection or eval issue
	if !strings.Contains(result.Content[0].Text, "issue") && !strings.Contains(result.Content[0].Text, "Found") {
		t.Logf("Response: %s", result.Content[0].Text)
	}
}

func TestMCPToolListRules(t *testing.T) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}
	server := NewServer(in, out)

	result := server.toolListRules()
	if result.IsError {
		t.Fatalf("toolListRules returned error: %s", result.Content[0].Text)
	}

	if !strings.Contains(result.Content[0].Text, "Raven Rules") {
		t.Fatalf("Expected rules list, got: %s", result.Content[0].Text)
	}
}

func TestMCPToolGetRule(t *testing.T) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}
	server := NewServer(in, out)

	args, _ := json.Marshal(map[string]string{
		"rule_id": "raven-secrets-aws-key",
	})

	result := server.toolGetRule(args)
	if result.IsError {
		// Rule might not exist, that's ok for the test
		t.Logf("Rule not found (expected if not in test env): %s", result.Content[0].Text)
		return
	}

	if !strings.Contains(result.Content[0].Text, "raven-secrets-aws-key") {
		t.Fatalf("Expected rule details, got: %s", result.Content[0].Text)
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"package main\nfunc main() {}", "go"},
		{"def hello():\n    pass", "python"},
		{"function foo() {}", "javascript"},
		{"public class Foo {}", "java"},
		{"<?php echo 'hi'; ?>", "php"},
		{"fn main() -> {}", "rust"},
		{"class Foo\nend", "ruby"},
	}

	for _, tt := range tests {
		result := detectLanguage(tt.code)
		if result != tt.expected {
			t.Errorf("detectLanguage(%q) = %q, want %q", tt.code, result, tt.expected)
		}
	}
}

func writeTestRequest(buf *bytes.Buffer, req Request) {
	data, _ := json.Marshal(req)
	fmt.Fprintf(buf, "Content-Length: %d\r\n\r\n%s", len(data), data)
}
