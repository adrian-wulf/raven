package lsp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

func TestLSPInitialize(t *testing.T) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}

	server := NewServer(in, out)

	req := Message{
		JSONRPC: "2.0",
		ID:      intPtr(1),
		Method:  "initialize",
		Params:  json.RawMessage(`{"processId":123,"rootUri":"file:///tmp/test","capabilities":{}}`),
	}

	err := server.handleInitialize(&req)
	if err != nil {
		t.Fatalf("handleInitialize returned error: %v", err)
	}
}

func TestLSPCalculateRange(t *testing.T) {
	tests := []struct {
		lineText string
		snippet  string
		column   int
		wantStart int
		wantEnd   int
	}{
		{"eval($GET['cmd'])", "eval(", 1, 0, 5},
		{"  console.log(x)", "console.log", 3, 2, 13},
		{"", "", 0, 0, 0},
		{"test", "", 2, 1, 4},
	}

	for _, tt := range tests {
		start, end := computeRange(tt.lineText, tt.snippet, tt.column)
		if tt.wantStart >= 0 && start != tt.wantStart {
			t.Errorf("computeRange(%q, %q, %d) start = %d, want %d", tt.lineText, tt.snippet, tt.column, start, tt.wantStart)
		}
		if tt.wantEnd >= 0 && end != tt.wantEnd {
			t.Errorf("computeRange(%q, %q, %d) end = %d, want %d", tt.lineText, tt.snippet, tt.column, end, tt.wantEnd)
		}
	}
}

func TestLanguageFromExt(t *testing.T) {
	tests := []struct {
		ext      string
		expected string
	}{
		{".js", "javascript"},
		{".ts", "typescript"},
		{".py", "python"},
		{".go", "go"},
		{".php", "php"},
		{".rs", "rust"},
		{".java", "java"},
		{".kt", "kotlin"},
		{".cs", "csharp"},
		{".rb", "ruby"},
		{".swift", "swift"},
		{".xyz", ""},
	}

	for _, tt := range tests {
		result := languageFromExt(tt.ext)
		if result != tt.expected {
			t.Errorf("languageFromExt(%q) = %q, want %q", tt.ext, result, tt.expected)
		}
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("contains should return true for existing item")
	}
	if contains([]string{"a", "b", "c"}, "d") {
		t.Error("contains should return false for non-existing item")
	}
	if !contains([]string{"Go", "Python"}, "go") {
		t.Error("contains should be case-insensitive")
	}
}

func intPtr(i int) *int {
	return &i
}

func writeTestMessage(buf *bytes.Buffer, msg Message) {
	data, _ := json.Marshal(msg)
	fmt.Fprintf(buf, "Content-Length: %d\r\n\r\n%s", len(data), data)
}
