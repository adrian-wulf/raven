package crossfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseJSImports(t *testing.T) {
	content := `
import express from 'express';
import { userInput, validate } from './utils';
const db = require('./db');
const { hashPassword } = require('./auth');
`
	imports := parseJSImports(content)
	if len(imports) != 4 {
		t.Fatalf("expected 4 imports, got %d: %v", len(imports), imports)
	}

	if imports[0].Source != "express" || len(imports[0].Names) != 1 || imports[0].Names[0] != "express" {
		t.Errorf("unexpected import[0]: %v", imports[0])
	}
	if imports[1].Source != "./utils" || len(imports[1].Names) != 2 {
		t.Errorf("unexpected import[1]: %v", imports[1])
	}
	if imports[2].Source != "./db" || imports[2].Names[0] != "db" {
		t.Errorf("unexpected import[2]: %v", imports[2])
	}
	if imports[3].Source != "./auth" || imports[3].Names[0] != "hashPassword" {
		t.Errorf("unexpected import[3]: %v", imports[3])
	}
}

func TestParseJSExports(t *testing.T) {
	content := `
module.exports = { getUser, createUser };
exports.validate = validateInput;
export const sanitize = (x) => x;
export default handler;
`
	exports := parseJSExports(content)
	if len(exports) != 5 {
		t.Fatalf("expected 5 exports, got %d: %v", len(exports), exports)
	}

	names := make(map[string]bool)
	for _, e := range exports {
		names[e.Name] = true
	}
	if !names["getUser"] || !names["createUser"] || !names["validate"] || !names["sanitize"] || !names["default"] {
		t.Errorf("missing expected exports: %v", exports)
	}
}

func TestScanDirectory(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "a.js"), []byte(`import { x } from './b';`), 0644)
	os.WriteFile(filepath.Join(tmp, "b.js"), []byte(`export const x = 1;`), 0644)
	os.WriteFile(filepath.Join(tmp, "c.go"), []byte(`package main\nimport "fmt"\nfunc Main() {}`), 0644)

	r := NewResolver()
	if err := r.ScanDirectory(tmp); err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(r.modules) != 3 {
		t.Errorf("expected 3 modules, got %d", len(r.modules))
	}

	info, ok := r.GetModuleInfo(filepath.Join(tmp, "a.js"))
	if !ok {
		t.Fatal("expected a.js to be parsed")
	}
	if len(info.Imports) != 1 || info.Imports[0].Source != "./b" {
		t.Errorf("unexpected imports in a.js: %v", info.Imports)
	}
}

func TestResolveImport(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "main.js"), []byte(`import { x } from './lib';`), 0644)
	os.WriteFile(filepath.Join(tmp, "lib.js"), []byte(`export const x = 1;`), 0644)

	r := NewResolver()
	r.ScanDirectory(tmp)

	resolved, ok := r.ResolveImport(filepath.Join(tmp, "main.js"), "./lib")
	if !ok {
		t.Fatal("expected to resolve ./lib")
	}
	if resolved != filepath.Join(tmp, "lib.js") {
		t.Errorf("expected %s, got %s", filepath.Join(tmp, "lib.js"), resolved)
	}
}

func TestIsTaintedSource(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "utils.js"), []byte(`
export const getUserInput = (req) => {
	return req.body.query;
};
`), 0644)

	r := NewResolver()
	r.ScanDirectory(tmp)

	if !r.IsTaintedSource(filepath.Join(tmp, "utils.js"), "getUserInput") {
		t.Error("expected getUserInput to be tainted source (req.body)")
	}
}

func TestParsePythonImports(t *testing.T) {
	content := `
from flask import request, Flask
import os, sys
`
	imports := parsePythonImports(content)
	if len(imports) != 2 {
		t.Fatalf("expected 2 imports, got %d: %v", len(imports), imports)
	}
	if imports[0].Source != "flask" || len(imports[0].Names) != 2 {
		t.Errorf("unexpected import[0]: %v", imports[0])
	}
}

func TestParseGoExports(t *testing.T) {
	content := `
package main
func PublicFunc() {}
func privateFunc() {}
var PublicVar int
`
	exports := parseGoExports(content)
	if len(exports) != 2 {
		t.Fatalf("expected 2 exports, got %d: %v", len(exports), exports)
	}
	if exports[0].Name != "PublicFunc" {
		t.Errorf("expected PublicFunc, got %s", exports[0].Name)
	}
}
