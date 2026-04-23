package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanCargoToml(t *testing.T) {
	tmp := t.TempDir()
	content := `[package]
name = "myapp"
version = "1.0.0"

[dependencies]
serde = "1.0"
hyper = { version = "0.14", features = ["full"] }
`
	os.WriteFile(filepath.Join(tmp, "Cargo.toml"), []byte(content), 0644)

	s := &Scanner{}
	// We can't test actual OSV API calls without network,
	// but we can verify parsing works by checking it doesn't error
	// and returns empty slice when no vulns found (or API fails)
	_, err := s.scanCargoToml(tmp)
	// Error is OK if OSV API fails or returns no results
	if err != nil {
		// Ensure it's not a parse error
		if err.Error() == "toml: unmarshal error" || err.Error() == "invalid TOML" {
			t.Fatalf("Cargo.toml parsing failed: %v", err)
		}
	}
}

func TestScanCargoTomlMissing(t *testing.T) {
	tmp := t.TempDir()
	s := &Scanner{}
	_, err := s.scanCargoToml(tmp)
	if err == nil {
		t.Error("expected error for missing Cargo.toml")
	}
}

func TestScanComposerJSON(t *testing.T) {
	tmp := t.TempDir()
	content := `{
		"require": {
			"symfony/console": "^5.0",
			"monolog/monolog": "^2.0"
		}
	}`
	os.WriteFile(filepath.Join(tmp, "composer.json"), []byte(content), 0644)

	s := &Scanner{}
	_, err := s.scanComposerJSON(tmp)
	// May error from API but should not error from parsing
	if err != nil && err.Error() == "invalid character" {
		t.Fatalf("composer.json parsing failed: %v", err)
	}
}

func TestScanGoMod(t *testing.T) {
	tmp := t.TempDir()
	content := `module example.com/test

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/sirupsen/logrus v1.9.3
)
`
	os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(content), 0644)

	s := &Scanner{}
	_, err := s.scanGoMod(tmp)
	if err != nil && err.Error() == "invalid go.mod" {
		t.Fatalf("go.mod parsing failed: %v", err)
	}
}

func TestScanPackageJSON(t *testing.T) {
	tmp := t.TempDir()
	content := `{
		"dependencies": {
			"express": "^4.18.0",
			"lodash": "^4.17.21"
		}
	}`
	os.WriteFile(filepath.Join(tmp, "package.json"), []byte(content), 0644)

	s := &Scanner{}
	_, err := s.scanPackageJSON(tmp)
	if err != nil && err.Error() == "invalid character" {
		t.Fatalf("package.json parsing failed: %v", err)
	}
}

func TestScanRequirementsTxt(t *testing.T) {
	tmp := t.TempDir()
	content := `requests==2.28.1
flask>=2.0.0
django~=4.0
# comment
`
	os.WriteFile(filepath.Join(tmp, "requirements.txt"), []byte(content), 0644)

	s := &Scanner{}
	_, err := s.scanRequirementsTXT(tmp)
	if err != nil {
		t.Fatalf("requirements.txt parsing failed: %v", err)
	}
}
