package framework

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectExpress(t *testing.T) {
	tmp := t.TempDir()
	content := `{
		"dependencies": {
			"express": "^4.18.0"
		}
	}`
	os.WriteFile(filepath.Join(tmp, "package.json"), []byte(content), 0644)

	d := NewDetector(tmp)
	frameworks, err := d.Detect()
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, fw := range frameworks {
		if fw.Name == "express" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Express to be detected, got: %v", frameworks)
	}
}

func TestDetectGin(t *testing.T) {
	tmp := t.TempDir()
	content := `module example.com/test

go 1.21

require github.com/gin-gonic/gin v1.9.1
`
	os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(content), 0644)

	d := NewDetector(tmp)
	frameworks, err := d.Detect()
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, fw := range frameworks {
		if fw.Name == "gin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Gin to be detected, got: %v", frameworks)
	}
}

func TestDetectFlask(t *testing.T) {
	tmp := t.TempDir()
	content := `flask==2.3.0
requests==2.28.1
`
	os.WriteFile(filepath.Join(tmp, "requirements.txt"), []byte(content), 0644)

	d := NewDetector(tmp)
	frameworks, err := d.Detect()
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, fw := range frameworks {
		if fw.Name == "flask" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Flask to be detected, got: %v", frameworks)
	}
}

func TestDetectLaravel(t *testing.T) {
	tmp := t.TempDir()
	content := `{
		"require": {
			"laravel/framework": "^10.0"
		}
	}`
	os.WriteFile(filepath.Join(tmp, "composer.json"), []byte(content), 0644)

	d := NewDetector(tmp)
	frameworks, err := d.Detect()
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, fw := range frameworks {
		if fw.Name == "laravel" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Laravel to be detected, got: %v", frameworks)
	}
}

func TestDetectNoFrameworks(t *testing.T) {
	tmp := t.TempDir()

	d := NewDetector(tmp)
	frameworks, err := d.Detect()
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(frameworks) != 0 {
		t.Errorf("expected no frameworks, got: %v", frameworks)
	}
}
