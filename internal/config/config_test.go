package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.Output.Format != "pretty" {
		t.Errorf("expected format pretty, got %s", cfg.Output.Format)
	}
	if !cfg.Output.Color {
		t.Error("expected Color to be true")
	}
	if cfg.Rules.Confidence != "medium" {
		t.Errorf("expected confidence medium, got %s", cfg.Rules.Confidence)
	}
}

func TestLoadWithConfigFile(t *testing.T) {
	tmp := t.TempDir()
	originalWd, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(originalWd)

	content := `rules:
  confidence: high
output:
  format: json
`
	os.WriteFile(filepath.Join(tmp, ".raven.yaml"), []byte(content), 0644)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Rules.Confidence != "high" {
		t.Errorf("expected confidence high, got %s", cfg.Rules.Confidence)
	}
	if cfg.Output.Format != "json" {
		t.Errorf("expected format json, got %s", cfg.Output.Format)
	}
}

func TestLoadIgnoresBinaryFile(t *testing.T) {
	tmp := t.TempDir()
	originalWd, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(originalWd)

	// Create a binary file named "raven" that would be picked up by old config name
	os.WriteFile(filepath.Join(tmp, "raven"), []byte{0x00, 0x7f, 0x01}, 0644)

	// No .raven.yaml exists - should use defaults without error
	_, err := Load()
	if err != nil {
		t.Fatalf("Load failed with binary file present: %v", err)
	}
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("RAVEN_RULES_CONFIDENCE", "low")
	defer os.Unsetenv("RAVEN_RULES_CONFIDENCE")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Rules.Confidence != "low" {
		t.Errorf("expected confidence low from env, got %s", cfg.Rules.Confidence)
	}
}

func TestConfigDir(t *testing.T) {
	dir := ConfigDir()
	if !strings.Contains(dir, "raven") {
		t.Errorf("expected ConfigDir to contain 'raven', got %s", dir)
	}
}
