package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectAWSKey(t *testing.T) {
	d := NewDetector()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.js")
	os.WriteFile(path, []byte(`const key = "AKIAIOSFODNN7EXAMPLE";`), 0644)

	findings, err := d.Detect(path)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "aws_key" {
		t.Errorf("expected aws_key, got %s", findings[0].Type)
	}
}

func TestDetectPrivateKey(t *testing.T) {
	d := NewDetector()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "key.pem")
	os.WriteFile(path, []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...`), 0644)

	findings, err := d.Detect(path)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "private_key" {
		t.Errorf("expected private_key, got %s", findings[0].Type)
	}
}

func TestDetectAPIKey(t *testing.T) {
	d := NewDetector()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.py")
	os.WriteFile(path, []byte(`API_KEY = "sk_live_abc123xyz789secretkey"`), 0644)

	findings, err := d.Detect(path)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for API key")
	}
	found := false
	for _, f := range findings {
		if f.Type == "api_key" || f.Type == "high_entropy" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected api_key or high_entropy finding, got %v", findings)
	}
}

func TestExcludesTestValues(t *testing.T) {
	d := NewDetector()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.js")
	os.WriteFile(path, []byte(`const key = "test_key_example";
const pwd = "password123";`), 0644)

	findings, err := d.Detect(path)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "api_key" || f.Type == "password" {
			t.Errorf("should exclude test values, found %s: %s", f.Type, f.Match)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	// Low entropy string
	low := shannonEntropy("aaaaaaaaaaaaaaaa")
	if low > 1.0 {
		t.Errorf("expected low entropy, got %f", low)
	}

	// High entropy string
	high := shannonEntropy("aB3#kL9$mN2@pQ5&")
	if high < 3.5 {
		t.Errorf("expected high entropy, got %f", high)
	}
}

func TestDetectHighEntropy(t *testing.T) {
	d := NewDetector()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "env")
	os.WriteFile(path, []byte(`SECRET="aB3#kL9$mN2@pQ5&xY7^nB4*vF2"`), 0644)

	findings, err := d.Detect(path)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "high_entropy" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected high_entropy finding, got %v", findings)
	}
}

func TestDetectGitHubToken(t *testing.T) {
	d := NewDetector()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config")
	os.WriteFile(path, []byte(`token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`), 0644)

	findings, err := d.Detect(path)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "github_token" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected github_token finding, got %v", findings)
	}
}

func TestDetectNoSecrets(t *testing.T) {
	d := NewDetector()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "safe.js")
	os.WriteFile(path, []byte(`const x = 1;
const y = "hello world";`), 0644)

	findings, err := d.Detect(path)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
