package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheRoundtrip(t *testing.T) {
	tmp := t.TempDir()
	cachePath := filepath.Join(tmp, "cache.json")
	filePath := filepath.Join(tmp, "test.js")
	os.WriteFile(filePath, []byte("console.log(1);"), 0644)

	c, err := Load(cachePath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	c.SetPath(cachePath)

	findings := []map[string]interface{}{{"rule_id": "R001", "line": 1}}
	data, _ := json.Marshal(findings)
	if err := c.Store(filePath, data); err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	c2, err := Load(cachePath)
	if err != nil {
		t.Fatalf("Load2 failed: %v", err)
	}

	if !c2.IsFresh(filePath) {
		t.Error("expected file to be fresh")
	}
	got := c2.Get(filePath)
	if got == nil {
		t.Fatal("expected cached findings")
	}
	var parsed []map[string]interface{}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(parsed) != 1 || parsed[0]["rule_id"] != "R001" {
		t.Errorf("unexpected findings: %v", parsed)
	}
}

func TestCacheMissOnChange(t *testing.T) {
	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "test.js")
	os.WriteFile(filePath, []byte("console.log(1);"), 0644)

	c := New()
	data, _ := json.Marshal([]map[string]interface{}{{"rule_id": "R001"}})
	c.Store(filePath, data)

	// Modify file
	os.WriteFile(filePath, []byte("console.log(2);"), 0644)

	if c.IsFresh(filePath) {
		t.Error("expected file to be stale after modification")
	}
	if c.Get(filePath) != nil {
		t.Error("expected nil findings for stale cache entry")
	}
}

func TestFileHash(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.txt")
	os.WriteFile(path, []byte("hello"), 0644)

	h1, err := fileHash(path)
	if err != nil {
		t.Fatalf("fileHash failed: %v", err)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex hash, got %d", len(h1))
	}

	os.WriteFile(path, []byte("world"), 0644)
	h2, _ := fileHash(path)
	if h1 == h2 {
		t.Error("expected different hashes for different contents")
	}
}
