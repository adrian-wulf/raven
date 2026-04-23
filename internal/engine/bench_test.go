package engine

import (
	"fmt"
	"os"
	"testing"

	"github.com/raven-security/raven/internal/cache"
)

func BenchmarkScanSmallProject(b *testing.B) {
	tmp := b.TempDir()
	// Create 10 small files
	for i := 0; i < 10; i++ {
		code := fmt.Sprintf(`
function handler(req, res) {
	var userId = req.body.id;
	db.query("SELECT * FROM users WHERE id = " + userId);
}
`)
		os.WriteFile(fmt.Sprintf("%s/file%d.js", tmp, i), []byte(code), 0644)
	}

	loader := NewRulesLoader()
	rules, _ := loader.Load()
	scanner := NewScanner(rules, ScanConfig{
		Paths:       []string{tmp},
		MinSeverity: Low,
		Confidence:  "low",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.Scan()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanMediumProject(b *testing.B) {
	tmp := b.TempDir()
	// Create 100 files
	for i := 0; i < 100; i++ {
		code := fmt.Sprintf(`
package main

func handler%d(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
`, i)
		os.WriteFile(fmt.Sprintf("%s/file%d.go", tmp, i), []byte(code), 0644)
	}

	loader := NewRulesLoader()
	rules, _ := loader.Load()
	scanner := NewScanner(rules, ScanConfig{
		Paths:       []string{tmp},
		MinSeverity: Low,
		Confidence:  "low",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.Scan()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanWithCache(b *testing.B) {
	tmp := b.TempDir()
	code := `
function handler(req, res) {
	var userId = req.body.id;
	db.query("SELECT * FROM users WHERE id = " + userId);
}
`
	os.WriteFile(tmp+"/test.js", []byte(code), 0644)

	loader := NewRulesLoader()
	rules, _ := loader.Load()

	// First scan to populate cache
	cachePath := tmp + "/.raven-cache.json"
	scanCache, _ := cache.Load(cachePath)
	scanCache.SetPath(cachePath)

	scanner := NewScanner(rules, ScanConfig{
		Paths:       []string{tmp},
		MinSeverity: Low,
		Confidence:  "low",
		Cache:       scanCache,
	})
	scanner.Scan()
	scanCache.Save()

	// Second scan should use cache
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanCache2, _ := cache.Load(cachePath)
		scanCache2.SetPath(cachePath)
		scanner2 := NewScanner(rules, ScanConfig{
			Paths:       []string{tmp},
			MinSeverity: Low,
			Confidence:  "low",
			Cache:       scanCache2,
		})
		_, err := scanner2.Scan()
		if err != nil {
			b.Fatal(err)
		}
	}
}
