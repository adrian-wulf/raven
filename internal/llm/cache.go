package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const cacheFileName = ".raven-ai-cache.json"
const cacheTTL = 30 * 24 * time.Hour // 30 days

// AICacheEntry stores a single cached AI fix
type AICacheEntry struct {
	Hash        string    `json:"hash"`
	FixedCode   string    `json:"fixed_code"`
	Explanation string    `json:"explanation"`
	Confidence  float64   `json:"confidence"`
	Model       string    `json:"model"`
	Provider    string    `json:"provider"`
	Timestamp   time.Time `json:"timestamp"`
}

// AICache manages caching of AI-generated fixes
type AICache struct {
	mu      sync.RWMutex
	entries map[string]AICacheEntry
	path    string
	dirty   bool
}

// NewAICache creates or loads the AI fix cache
func NewAICache() *AICache {
	path := filepath.Join(findProjectRoot(), cacheFileName)
	// If not in project, use home dir
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, cacheFileName)
	}

	c := &AICache{
		entries: make(map[string]AICacheEntry),
		path:    path,
	}
	c.load()
	return c
}

// Get looks up a cached fix by request parameters
func (c *AICache) Get(code, vulnType, language, model, provider string) (*FixResponse, bool) {
	hash := cacheKey(code, vulnType, language, model, provider)

	c.mu.RLock()
	entry, ok := c.entries[hash]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	// Check TTL
	if time.Since(entry.Timestamp) > cacheTTL {
		c.mu.Lock()
		delete(c.entries, hash)
		c.dirty = true
		c.mu.Unlock()
		return nil, false
	}

	return &FixResponse{
		FixedCode:   entry.FixedCode,
		Explanation: entry.Explanation,
		Confidence:  entry.Confidence,
	}, true
}

// Set stores a fix in the cache
func (c *AICache) Set(code, vulnType, language, model, provider string, resp *FixResponse) {
	hash := cacheKey(code, vulnType, language, model, provider)

	c.mu.Lock()
	c.entries[hash] = AICacheEntry{
		Hash:        hash,
		FixedCode:   resp.FixedCode,
		Explanation: resp.Explanation,
		Confidence:  resp.Confidence,
		Model:       model,
		Provider:    provider,
		Timestamp:   time.Now(),
	}
	c.dirty = true
	c.mu.Unlock()
}

// Save persists the cache to disk
func (c *AICache) Save() error {
	c.mu.RLock()
	if !c.dirty {
		c.mu.RUnlock()
		return nil
	}
	entries := make(map[string]AICacheEntry, len(c.entries))
	for k, v := range c.entries {
		entries[k] = v
	}
	c.mu.RUnlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(c.path, data, 0644); err != nil {
		return err
	}

	c.mu.Lock()
	c.dirty = false
	c.mu.Unlock()
	return nil
}

// Stats returns cache statistics
func (c *AICache) Stats() (total, valid int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total = len(c.entries)
	for _, e := range c.entries {
		if time.Since(e.Timestamp) <= cacheTTL {
			valid++
		}
	}
	return
}

// Clear removes all cached entries
func (c *AICache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]AICacheEntry)
	c.dirty = true
	c.mu.Unlock()
}

func (c *AICache) load() {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return // No cache yet
	}

	var entries map[string]AICacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return // Corrupted cache, ignore
	}

	c.mu.Lock()
	for k, v := range entries {
		// Skip expired entries on load
		if time.Since(v.Timestamp) <= cacheTTL {
			c.entries[k] = v
		}
	}
	c.mu.Unlock()
}

func cacheKey(code, vulnType, language, model, provider string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s", code, vulnType, language, model, provider)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func findProjectRoot() string {
	dir, _ := os.Getwd()
	for dir != "/" && dir != "" {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return ""
}
