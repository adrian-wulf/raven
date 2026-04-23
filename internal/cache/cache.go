package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Entry stores cached findings for a single file.
type Entry struct {
	Hash     string          `json:"hash"`
	Findings json.RawMessage `json:"findings"`
}

// Cache stores scan results keyed by file path.
type Cache struct {
	entries map[string]Entry
	path    string // path to cache file on disk
	mu      sync.RWMutex
}

// New creates an in-memory cache.
func New() *Cache {
	return &Cache{entries: make(map[string]Entry)}
}

// Load reads a cache from disk.
func Load(path string) (*Cache, error) {
	c := New()
	c.path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil // no cache yet
		}
		return nil, fmt.Errorf("reading cache: %w", err)
	}
	if err := json.Unmarshal(data, &c.entries); err != nil {
		return nil, fmt.Errorf("parsing cache: %w", err)
	}
	return c, nil
}

// Save persists the cache to disk.
func (c *Cache) Save() error {
	if c.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding cache: %w", err)
	}
	if err := os.WriteFile(c.path, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	return nil
}

// SetPath sets the on-disk path for the cache.
func (c *Cache) SetPath(path string) {
	c.path = path
}

// IsFresh reports whether the file's current hash matches the cache.
func (c *Cache) IsFresh(file string) bool {
	c.mu.RLock()
	entry, ok := c.entries[file]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	hash, err := fileHash(file)
	if err != nil {
		return false
	}
	return entry.Hash == hash
}

// Get returns cached findings as JSON (nil if not cached or stale).
func (c *Cache) Get(file string) json.RawMessage {
	if !c.IsFresh(file) {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[file].Findings
}

// Store saves findings for a file in the cache.
func (c *Cache) Store(file string, findingsJSON json.RawMessage) error {
	hash, err := fileHash(file)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.entries[file] = Entry{Hash: hash, Findings: findingsJSON}
	c.mu.Unlock()
	return nil
}

// fileHash returns the SHA256 hash of a file's contents.
func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
