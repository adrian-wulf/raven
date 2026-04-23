package cache

import (
	"os"
	"testing"
)

func TestSaveCreatesFile(t *testing.T) {
	c := New()
	c.SetPath("/tmp/test-raven-cache.json")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/tmp/test-raven-cache.json"); os.IsNotExist(err) {
		t.Error("cache file not created")
	}
	os.Remove("/tmp/test-raven-cache.json")
}
