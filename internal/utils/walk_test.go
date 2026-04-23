package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWalkFollowsSymlinkToDir(t *testing.T) {
	tmp := t.TempDir()

	// Create real dir with a file
	realDir := filepath.Join(tmp, "real")
	os.Mkdir(realDir, 0755)
	os.WriteFile(filepath.Join(realDir, "file.txt"), []byte("hello"), 0644)

	// Create symlink to real dir
	linkDir := filepath.Join(tmp, "link")
	os.Symlink(realDir, linkDir)

	var files []string
	err := Walk(tmp, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	found := false
	for _, f := range files {
		if f == "file.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find file.txt through symlink, got: %v", files)
	}
}

func TestWalkSkipsCyclicSymlinks(t *testing.T) {
	tmp := t.TempDir()

	// Create cyclic symlink: a -> b, b -> a
	a := filepath.Join(tmp, "a")
	b := filepath.Join(tmp, "b")
	os.Symlink(b, a)
	os.Symlink(a, b)

	var visitCount int
	err := Walk(tmp, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // ignore errors from broken symlinks
		}
		visitCount++
		return nil
	})
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	// Should visit tmp, a, b (but not loop forever)
	if visitCount > 5 {
		t.Errorf("possible infinite loop: visited %d times", visitCount)
	}
}

func TestWalkHandlesRegularFiles(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(tmp, "b.txt"), []byte("b"), 0644)

	var files []string
	err := Walk(tmp, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d: %v", len(files), files)
	}
}
