package utils

import (
	"os"
	"path/filepath"
)

// Walk follows symlinks to directories (unlike filepath.Walk).
// It tracks visited real paths to prevent infinite loops from cyclic symlinks.
func Walk(root string, walkFn filepath.WalkFunc) error {
	visited := make(map[string]bool)
	return walkRecursive(root, root, visited, walkFn)
}

func walkRecursive(root, path string, visited map[string]bool, walkFn filepath.WalkFunc) error {
	info, err := os.Lstat(path)
	if err != nil {
		return walkFn(path, info, err)
	}

	// Follow directory symlinks
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return walkFn(path, info, err)
		}
		realPath, err := filepath.Abs(target)
		if err != nil {
			realPath = target
		}
		if visited[realPath] {
			return nil // skip cycles
		}
		visited[realPath] = true

		targetInfo, err := os.Stat(target)
		if err != nil {
			return walkFn(path, info, err)
		}
		if targetInfo.IsDir() {
			// Report the symlink itself as a directory
			if err := walkFn(path, targetInfo, nil); err != nil {
				if err == filepath.SkipDir {
					return nil
				}
				return err
			}
			entries, err := os.ReadDir(target)
			if err != nil {
				return walkFn(path, targetInfo, err)
			}
			for _, entry := range entries {
				childPath := filepath.Join(path, entry.Name())
				if err := walkRecursive(root, childPath, visited, walkFn); err != nil {
					if err == filepath.SkipDir {
						continue
					}
					return err
				}
			}
			return nil
		}
		// symlink to file: fall through to normal walk
		info = targetInfo
	}

	if !info.IsDir() {
		return walkFn(path, info, nil)
	}

	// Directory
	realPath, err := filepath.Abs(path)
	if err != nil {
		realPath = path
	}
	if visited[realPath] {
		return nil
	}
	visited[realPath] = true

	if err := walkFn(path, info, nil); err != nil {
		if err == filepath.SkipDir {
			return nil
		}
		return err
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return walkFn(path, info, err)
	}
	for _, entry := range entries {
		childPath := filepath.Join(path, entry.Name())
		if err := walkRecursive(root, childPath, visited, walkFn); err != nil {
			if err == filepath.SkipDir {
				continue
			}
			return err
		}
	}
	return nil
}

// WalkDirs is like Walk but only visits directories.
func WalkDirs(root string, walkFn filepath.WalkFunc) error {
	return Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return walkFn(path, info, err)
		}
		if !info.IsDir() {
			return nil
		}
		return walkFn(path, info, nil)
	})
}
