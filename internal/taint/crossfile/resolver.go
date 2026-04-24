package crossfile

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Import represents an import/require statement.
type Import struct {
	Source   string   // the module path, e.g. "./utils" or "express"
	Names    []string // imported names, e.g. ["userInput"]
	IsRequire bool    // true for require(), false for import
	Line     int
}

// Export represents an exported symbol from a file.
type Export struct {
	Name string // exported name, e.g. "userInput" or "default"
	Line int
}

// ModuleInfo holds imports and exports for a single file.
type ModuleInfo struct {
	Path    string
	Imports []Import
	Exports []Export
}

// Resolver builds a module graph from source files.
type Resolver struct {
	modules map[string]*ModuleInfo // path -> info
}

// NewResolver creates a new module resolver.
func NewResolver() *Resolver {
	return &Resolver{modules: make(map[string]*ModuleInfo)}
}

// ScanDirectory recursively scans a directory for JS/TS/Go/Python files
// and extracts imports/exports.
func (r *Resolver) ScanDirectory(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !isSourceFile(path) {
			return nil
		}
		if err := r.parseFile(path); err != nil {
			return nil // skip unparseable files
		}
		return nil
	})
}

// parseFile extracts imports and exports from a single file.
func (r *Resolver) parseFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)
	ext := filepath.Ext(path)

	info := &ModuleInfo{Path: path}

	switch ext {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		info.Imports = parseJSImports(content)
		info.Exports = parseJSExports(content)
	case ".go":
		info.Imports = parseGoImports(content)
		info.Exports = parseGoExports(content)
	case ".py":
		info.Imports = parsePythonImports(content)
		info.Exports = parsePythonExports(content)
	case ".java":
		info.Imports = parseJavaImports(content)
		info.Exports = parseJavaExports(content)
	case ".cs":
		info.Imports = parseCSharpImports(content)
		info.Exports = parseCSharpExports(content)
	}

	r.modules[path] = info
	return nil
}

// ResolveImport resolves an import path to an absolute file path.
func (r *Resolver) ResolveImport(fromFile, importPath string) (string, bool) {
	// Skip node_modules and external packages
	if !strings.HasPrefix(importPath, ".") {
		return "", false
	}

	dir := filepath.Dir(fromFile)
	candidate := filepath.Join(dir, importPath)

	// Try exact file
	if info, ok := r.modules[candidate]; ok {
		return info.Path, true
	}

	// Try with extensions
	for _, ext := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".go", ".py"} {
		if info, ok := r.modules[candidate+ext]; ok {
			return info.Path, true
		}
	}

	// Try index file in directory
	for _, ext := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs"} {
		indexPath := filepath.Join(candidate, "index"+ext)
		if info, ok := r.modules[indexPath]; ok {
			return info.Path, true
		}
	}

	return "", false
}

// IsTaintedSource checks if a name exported from a file is a taint source.
func (r *Resolver) IsTaintedSource(filePath, name string) bool {
	info, ok := r.modules[filePath]
	if !ok {
		return false
	}
	// For now, consider any exported function/variable that interacts with
	// user input as a taint source. This is a heuristic.
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	content := string(data)

	// Check if the exported name is assigned from a known source
	sourcePatterns := []string{
		`req\.body`, `req\.params`, `req\.query`, `req\.headers`,
		`process\.argv`, `os\.Args`, `r\.FormValue`, `r\.URL\.Query`,
		`input\(`, `sys\.stdin`, `request\.(get_json|json|args|form)`,
	}

	// Find where the export is defined and check if source pattern is nearby
	for _, export := range info.Exports {
		if export.Name == name || name == "default" && export.Name == "default" {
			// Check surrounding lines for source patterns
			lines := strings.Split(content, "\n")
			start := max(0, export.Line-5)
			end := min(len(lines), export.Line+5)
			for i := start; i < end; i++ {
				for _, pattern := range sourcePatterns {
					if matched, _ := regexp.MatchString(pattern, lines[i]); matched {
						return true
					}
				}
			}
		}
	}
	return false
}

// GetModuleInfo returns module info for a file.
func (r *Resolver) GetModuleInfo(path string) (*ModuleInfo, bool) {
	info, ok := r.modules[path]
	return info, ok
}

func isSourceFile(path string) bool {
	ext := filepath.Ext(path)
	switch ext {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".py", ".java", ".cs":
		return true
	}
	return false
}

// parseJSImports extracts require() and import statements from JS/TS.
func parseJSImports(content string) []Import {
	var imports []Import
	lines := strings.Split(content, "\n")

	// require() patterns
	requireRe := regexp.MustCompile(`(?:const|let|var)\s+(?:\{\s*([^}]+)\}\s+|(\w+)\s*)=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	simpleRequireRe := regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	importRe := regexp.MustCompile(`import\s+(?:(\w+)\s+from\s+|\{\s*([^}]+)\}\s+from\s+|\*\s+as\s+(\w+)\s+from\s+)?['"]([^'"]+)['"]`)

	for lineNum, line := range lines {
		// import { a, b } from './module'
		if matches := importRe.FindStringSubmatch(line); matches != nil {
			imp := Import{Source: matches[4], Line: lineNum + 1}
			if matches[2] != "" {
				// Named imports
				for _, name := range strings.Split(matches[2], ",") {
					imp.Names = append(imp.Names, strings.TrimSpace(name))
				}
			} else if matches[1] != "" {
				imp.Names = []string{matches[1]}
			} else if matches[3] != "" {
				imp.Names = []string{matches[3]}
			}
			imports = append(imports, imp)
			continue
		}

		// const { a, b } = require('./module')
		if matches := requireRe.FindStringSubmatch(line); matches != nil {
			imp := Import{Source: matches[3], IsRequire: true, Line: lineNum + 1}
			if matches[1] != "" {
				for _, name := range strings.Split(matches[1], ",") {
					imp.Names = append(imp.Names, strings.TrimSpace(name))
				}
			} else if matches[2] != "" {
				imp.Names = []string{matches[2]}
			}
			imports = append(imports, imp)
			continue
		}

		// const x = require('./module')
		if matches := simpleRequireRe.FindStringSubmatch(line); matches != nil {
			imports = append(imports, Import{
				Source:    matches[2],
				Names:     []string{matches[1]},
				IsRequire: true,
				Line:      lineNum + 1,
			})
		}
	}

	return imports
}

// parseJSExports extracts exports from JS/TS files.
func parseJSExports(content string) []Export {
	var exports []Export
	lines := strings.Split(content, "\n")

	// Single-line patterns
	exportRe := regexp.MustCompile(`(?:module\.exports\s*=\s*\{([^}]*)\}|exports\.(\w+)\s*=|export\s+(?:const|let|var|function)\s+(\w+)|export\s+default\s+(?:function\s+)?(\w+)?)`)

	// Multi-line module.exports = { ... }
	multiLineRe := regexp.MustCompile(`(?s)module\.exports\s*=\s*\{(.*?)\}`)

	// Try multi-line first
	if matches := multiLineRe.FindStringSubmatch(content); matches != nil {
		inner := matches[1]
		// Find the line number of module.exports
		lineNum := 1
		for i, line := range lines {
			if strings.Contains(line, "module.exports") {
				lineNum = i + 1
				break
			}
		}
		for _, name := range strings.Split(inner, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			name = strings.Split(name, ":")[0]
			name = strings.TrimSpace(name)
			if name != "" {
				exports = append(exports, Export{Name: name, Line: lineNum})
			}
		}
	}

	// Single-line exports
	for lineNum, line := range lines {
		if matches := exportRe.FindStringSubmatch(line); matches != nil {
			if matches[2] != "" {
				exports = append(exports, Export{Name: matches[2], Line: lineNum + 1})
			} else if matches[3] != "" {
				exports = append(exports, Export{Name: matches[3], Line: lineNum + 1})
			} else if matches[4] != "" || strings.Contains(line, "export default") {
				exports = append(exports, Export{Name: "default", Line: lineNum + 1})
			}
		}
	}

	return exports
}

func parseGoImports(content string) []Import {
	var imports []Import
	// Simplified: just look for import blocks
	importRe := regexp.MustCompile(`import\s+\(\s*([^)]+)\)`)
	if matches := importRe.FindStringSubmatch(content); matches != nil {
		for _, line := range strings.Split(matches[1], "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			// Extract quoted path
			if idx := strings.Index(line, `"`); idx >= 0 {
				end := strings.Index(line[idx+1:], `"`)
				if end >= 0 {
					imports = append(imports, Import{
						Source: line[idx+1 : idx+1+end],
					})
				}
			}
		}
	}
	return imports
}

func parseGoExports(content string) []Export {
	var exports []Export
	lines := strings.Split(content, "\n")
	exportRe := regexp.MustCompile(`^func\s+(\w+)|^var\s+(\w+)|^const\s+(\w+)|^type\s+(\w+)`)
	for lineNum, line := range lines {
		if matches := exportRe.FindStringSubmatch(line); matches != nil {
			for i := 1; i < len(matches); i++ {
				if matches[i] != "" {
					// Only exported names (capitalized)
					if matches[i][0] >= 'A' && matches[i][0] <= 'Z' {
						exports = append(exports, Export{Name: matches[i], Line: lineNum + 1})
					}
					break
				}
			}
		}
	}
	return exports
}

func parsePythonImports(content string) []Import {
	var imports []Import
	lines := strings.Split(content, "\n")
	importRe := regexp.MustCompile(`(?:from\s+(\S+)\s+import\s+([^#\n]+)|import\s+([^#\n]+))`)
	for lineNum, line := range lines {
		if matches := importRe.FindStringSubmatch(line); matches != nil {
			if matches[1] != "" {
				var names []string
				for _, n := range strings.Split(matches[2], ",") {
					names = append(names, strings.TrimSpace(n))
				}
				imports = append(imports, Import{Source: matches[1], Names: names, Line: lineNum + 1})
			} else if matches[3] != "" {
				var names []string
				for _, n := range strings.Split(matches[3], ",") {
					names = append(names, strings.TrimSpace(n))
				}
				imports = append(imports, Import{Source: names[0], Names: names, Line: lineNum + 1})
			}
		}
	}
	return imports
}

func parsePythonExports(content string) []Export {
	// In Python, everything is exported unless prefixed with _
	// We'll look for function/class definitions
	var exports []Export
	lines := strings.Split(content, "\n")
	exportRe := regexp.MustCompile(`^(?:def|class)\s+(\w+)`)
	for lineNum, line := range lines {
		if matches := exportRe.FindStringSubmatch(line); matches != nil {
			if !strings.HasPrefix(matches[1], "_") {
				exports = append(exports, Export{Name: matches[1], Line: lineNum + 1})
			}
		}
	}
	return exports
}

func parseJavaImports(content string) []Import {
	var imports []Import
	lines := strings.Split(content, "\n")
	importRe := regexp.MustCompile(`^import\s+(?:static\s+)?([\w.]+(?:\.\*)?);`)
	for lineNum, line := range lines {
		if matches := importRe.FindStringSubmatch(line); matches != nil {
			imports = append(imports, Import{
				Source: matches[1],
				Line:   lineNum + 1,
			})
		}
	}
	return imports
}

func parseJavaExports(content string) []Export {
	var exports []Export
	lines := strings.Split(content, "\n")
	// public class/interface/enum/record/method
	exportRe := regexp.MustCompile(`^\s*public\s+(?:class|interface|enum|record|(?:static\s+)?(?:void|[\w<>,\s\[\]]+)\s+(\w+))`)
	for lineNum, line := range lines {
		if matches := exportRe.FindStringSubmatch(line); matches != nil {
			if matches[1] != "" {
				exports = append(exports, Export{Name: matches[1], Line: lineNum + 1})
			}
		}
	}
	return exports
}

func parseCSharpImports(content string) []Import {
	var imports []Import
	lines := strings.Split(content, "\n")
	usingRe := regexp.MustCompile(`^using\s+(?:static\s+)?([\w.]+);`)
	for lineNum, line := range lines {
		if matches := usingRe.FindStringSubmatch(line); matches != nil {
			imports = append(imports, Import{
				Source: matches[1],
				Line:   lineNum + 1,
			})
		}
	}
	return imports
}

func parseCSharpExports(content string) []Export {
	var exports []Export
	lines := strings.Split(content, "\n")
	// public class/interface/struct/enum/method/property
	exportRe := regexp.MustCompile(`^\s*public\s+(?:class|interface|struct|enum|(?:static\s+)?(?:void|Task|[\w<>,\s\[\]?]+)\s+(\w+))`)
	for lineNum, line := range lines {
		if matches := exportRe.FindStringSubmatch(line); matches != nil {
			if matches[1] != "" {
				exports = append(exports, Export{Name: matches[1], Line: lineNum + 1})
			}
		}
	}
	return exports
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
