package ast

import (
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	cparser "github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/csharp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/kotlin"
	"github.com/smacker/go-tree-sitter/php"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/ruby"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/swift"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// Language defines a Tree-sitter language with its metadata
type Language struct {
	Name       string
	Extensions []string
	Parser     *sitter.Language
}

// Registry of supported languages
var registry = []Language{
	{
		Name:       "javascript",
		Extensions: []string{".js", ".jsx", ".mjs", ".cjs"},
		Parser:     javascript.GetLanguage(),
	},
	{
		Name:       "typescript",
		Extensions: []string{".ts"},
		Parser:     typescript.GetLanguage(),
	},
	{
		Name:       "tsx",
		Extensions: []string{".tsx"},
		Parser:     tsx.GetLanguage(),
	},
	{
		Name:       "python",
		Extensions: []string{".py", ".pyw"},
		Parser:     python.GetLanguage(),
	},
	{
		Name:       "go",
		Extensions: []string{".go"},
		Parser:     golang.GetLanguage(),
	},
	{
		Name:       "java",
		Extensions: []string{".java"},
		Parser:     java.GetLanguage(),
	},
	{
		Name:       "kotlin",
		Extensions: []string{".kt"},
		Parser:     kotlin.GetLanguage(),
	},
	{
		Name:       "c",
		Extensions: []string{".c", ".h"},
		Parser:     cparser.GetLanguage(),
	},
	{
		Name:       "cpp",
		Extensions: []string{".cpp", ".cc", ".cxx", ".hpp", ".hxx"},
		Parser:     cpp.GetLanguage(),
	},
	{
		Name:       "csharp",
		Extensions: []string{".cs"},
		Parser:     csharp.GetLanguage(),
	},
	{
		Name:       "php",
		Extensions: []string{".php", ".phtml", ".php3", ".php4", ".php5"},
		Parser:     php.GetLanguage(),
	},
	{
		Name:       "ruby",
		Extensions: []string{".rb", ".erb", ".rake", ".gemspec"},
		Parser:     ruby.GetLanguage(),
	},
	{
		Name:       "rust",
		Extensions: []string{".rs"},
		Parser:     rust.GetLanguage(),
	},
	{
		Name:       "swift",
		Extensions: []string{".swift"},
		Parser:     swift.GetLanguage(),
	},
}

// GetLanguageByExtension returns the language for a given file extension
func GetLanguageByExtension(path string) *Language {
	ext := strings.ToLower(filepath.Ext(path))
	for _, lang := range registry {
		for _, e := range lang.Extensions {
			if e == ext {
				return &lang
			}
		}
	}
	return nil
}

// IsSupported returns true if the file extension has a Tree-sitter parser
func IsSupported(path string) bool {
	return GetLanguageByExtension(path) != nil
}

// SupportedLanguages returns a list of supported language names
func SupportedLanguages() []string {
	var names []string
	seen := make(map[string]bool)
	for _, lang := range registry {
		if !seen[lang.Name] {
			seen[lang.Name] = true
			names = append(names, lang.Name)
		}
	}
	return names
}
