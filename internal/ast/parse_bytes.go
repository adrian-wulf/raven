package ast

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
)

// ParseBytes parses source code directly from bytes using the given language
func ParseBytes(lang *Language, source []byte) (*ParsedFile, error) {
	if lang == nil {
		return nil, fmt.Errorf("language is nil")
	}
	if lang.Parser == nil {
		return nil, fmt.Errorf("language %q has no parser", lang.Name)
	}

	parser := sitter.NewParser()
	parser.SetLanguage(lang.Parser)

	tree := parser.Parse(nil, source)
	if tree == nil {
		return nil, fmt.Errorf("parsing failed for language %q", lang.Name)
	}

	return &ParsedFile{
		Path:     "",
		Source:   source,
		Tree:     tree,
		Language: lang,
	}, nil
}

// ParseBytesByName parses source code by language name (e.g. "javascript", "go")
func ParseBytesByName(langName string, source []byte) (*ParsedFile, error) {
	lang := GetLanguageByName(langName)
	if lang == nil {
		return nil, fmt.Errorf("unsupported language: %s", langName)
	}
	return ParseBytes(lang, source)
}
