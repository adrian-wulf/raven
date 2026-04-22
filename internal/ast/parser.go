package ast

import (
	"fmt"
	"os"

	sitter "github.com/smacker/go-tree-sitter"
)

// ParsedFile holds the AST and metadata for a parsed file
type ParsedFile struct {
	Path     string
	Source   []byte
	Tree     *sitter.Tree
	Language *Language
}

// Parse reads a file and parses it with the appropriate Tree-sitter parser
func Parse(path string) (*ParsedFile, error) {
	lang := GetLanguageByExtension(path)
	if lang == nil {
		return nil, fmt.Errorf("unsupported file type: %s", path)
	}

	source, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	parser := sitter.NewParser()
	parser.SetLanguage(lang.Parser)

	tree := parser.Parse(nil, source)
	if tree == nil {
		return nil, fmt.Errorf("parsing failed for %s", path)
	}

	return &ParsedFile{
		Path:     path,
		Source:   source,
		Tree:     tree,
		Language: lang,
	}, nil
}

// RootNode returns the root AST node
func (pf *ParsedFile) RootNode() *sitter.Node {
	return pf.Tree.RootNode()
}

// Close releases the parsed tree
func (pf *ParsedFile) Close() {
	if pf.Tree != nil {
		pf.Tree.Close()
	}
}

// NodeAt returns the AST node at the given position
func (pf *ParsedFile) NodeAt(line, column uint32) *sitter.Node {
	point := sitter.Point{Row: line, Column: column}
	return pf.RootNode().NamedDescendantForPointRange(point, point)
}
