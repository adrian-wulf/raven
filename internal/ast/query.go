package ast

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
)

// Capture represents a named capture from a Tree-sitter query
type Capture struct {
	Name string
	Node *sitter.Node
}

// Match represents a single query match with all captures
type Match struct {
	Captures []Capture
}

// Query runs a Tree-sitter query against a parsed file and returns matches
func Query(pf *ParsedFile, queryStr string) ([]Match, error) {
	query, err := sitter.NewQuery([]byte(queryStr), pf.Language.Parser)
	if err != nil {
		return nil, fmt.Errorf("compiling query: %w", err)
	}
	defer query.Close()

	cursor := sitter.NewQueryCursor()
	defer cursor.Close()

	cursor.Exec(query, pf.RootNode())

	var matches []Match
	for {
		qm, ok := cursor.NextMatch()
		if !ok {
			break
		}

		qm = cursor.FilterPredicates(qm, pf.Source)

		var captures []Capture
		for _, c := range qm.Captures {
			name := query.CaptureNameForId(c.Index)
			captures = append(captures, Capture{
				Name: name,
				Node: c.Node,
			})
		}

		if len(captures) > 0 {
			matches = append(matches, Match{Captures: captures})
		}
	}

	return matches, nil
}

// GetCapture returns the first capture with the given name, or nil
func (m *Match) GetCapture(name string) *Capture {
	for _, c := range m.Captures {
		if c.Name == name {
			return &c
		}
	}
	return nil
}

// GetCaptures returns all captures with the given name
func (m *Match) GetCaptures(name string) []Capture {
	var result []Capture
	for _, c := range m.Captures {
		if c.Name == name {
			result = append(result, c)
		}
	}
	return result
}
