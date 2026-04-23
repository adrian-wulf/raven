package main

import (
	"fmt"
	"github.com/raven-security/raven/internal/ast"
	sitter "github.com/smacker/go-tree-sitter"
)

func main() {
	code := []byte(`field = relation.field
`)
	lang := ast.GetLanguageByName("python")
	pf, err := ast.ParseBytes(lang, code)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	defer pf.Close()
	var walk func(n *sitter.Node, depth int)
	walk = func(n *sitter.Node, depth int) {
		indent := ""
		for i := 0; i < depth; i++ { indent += "  " }
		fmt.Printf("%s%s: %q\n", indent, n.Type(), string(pf.Source[n.StartByte():n.EndByte()]))
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i), depth+1)
		}
	}
	walk(pf.RootNode(), 0)
}
