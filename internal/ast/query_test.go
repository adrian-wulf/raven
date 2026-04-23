package ast

import (
	"testing"
)

func TestQueryJSRules(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		query    string
		expected int
	}{
		{
			name:   "innerHTML assignment",
			source: `document.body.innerHTML = userInput;`,
			query: `(assignment_expression
				left: (member_expression
					property: (property_identifier) @prop (#eq? @prop "innerHTML"))
				right: (_) @vuln)`,
			expected: 1,
		},
		{
			name:   "document.write",
			source: `document.write(userInput);`,
			query: `(call_expression
				function: (member_expression
					object: (identifier) @obj (#eq? @obj "document")
					property: (property_identifier) @prop (#eq? @prop "write"))
				arguments: (arguments (_) @vuln))`,
			expected: 1,
		},
		{
			name:   "setTimeout with string",
			source: `setTimeout("alert(1)", 1000);`,
			query: `(call_expression
				function: (identifier) @fn (#match? @fn "^(setTimeout|setInterval)$")
				arguments: (arguments . (string) @vuln))`,
			expected: 1,
		},
		{
			name:   "postMessage without origin",
			source: `window.postMessage(data, "*");`,
			query: `(call_expression
				function: (member_expression
					property: (property_identifier) @prop (#eq? @prop "postMessage"))
				arguments: (arguments
					(_)
					(string) @vuln (#eq? @vuln "\"*\"")))`,
			expected: 1,
		},
		{
			name:   "window.open with user URL",
			source: `window.open(userUrl);`,
			query: `(call_expression
				function: (member_expression
					object: (identifier) @obj (#eq? @obj "window")
					property: (property_identifier) @prop (#eq? @prop "open"))
				arguments: (arguments (_) @vuln))`,
			expected: 1,
		},
		{
			name:   "dangerouslySetInnerHTML",
			source: `<div dangerouslySetInnerHTML={{__html: userInput}} />`,
			query: `(jsx_attribute
				(property_identifier) @prop (#eq? @prop "dangerouslySetInnerHTML")
				(jsx_expression (_) @vuln))`,
			expected: 1,
		},
		{
			name:   "Function constructor",
			source: `new Function(userInput);`,
			query: `(new_expression
				constructor: (identifier) @fn (#eq? @fn "Function")
				arguments: (arguments (_) @vuln))`,
			expected: 1,
		},
		{
			name:   "eval with identifier",
			source: `eval(userInput);`,
			query: `(call_expression
				function: (identifier) @fn (#eq? @fn "eval")
				arguments: (arguments (_) @vuln))`,
			expected: 1,
		},
		{
			name:   "child_process.exec with template",
			source: "exec(`ls ${dir}`);",
			query: `(call_expression
				function: (identifier) @fn (#match? @fn "^(exec|execSync|spawn)$")
				arguments: (arguments (template_string) @vuln))`,
			expected: 1,
		},
		{
			name:   "href javascript scheme",
			source: `<a href="javascript:alert(1)">click</a>`,
			query: `(jsx_attribute
				(property_identifier) @prop (#eq? @prop "href")
				(string) @vuln (#match? @vuln "^\"javascript:"))`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lang := GetLanguageByName("javascript")
			if lang == nil {
				t.Fatal("javascript language not found")
			}
			pf, err := ParseBytes(lang, []byte(tt.source))
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			defer pf.Close()

			matches, err := Query(pf, tt.query)
			if err != nil {
				t.Fatalf("query error: %v", err)
			}
			if len(matches) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(matches))
				for i, m := range matches {
					for _, c := range m.Captures {
						t.Logf("match %d capture %s: %q", i, c.Name, string(pf.Source[c.Node.StartByte():c.Node.EndByte()]))
					}
				}
			}
		})
	}
}

func TestQueryPythonRules(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		query    string
		expected int
	}{
		{
			name:   "subprocess.call with shell=True",
			source: "subprocess.call('ls ' + user_input, shell=True)",
			query: `(call
				function: (attribute
					object: (identifier) @obj (#eq? @obj "subprocess")
					attribute: (identifier) @attr (#eq? @attr "call"))
				arguments: (argument_list
					(_)
					(keyword_argument
						name: (identifier) @kw (#eq? @kw "shell")
						value: (true) @vuln)))`,
			expected: 1,
		},
		{
			name:   "os.system with f-string",
			source: "os.system(f'rm {path}')",
			query: `(call
				function: (attribute
					object: (identifier) @obj (#eq? @obj "os")
					attribute: (identifier) @attr (#eq? @attr "system"))
				arguments: (argument_list (string) @vuln))`,
			expected: 1,
		},
		{
			name:   "pickle.loads",
			source: "pickle.loads(user_data)",
			query: `(call
				function: (attribute
					object: (identifier) @obj (#eq? @obj "pickle")
					attribute: (identifier) @attr (#eq? @attr "loads"))
				arguments: (argument_list (_) @vuln))`,
			expected: 1,
		},
		{
			name:   "yaml.load without Loader",
			source: "yaml.load(data)",
			query: `(call
				function: (attribute
					object: (identifier) @obj (#eq? @obj "yaml")
					attribute: (identifier) @attr (#eq? @attr "load"))
				arguments: (argument_list (_) @vuln))`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lang := GetLanguageByName("python")
			if lang == nil {
				t.Fatal("python language not found")
			}
			pf, err := ParseBytes(lang, []byte(tt.source))
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			defer pf.Close()

			matches, err := Query(pf, tt.query)
			if err != nil {
				t.Fatalf("query error: %v", err)
			}
			if len(matches) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(matches))
				for i, m := range matches {
					for _, c := range m.Captures {
						t.Logf("match %d capture %s: %q", i, c.Name, string(pf.Source[c.Node.StartByte():c.Node.EndByte()]))
					}
				}
			}
		})
	}
}

func TestQueryGoRules(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		query    string
		expected int
	}{
		{
			name:   "exec.Command with string concatenation",
			source: "exec.Command(\"sh\", \"-c\", \"echo \"+userInput)",
			query: `(call_expression
				function: (selector_expression
					operand: (identifier) @pkg (#eq? @pkg "exec")
					field: (field_identifier) @fn (#eq? @fn "Command"))
				arguments: (argument_list
					(_)
					(_)
					(binary_expression) @vuln))`,
			expected: 1,
		},
		{
			name:   "template.Parse with user input",
			source: "template.New(\"name\").Parse(userTemplate)",
			query: `(call_expression
				function: (selector_expression
					operand: (call_expression)
					field: (field_identifier) @fn (#eq? @fn "Parse"))
				arguments: (argument_list (identifier) @vuln))`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lang := GetLanguageByName("go")
			if lang == nil {
				t.Fatal("go language not found")
			}
			pf, err := ParseBytes(lang, []byte(tt.source))
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			defer pf.Close()

			matches, err := Query(pf, tt.query)
			if err != nil {
				t.Fatalf("query error: %v", err)
			}
			if len(matches) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(matches))
				for i, m := range matches {
					for _, c := range m.Captures {
						t.Logf("match %d capture %s: %q", i, c.Name, string(pf.Source[c.Node.StartByte():c.Node.EndByte()]))
					}
				}
			}
		})
	}
}

func TestQueryJavaRules(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		query    string
		expected int
	}{
		{
			name:   "Runtime.exec with user input",
			source: "Runtime.getRuntime().exec(userCmd);",
			query: `(method_invocation
				object: (method_invocation
					object: (identifier) @cls (#eq? @cls "Runtime")
					name: (identifier) @meth1 (#eq? @meth1 "getRuntime"))
				name: (identifier) @meth2 (#eq? @meth2 "exec")
				arguments: (argument_list (_) @vuln))`,
			expected: 1,
		},
		{
			name:   "Statement.executeQuery with concatenation",
			source: "stmt.executeQuery(\"SELECT * WHERE id = \" + userId);",
			query: `(method_invocation
				name: (identifier) @fn (#eq? @fn "executeQuery")
				arguments: (argument_list (binary_expression) @vuln))`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lang := GetLanguageByName("java")
			if lang == nil {
				t.Fatal("java language not found")
			}
			pf, err := ParseBytes(lang, []byte(tt.source))
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			defer pf.Close()

			matches, err := Query(pf, tt.query)
			if err != nil {
				t.Fatalf("query error: %v", err)
			}
			if len(matches) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(matches))
				for i, m := range matches {
					for _, c := range m.Captures {
						t.Logf("match %d capture %s: %q", i, c.Name, string(pf.Source[c.Node.StartByte():c.Node.EndByte()]))
					}
				}
			}
		})
	}
}
