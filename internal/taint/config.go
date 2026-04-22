package taint

// SourcePattern defines a taint source
type SourcePattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"` // Tree-sitter query or simple matcher
}

// SinkPattern defines a taint sink
type SinkPattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
}

// Rule defines a taint analysis rule
type Rule struct {
	ID       string          `yaml:"id"`
	Name     string          `yaml:"name"`
	Severity string          `yaml:"severity"`
	Category string          `yaml:"category"`
	Message  string          `yaml:"message"`
	Sources  []SourcePattern `yaml:"sources"`
	Sinks    []SinkPattern   `yaml:"sinks"`
}

// LanguageConfig holds taint sources and sinks for a language
type LanguageConfig struct {
	Sources []SourcePattern
	Sinks   []SinkPattern
}

// DefaultConfigs provides built-in taint configs per language
var DefaultConfigs = map[string]LanguageConfig{
	"javascript": {
		Sources: []SourcePattern{
			{Name: "req.body", Pattern: "req.body"},
			{Name: "req.params", Pattern: "req.params"},
			{Name: "req.query", Pattern: "req.query"},
			{Name: "req.headers", Pattern: "req.headers"},
			{Name: "req.cookies", Pattern: "req.cookies"},
			{Name: "req.files", Pattern: "req.files"},
			{Name: "process.argv", Pattern: "process.argv"},
			{Name: "window.location", Pattern: "window.location"},
			{Name: "document.URL", Pattern: "document.URL"},
		},
		Sinks: []SinkPattern{
			{Name: "db.query", Pattern: ".query("},
			{Name: "db.execute", Pattern: ".execute("},
			{Name: "eval", Pattern: "eval("},
			{Name: "Function", Pattern: "Function("},
			{Name: "setTimeout", Pattern: "setTimeout("},
			{Name: "setInterval", Pattern: "setInterval("},
			{Name: "innerHTML", Pattern: ".innerHTML"},
			{Name: "outerHTML", Pattern: ".outerHTML"},
			{Name: "document.write", Pattern: "document.write"},
			{Name: "document.writeln", Pattern: "document.writeln"},
			{Name: "child_process.exec", Pattern: "child_process.exec"},
			{Name: "child_process.execSync", Pattern: "child_process.execSync"},
			{Name: "child_process.spawn", Pattern: "child_process.spawn"},
			{Name: "cp.exec", Pattern: "cp.exec"},
			{Name: "cp.execSync", Pattern: "cp.execSync"},
			{Name: "cp.spawn", Pattern: "cp.spawn"},
			{Name: "fetch", Pattern: "fetch("},
		},
	},
	"typescript": {
		Sources: []SourcePattern{
			{Name: "req.body", Pattern: "req.body"},
			{Name: "req.params", Pattern: "req.params"},
			{Name: "req.query", Pattern: "req.query"},
			{Name: "req.headers", Pattern: "req.headers"},
			{Name: "process.argv", Pattern: "process.argv"},
		},
		Sinks: []SinkPattern{
			{Name: "db.query", Pattern: ".query"},
			{Name: "eval", Pattern: "eval"},
			{Name: "innerHTML", Pattern: ".innerHTML"},
			{Name: "exec", Pattern: ".exec"},
			{Name: "document.write", Pattern: "document.write"},
		},
	},
	"python": {
		Sources: []SourcePattern{
			{Name: "request.args", Pattern: "request.args"},
			{Name: "request.form", Pattern: "request.form"},
			{Name: "request.json", Pattern: "request.json"},
			{Name: "request.data", Pattern: "request.data"},
			{Name: "request.headers", Pattern: "request.headers"},
			{Name: "request.cookies", Pattern: "request.cookies"},
			{Name: "request.files", Pattern: "request.files"},
			{Name: "sys.argv", Pattern: "sys.argv"},
			{Name: "input", Pattern: "input"},
			{Name: "input()", Pattern: "input()"},
		},
		Sinks: []SinkPattern{
			{Name: "execute", Pattern: ".execute"},
			{Name: "executemany", Pattern: ".executemany"},
			{Name: "eval", Pattern: "eval"},
			{Name: "exec", Pattern: "exec"},
			{Name: "os.system", Pattern: "os.system"},
			{Name: "subprocess.call", Pattern: "subprocess.call"},
			{Name: "subprocess.run", Pattern: "subprocess.run"},
			{Name: "subprocess.Popen", Pattern: "subprocess.Popen"},
			{Name: "render_template_string", Pattern: "render_template_string"},
			{Name: "pickle.loads", Pattern: "pickle.loads"},
		},
	},
	"go": {
		Sources: []SourcePattern{
			{Name: "r.Body", Pattern: "r.Body"},
			{Name: "r.URL.Query", Pattern: "r.URL.Query"},
			{Name: "r.FormValue", Pattern: "r.FormValue"},
			{Name: "r.PostFormValue", Pattern: "r.PostFormValue"},
			{Name: "r.Header.Get", Pattern: "r.Header.Get"},
			{Name: "os.Args", Pattern: "os.Args"},
			{Name: "req.Body", Pattern: "req.Body"},
		},
		Sinks: []SinkPattern{
			{Name: "db.Query", Pattern: ".Query"},
			{Name: "db.Exec", Pattern: ".Exec"},
			{Name: "db.QueryRow", Pattern: ".QueryRow"},
			{Name: "db.QueryContext", Pattern: ".QueryContext"},
			{Name: "db.ExecContext", Pattern: ".ExecContext"},
			{Name: "exec.Command", Pattern: "exec.Command"},
			{Name: "os/exec.Command", Pattern: "os/exec.Command"},
			{Name: "template.Parse", Pattern: "template.Parse"},
			{Name: "template.Execute", Pattern: "template.Execute"},
		},
	},
}
