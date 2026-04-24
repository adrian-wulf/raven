package taint

// SourcePattern defines a taint source
type SourcePattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"` // Tree-sitter query or simple matcher
	Type    string `yaml:"type,omitempty"`
}

// SinkPattern defines a taint sink
type SinkPattern struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity,omitempty"`
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

// LanguageConfig holds taint sources, sinks, and sanitizers for a language
type LanguageConfig struct {
	Sources    []SourcePattern
	Sinks      []SinkPattern
	Sanitizers []string // function names that sanitize tainted input
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
		Sanitizers: []string{
			"DOMPurify.sanitize",
			"escapeHtml",
			"htmlspecialchars",
			"encodeURIComponent",
			"he.encode",
			"validator.escape",
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
		Sanitizers: []string{
			"DOMPurify.sanitize",
			"escapeHtml",
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
			// raven-ignore-next-line: taint sink definition, not actual deserialization
			{Name: "pickle.loads", Pattern: "pickle.loads"},
		},
		Sanitizers: []string{
			"bleach.clean",
			"html.escape",
			"urllib.parse.quote",
			"sqlalchemy.text",
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
		Sanitizers: []string{
			"html.EscapeString",
			"url.QueryEscape",
			"strconv.Quote",
		},
	},
	"java": {
		Sources: []SourcePattern{
			{Name: "request.getParameter", Pattern: "request.getParameter"},
			{Name: "req.getParameter", Pattern: "req.getParameter"},
			{Name: "request.getHeader", Pattern: "request.getHeader"},
			{Name: "request.getInputStream", Pattern: "request.getInputStream"},
			{Name: "System.getenv", Pattern: "System.getenv"},
			{Name: "args", Pattern: "args["},
		},
		Sinks: []SinkPattern{
			{Name: "Statement.execute", Pattern: ".execute"},
			{Name: "Statement.executeQuery", Pattern: ".executeQuery"},
			{Name: "Statement.executeUpdate", Pattern: ".executeUpdate"},
			{Name: "Runtime.exec", Pattern: "Runtime.getRuntime().exec"},
			{Name: "ProcessBuilder", Pattern: "new ProcessBuilder"},
			// raven-ignore-next-line: taint sink definition, not actual deserialization
			{Name: "ObjectInputStream.readObject", Pattern: "readObject"},
			{Name: "ScriptEngine.eval", Pattern: ".eval("},
		},
		Sanitizers: []string{
			"PreparedStatement",
			"ESAPI.encoder",
			"org.owasp.encoder",
		},
	},
	"csharp": {
		Sources: []SourcePattern{
			{Name: "Request.QueryString", Pattern: "Request.QueryString"},
			{Name: "Request.Form", Pattern: "Request.Form"},
			{Name: "Request.Params", Pattern: "Request.Params"},
			{Name: "Request.Headers", Pattern: "Request.Headers"},
			{Name: "Request.Cookies", Pattern: "Request.Cookies"},
			{Name: "Environment.GetEnvironmentVariable", Pattern: "Environment.GetEnvironmentVariable"},
			{Name: "args", Pattern: "args["},
		},
		Sinks: []SinkPattern{
			{Name: "SqlCommand.Execute", Pattern: ".Execute"},
			{Name: "SqlCommand.ExecuteNonQuery", Pattern: ".ExecuteNonQuery"},
			{Name: "SqlCommand.ExecuteReader", Pattern: ".ExecuteReader"},
			{Name: "Process.Start", Pattern: "Process.Start"},
			{Name: "Process.Start", Pattern: "new Process"},
			{Name: "Assembly.Load", Pattern: "Assembly.Load"},
			{Name: "JavaScriptSerializer.Deserialize", Pattern: ".Deserialize"},
		},
		Sanitizers: []string{
			"HttpUtility.HtmlEncode",
			"WebUtility.HtmlEncode",
			"AntiXssEncoder",
			"SqlParameter",
		},
	},
	"php": {
		Sources: []SourcePattern{
			{Name: "$_GET", Pattern: "$_GET"},
			{Name: "$_POST", Pattern: "$_POST"},
			{Name: "$_REQUEST", Pattern: "$_REQUEST"},
			{Name: "$_COOKIE", Pattern: "$_COOKIE"},
			{Name: "$_FILES", Pattern: "$_FILES"},
			{Name: "$_SERVER", Pattern: "$_SERVER"},
			{Name: "$argv", Pattern: "$argv"},
		},
		Sinks: []SinkPattern{
			{Name: "mysql_query", Pattern: "mysql_query"},
			{Name: "mysqli_query", Pattern: "mysqli_query"},
			{Name: "PDO.query", Pattern: "->query"},
			{Name: "PDO.exec", Pattern: "->exec"},
			{Name: "PDO.prepare", Pattern: "->prepare"},
			{Name: "eval", Pattern: "eval("},
			{Name: "exec", Pattern: "exec("},
			{Name: "system", Pattern: "system("},
			{Name: "shell_exec", Pattern: "shell_exec("},
			{Name: "passthru", Pattern: "passthru("},
			{Name: "proc_open", Pattern: "proc_open("},
			{Name: "file_get_contents", Pattern: "file_get_contents("},
			{Name: "fopen", Pattern: "fopen("},
			{Name: "include", Pattern: "include("},
			{Name: "require", Pattern: "require("},
			{Name: "echo", Pattern: "echo "},
			{Name: "print", Pattern: "print "},
			{Name: "header", Pattern: "header("},
			// raven-ignore-next-line: taint sink definition, not actual deserialization
			{Name: "unserialize", Pattern: "unserialize("},
		},
		Sanitizers: []string{
			"htmlspecialchars",
			"htmlentities",
			"strip_tags",
			"mysqli_real_escape_string",
			"PDO::quote",
			"escapeshellarg",
			"escapeshellcmd",
			"filter_input",
		},
	},
	"rust": {
		Sources: []SourcePattern{
			{Name: "std::io::stdin", Pattern: "std::io::stdin"},
			{Name: "std::env::args", Pattern: "std::env::args"},
			{Name: "std::env::var", Pattern: "std::env::var"},
			{Name: "req.body", Pattern: "req.body"},
			{Name: "req.params", Pattern: "req.params"},
			{Name: "req.query", Pattern: "req.query"},
		},
		Sinks: []SinkPattern{
			{Name: "std::process::Command::new", Pattern: "Command::new"},
			{Name: "std::fs::read", Pattern: "std::fs::read"},
			{Name: "std::fs::write", Pattern: "std::fs::write"},
			{Name: "std::fs::File::open", Pattern: "File::open"},
			{Name: "sqlx::query", Pattern: "sqlx::query"},
			{Name: "diesel::sql_query", Pattern: "sql_query"},
			{Name: "reqwest::get", Pattern: "reqwest::get"},
		},
		Sanitizers: []string{
			" ammonia::clean",
			" pulldown_cmark",
		},
	},
	"kotlin": {
		Sources: []SourcePattern{
			{Name: "intent.getStringExtra", Pattern: "intent.getStringExtra"},
			{Name: "intent.getData", Pattern: "intent.getData"},
			{Name: "request.getParameter", Pattern: "request.getParameter"},
			{Name: "req.getParameter", Pattern: "req.getParameter"},
			{Name: "args", Pattern: "args["},
		},
		Sinks: []SinkPattern{
			{Name: "Statement.execute", Pattern: ".execute"},
			{Name: "Statement.executeQuery", Pattern: ".executeQuery"},
			{Name: "Runtime.exec", Pattern: "Runtime.getRuntime().exec"},
			{Name: "ProcessBuilder", Pattern: "new ProcessBuilder"},
			// raven-ignore-next-line: taint sink definition, not actual deserialization
			{Name: "ObjectInputStream.readObject", Pattern: "readObject"},
			{Name: "ScriptEngine.eval", Pattern: ".eval("},
		},
		Sanitizers: []string{
			"PreparedStatement",
			"org.owasp.encoder",
			"HtmlCompat",
		},
	},
	"c": {
		Sources: []SourcePattern{
			{Name: "argv", Pattern: "argv["},
			{Name: "getenv", Pattern: "getenv("},
			{Name: "fgets", Pattern: "fgets("},
			{Name: "scanf", Pattern: "scanf("},
			{Name: "read", Pattern: "read("},
			{Name: "recv", Pattern: "recv("},
			{Name: "recvfrom", Pattern: "recvfrom("},
		},
		Sinks: []SinkPattern{
			{Name: "system", Pattern: "system("},
			{Name: "popen", Pattern: "popen("},
			{Name: "exec", Pattern: "exec("},
			{Name: "sprintf", Pattern: "sprintf("},
			{Name: "strcpy", Pattern: "strcpy("},
			{Name: "strcat", Pattern: "strcat("},
			{Name: "memcpy", Pattern: "memcpy("},
			{Name: "gets", Pattern: "gets("},
			{Name: "fopen", Pattern: "fopen("},
			{Name: "open", Pattern: "open("},
		},
		Sanitizers: []string{
			"strncpy",
			"strncat",
			"snprintf",
			"strlcpy",
			"strlcat",
		},
	},
	"cpp": {
		Sources: []SourcePattern{
			{Name: "argv", Pattern: "argv["},
			{Name: "std::getenv", Pattern: "std::getenv("},
			{Name: "std::cin", Pattern: "std::cin"},
			{Name: "getenv", Pattern: "getenv("},
			{Name: "recv", Pattern: "recv("},
			{Name: "recvfrom", Pattern: "recvfrom("},
		},
		Sinks: []SinkPattern{
			{Name: "system", Pattern: "system("},
			{Name: "popen", Pattern: "popen("},
			{Name: "exec", Pattern: "exec("},
			{Name: "sprintf", Pattern: "sprintf("},
			{Name: "strcpy", Pattern: "strcpy("},
			{Name: "strcat", Pattern: "strcat("},
			{Name: "memcpy", Pattern: "memcpy("},
			{Name: "std::system", Pattern: "std::system("},
			{Name: "std::process::system", Pattern: "std::process::system("},
		},
		Sanitizers: []string{
			"std::string",
			"strncpy",
			"snprintf",
			"strlcpy",
		},
	},
}

// RegisterLanguageConfig registers a language config for taint analysis
func RegisterLanguageConfig(lang string, config LanguageConfig) {
	if DefaultConfigs == nil {
		DefaultConfigs = make(map[string]LanguageConfig)
	}
	DefaultConfigs[lang] = config
}
