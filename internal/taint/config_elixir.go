package taint

func init() {
	RegisterLanguageConfig("elixir", elixirConfig)
}

var elixirConfig = LanguageConfig{
	Sources: []SourcePattern{
		{Pattern: "params", Type: "http"},
		{Pattern: "conn.params", Type: "http"},
		{Pattern: "conn.query_string", Type: "http"},
		{Pattern: "System.get_env", Type: "environment"},
		{Pattern: "IO.gets", Type: "input"},
		{Pattern: "File.read!", Type: "file"},
		{Pattern: "recv", Type: "network"},
	},
	Sinks: []SinkPattern{
		{Pattern: "Ecto.Adapters.SQL.query", Severity: "critical"},
		{Pattern: "unsafe_fragment", Severity: "critical"},
		{Pattern: "Code.eval_string", Severity: "critical"},
		{Pattern: "Code.load_file", Severity: "critical"},
		{Pattern: "System.cmd", Severity: "critical"},
		{Pattern: ":os.cmd", Severity: "critical"},
		{Pattern: "send_resp", Severity: "high"},
		{Pattern: "render", Severity: "medium"},
		{Pattern: "File.write!", Severity: "medium"},
		{Pattern: "File.rm!", Severity: "medium"},
		{Pattern: "spawn", Severity: "low"},
	},
	Sanitizers: []string{
		"HtmlEntities.encode", "URI.encode", "Regex.escape",
		"String.trim", "Integer.parse", "Float.parse", "Phoenix.HTML",
	},
}
