package taint

func init() {
	RegisterLanguageConfig("dart", dartConfig)
}

var dartConfig = LanguageConfig{
	Sources: []SourcePattern{
		{Pattern: "stdin", Type: "input"},
		{Pattern: "args", Type: "argument"},
		{Pattern: "TextEditingController", Type: "input"},
		{Pattern: "queryParameters", Type: "http"},
		{Pattern: "headers", Type: "http"},
		{Pattern: "uri.pathSegments", Type: "http"},
		{Pattern: "MethodChannel", Type: "input"},
	},
	Sinks: []SinkPattern{
		{Pattern: "eval", Severity: "critical"},
		{Pattern: "execute", Severity: "critical"},
		{Pattern: "rawQuery", Severity: "critical"},
		{Pattern: "innerHtml", Severity: "high"},
		{Pattern: "loadUrl", Severity: "high"},
		{Pattern: "open", Severity: "high"},
		{Pattern: "File(", Severity: "medium"},
		{Pattern: "http.get", Severity: "medium"},
		{Pattern: "http.post", Severity: "medium"},
		{Pattern: "Process.run", Severity: "critical"},
		{Pattern: "Process.start", Severity: "critical"},
	},
	Sanitizers: []string{
		"HtmlEscape", "Uri.encodeComponent", "Uri.encodeFull",
		"RegExp.escape", "validator", "int.parse", "double.parse",
	},
}
