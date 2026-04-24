package taint

func init() {
	RegisterLanguageConfig("scala", scalaConfig)
}

var scalaConfig = LanguageConfig{
	Sources: []SourcePattern{
		{Pattern: "request.queryString", Type: "http"},
		{Pattern: "request.body", Type: "http"},
		{Pattern: "params", Type: "http"},
		{Pattern: "args", Type: "argument"},
		{Pattern: "scala.io.StdIn", Type: "input"},
		{Pattern: "System.getenv", Type: "environment"},
		{Pattern: "request.headers", Type: "http"},
		{Pattern: "request.path", Type: "http"},
	},
	Sinks: []SinkPattern{
		{Pattern: "sql", Severity: "critical"},
		{Pattern: "DB.withConnection", Severity: "critical"},
		{Pattern: "raw", Severity: "critical"},
		{Pattern: "slick.jdbc", Severity: "critical"},
		{Pattern: "Runtime.exec", Severity: "critical"},
		{Pattern: "ProcessBuilder", Severity: "critical"},
		{Pattern: "Process", Severity: "critical"},
		{Pattern: "scala.tools.nsc", Severity: "critical"},
		{Pattern: "ObjectInputStream", Severity: "high"},
		{Pattern: "new File", Severity: "medium"},
		{Pattern: "WS.url", Severity: "medium"},
		{Pattern: "render", Severity: "medium"},
	},
	Sanitizers: []string{
		"HtmlFormat.escape", "UriEncoding.encodePath", "StringEscapeUtils",
		"play.api.libs.json.Json", "scala.xml.Utility.escape",
	},
}
