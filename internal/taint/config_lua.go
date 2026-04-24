package taint

func init() {
	RegisterLanguageConfig("lua", luaConfig)
}

var luaConfig = LanguageConfig{
	Sources: []SourcePattern{
		{Pattern: "arg", Type: "argument"},
		{Pattern: "io.read", Type: "input"},
		{Pattern: "os.getenv", Type: "environment"},
		{Pattern: "socket.receive", Type: "network"},
		{Pattern: "ngx.var", Type: "http"},
		{Pattern: "ngx.req.get_uri_args", Type: "http"},
		{Pattern: "ngx.req.get_post_args", Type: "http"},
		{Pattern: "request", Type: "http"},
	},
	Sinks: []SinkPattern{
		{Pattern: "os.execute", Severity: "critical"},
		{Pattern: "io.popen", Severity: "critical"},
		{Pattern: "loadstring", Severity: "critical"},
		{Pattern: "load", Severity: "critical"},
		{Pattern: "loadfile", Severity: "critical"},
		{Pattern: "dofile", Severity: "high"},
		{Pattern: "require", Severity: "medium"},
		{Pattern: "io.open", Severity: "medium"},
		{Pattern: "socket.http.request", Severity: "medium"},
		{Pattern: "luasql", Severity: "high"},
		{Pattern: "ngx.redirect", Severity: "medium"},
	},
	Sanitizers: []string{
		"ngx.escape_uri", "string.gsub", "string.match",
		"tonumber", "tostring", "ngx.quote_sql_str",
	},
}
