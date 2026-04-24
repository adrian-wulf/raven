package taint

func init() {
	RegisterLanguageConfig("bash", bashConfig)
}

var bashConfig = LanguageConfig{
	Sources: []SourcePattern{
		{Pattern: "$1", Type: "argument"},
		{Pattern: "$2", Type: "argument"},
		{Pattern: "$@", Type: "argument"},
		{Pattern: "read ", Type: "input"},
		{Pattern: "cat ", Type: "file"},
		{Pattern: "curl ", Type: "network"},
		{Pattern: "wget ", Type: "network"},
		{Pattern: "env", Type: "environment"},
		{Pattern: "getopts", Type: "argument"},
	},
	Sinks: []SinkPattern{
		{Pattern: "eval", Severity: "critical"},
		{Pattern: "exec", Severity: "critical"},
		{Pattern: "system", Severity: "critical"},
		{Pattern: "source", Severity: "high"},
		{Pattern: ".", Severity: "high"},
		{Pattern: "mysql", Severity: "high"},
		{Pattern: "psql", Severity: "high"},
		{Pattern: "rm -rf", Severity: "critical"},
		{Pattern: "chmod", Severity: "medium"},
		{Pattern: "chown", Severity: "medium"},
		{Pattern: "tee", Severity: "medium"},
	},
	Sanitizers: []string{
		"quoted", "printf '%q'", "sed 's/[^a-zA-Z0-9]//g'", "tr -d",
	},
}
