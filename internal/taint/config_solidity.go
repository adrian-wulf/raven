package taint

func init() {
	RegisterLanguageConfig("solidity", solidityConfig)
}

var solidityConfig = LanguageConfig{
	Sources: []SourcePattern{
		{Pattern: "msg.data", Type: "blockchain"},
		{Pattern: "msg.sender", Type: "blockchain"},
		{Pattern: "msg.value", Type: "blockchain"},
		{Pattern: "tx.origin", Type: "blockchain"},
		{Pattern: "block.timestamp", Type: "blockchain"},
		{Pattern: "block.number", Type: "blockchain"},
		{Pattern: "block.coinbase", Type: "blockchain"},
		{Pattern: "block.difficulty", Type: "blockchain"},
	},
	Sinks: []SinkPattern{
		{Pattern: "call.value", Severity: "critical"},
		{Pattern: "delegatecall", Severity: "critical"},
		{Pattern: "selfdestruct", Severity: "critical"},
		{Pattern: "send(", Severity: "critical"},
		{Pattern: "transfer(", Severity: "critical"},
		{Pattern: "call{value:", Severity: "critical"},
		{Pattern: "address.call", Severity: "critical"},
		{Pattern: "assembly", Severity: "high"},
		{Pattern: "create", Severity: "high"},
		{Pattern: "create2", Severity: "high"},
	},
	Sanitizers: []string{
		"require", "assert", "revert", "check",
		"SafeMath", "OpenZeppelin", "onlyOwner", "nonReentrant",
	},
}
