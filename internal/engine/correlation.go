package engine

// DefaultRuleGroups maps vulnerability categories to related rule IDs
var DefaultRuleGroups = map[string][]string{
	"sql-injection":      {"sqli", "sql", "query", "database"},
	"xss":                {"xss", "cross-site", "innerHTML", "html"},
	"command-injection":  {"cmdi", "command", "exec", "system", "shell"},
	"path-traversal":     {"pathtraversal", "path", "directory", "file"},
	"ssrf":               {"ssrf", "server-side-request", "request-forgery"},
	"crypto":             {"crypto", "encryption", "hash", "cipher"},
	"auth":               {"auth", "authentication", "session", "login"},
	"injection":          {"injection", "inject", "eval", "template"},
	"deserialization":    {"deserialization", "unserialize", "marshal", "pickle"},
	"secrets":            {"secrets", "password", "api-key", "token"},
	"headers":            {"headers", "cors", "csp", "hsts"},
	"race-condition":     {"race", "deadlock", "concurrency", "thread"},
}

// CorrelationEngine boosts/reduces confidence based on multiple signals
type CorrelationEngine struct {
	ruleGroups map[string][]string
}

// NewCorrelationEngine creates a new correlation engine
func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{ruleGroups: DefaultRuleGroups}
}

// BoostConfidence applies correlation-based confidence adjustment
func (ce *CorrelationEngine) BoostConfidence(findings []Finding, content []byte) []Finding {
	related := ce.FindRelatedFindings(findings)
	for i := range findings {
		key := findings[i].File + ":" + findings[i].Category
		if group, ok := related[key]; ok && len(group) > 1 {
			proximityScore := CalculateProximityScore(findings[i], group)
			findings[i].ConfidenceScore += proximityScore * 0.1
			if findings[i].ConfidenceScore > 1.0 {
				findings[i].ConfidenceScore = 1.0
			}
		}
	}
	return findings
}

// FindRelatedFindings groups findings by proximity and category
func (ce *CorrelationEngine) FindRelatedFindings(findings []Finding) map[string][]Finding {
	groups := make(map[string][]Finding)
	for _, f := range findings {
		key := f.File + ":" + f.Category
		groups[key] = append(groups[key], f)
	}
	return groups
}

// CalculateProximityScore scores how many related findings are nearby
func CalculateProximityScore(finding Finding, related []Finding) float64 {
	if len(related) <= 1 {
		return 0
	}
	nearby := 0
	for _, r := range related {
		if r.RuleID == finding.RuleID {
			continue
		}
		diff := r.Line - finding.Line
		if diff < 0 {
			diff = -diff
		}
		if diff <= 20 {
			nearby++
		}
	}
	return float64(nearby) / float64(len(related))
}
