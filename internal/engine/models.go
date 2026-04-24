package engine

import (
	"time"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// SeverityCategory is a string-based category type used for baseline comparisons.
type SeverityCategory string

// ScanSummary holds aggregate counts for a scan.
type ScanSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type Rule struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Severity    Severity  `yaml:"severity"`
	Category    string    `yaml:"category"`
	Confidence  string    `yaml:"confidence"` // high, medium, low
	CWE         string    `yaml:"cwe,omitempty"`
	Languages   []string  `yaml:"languages"`
	Frameworks  []string  `yaml:"frameworks,omitempty"`
	Patterns    []Pattern `yaml:"patterns"`
	Fix         *Fix      `yaml:"fix,omitempty"`
	References  []string  `yaml:"references,omitempty"`
	Message     string    `yaml:"message"`
}

type Pattern struct {
	Type       string        `yaml:"type"`    // regex, literal, ast-query, taint
	Pattern    string        `yaml:"pattern"`
	Query      string        `yaml:"query"`   // for ast-query patterns
	Sources    []string      `yaml:"sources,omitempty"`
	Sinks      []string      `yaml:"sinks,omitempty"`
	Where      []WhereClause `yaml:"where,omitempty"`
	Inside     *Pattern      `yaml:"inside,omitempty"`
	NotInside  *Pattern      `yaml:"not-inside,omitempty"`
}

type WhereClause struct {
	NotConstant  bool     `yaml:"not-constant,omitempty"`
	NotSanitized []string `yaml:"not-sanitized,omitempty"`
	NotTestFile  bool     `yaml:"not-test-file,omitempty"`
	InsideFunction string `yaml:"inside-function,omitempty"`
}

type Fix struct {
	Description string `yaml:"description"`
	Pattern     string `yaml:"pattern"`     // regex to match
	Replace     string `yaml:"replace"`     // replacement template
}

type Finding struct {
	RuleID       string            `json:"rule_id"`
	RuleName     string            `json:"rule_name"`
	Severity     Severity          `json:"severity"`
	Category     string            `json:"category"`
	CWE          string            `json:"cwe,omitempty"`
	Message      string            `json:"message"`
	File         string            `json:"file"`
	Line         int               `json:"line"`
	Column       int               `json:"column"`
	Snippet      string            `json:"snippet"`
	Fix          *Fix              `json:"fix,omitempty"`
	FixAvailable bool              `json:"fix_available"`
	References   []string          `json:"references,omitempty"`
	Confidence     string            `json:"confidence"`
	ConfidenceScore float64          `json:"confidence_score,omitempty"`
	Metavars       map[string]string `json:"metavars,omitempty"`
}

type Result struct {
	Findings         []Finding       `json:"findings"`
	NewFindings      []Finding       `json:"new_findings,omitempty"`
	BaselineFindings []Finding       `json:"baseline_findings,omitempty"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities,omitempty"`
	FilesScanned     int             `json:"files_scanned"`
	RulesRun         int             `json:"rules_run"`
	Duration         time.Duration   `json:"duration"`
	Target           string          `json:"target"`
}

type Vulnerability struct {
	ID           string   `json:"id"`
	Summary      string   `json:"summary"`
	Severity     string   `json:"severity"`
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	FixedVersion string   `json:"fixed_version"`
	References   []string `json:"references,omitempty"`
}

func (r *Result) BySeverity() map[Severity][]Finding {
	m := make(map[Severity][]Finding)
	for _, f := range r.Findings {
		m[f.Severity] = append(m[f.Severity], f)
	}
	return m
}

func (r *Result) HasFixes() bool {
	for _, f := range r.Findings {
		if f.FixAvailable {
			return true
		}
	}
	return false
}

func SeverityRank(s Severity) int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}
