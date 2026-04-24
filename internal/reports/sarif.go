package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/raven-security/raven/internal/engine"
)

// SARIFReport represents a full SARIF v2.1.0 report
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single scan run
type SARIFRun struct {
	Tool       SARIFTool       `json:"tool"`
	Results    []SARIFResult   `json:"results"`
	Taxonomies []SARIFTaxonomy `json:"taxonomies,omitempty"`
	Invocations []SARIFInvocation `json:"invocations"`
}

// SARIFTool describes the scanning tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver
type SARIFDriver struct {
	Name            string        `json:"name"`
	Version         string        `json:"version"`
	InformationURI  string        `json:"informationUri"`
	Rules           []SARIFRule   `json:"rules"`
	SupportedTaxonomies []SARIFSupportedTaxonomy `json:"supportedTaxonomies,omitempty"`
}

// SARIFSupportedTaxonomy references a taxonomy
type SARIFSupportedTaxonomy struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
}

// SARIFRule represents a rule definition
type SARIFRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription SARIFText         `json:"shortDescription"`
	FullDescription  SARIFText         `json:"fullDescription"`
	DefaultConfiguration SARIFConfig   `json:"defaultConfiguration"`
	Properties       SARIFRuleProps    `json:"properties"`
	Relationships    []SARIFRelationship `json:"relationships,omitempty"`
}

// SARIFRelationship maps rule to CWE
type SARIFRelationship struct {
	Target SARIFReference `json:"target"`
	Kinds  []string       `json:"kinds"`
}

// SARIFReference references a taxon
type SARIFReference struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
	ToolComponent SARIFToolComponentRef `json:"toolComponent"`
}

// SARIFToolComponentRef references tool component
type SARIFToolComponentRef struct {
	Name string `json:"name"`
	Index int   `json:"index"`
}

// SARIFText is a text field
type SARIFText struct {
	Text string `json:"text"`
}

// SARIFConfig is rule configuration
type SARIFConfig struct {
	Level string `json:"level"`
}

// SARIFRuleProps contains rule properties
type SARIFRuleProps struct {
	Category        string   `json:"category"`
	Confidence      string   `json:"confidence"`
	CWE             []string `json:"cwe,omitempty"`
	Language        string   `json:"language,omitempty"`
	Precision       string   `json:"precision"`
	SecuritySeverity string  `json:"security-severity,omitempty"`
}

// SARIFResult is a single finding
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
	CodeFlows []SARIFCodeFlow `json:"codeFlows,omitempty"`
	Fixes     []SARIFFix      `json:"fixes,omitempty"`
	SuppressionStates []string `json:"suppressionStates,omitempty"`
	Properties SARIFResultProps `json:"properties,omitempty"`
}

// SARIFMessage is a result message
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation is a code location
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation is a physical code location
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
	ContextRegion    *SARIFRegion          `json:"contextRegion,omitempty"`
}

// SARIFArtifactLocation references a file
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion is a code region
type SARIFRegion struct {
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn,omitempty"`
	EndLine     int    `json:"endLine,omitempty"`
	EndColumn   int    `json:"endColumn,omitempty"`
	Snippet     *SARIFCodeSnippet `json:"snippet,omitempty"`
}

// SARIFCodeSnippet contains the actual code
type SARIFCodeSnippet struct {
	Text string `json:"text"`
}

// SARIFCodeFlow represents taint/data flow
type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

// SARIFThreadFlow is a single data flow thread
type SARIFThreadFlow struct {
	Locations []SARIFThreadLoc `json:"locations"`
}

// SARIFThreadLoc is a single step in data flow
type SARIFThreadLoc struct {
	Location SARIFLocation `json:"location"`
	Kinds    []string      `json:"kinds,omitempty"`
}

// SARIFFix represents a suggested fix
type SARIFFix struct {
	Description SARIFMessage      `json:"description"`
	Changes     []SARIFReplacement `json:"artifactChanges"`
}

// SARIFReplacement is a code replacement
type SARIFReplacement struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Replacements     []SARIFReplaceRegion  `json:"replacements"`
}

// SARIFReplaceRegion is a region to replace
type SARIFReplaceRegion struct {
	DeletedRegion   SARIFRegion  `json:"deletedRegion"`
	InsertedContent SARIFMessage `json:"insertedContent"`
}

// SARIFResultProps contains result properties
type SARIFResultProps struct {
	ConfidenceScore float64 `json:"confidenceScore,omitempty"`
	Exploitability  float64 `json:"exploitability,omitempty"`
}

// SARIFTaxonomy represents CWE taxonomy
type SARIFTaxonomy struct {
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Organization string        `json:"organization"`
	Taxa        []SARIFTaxon   `json:"taxa"`
}

// SARIFTaxon is a single CWE entry
type SARIFTaxon struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	ShortDescription SARIFText `json:"shortDescription,omitempty"`
}

// SARIFInvocation represents scan invocation
type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

// SeverityToSARIFLevel maps Raven severity to SARIF level
func SeverityToSARIFLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// SeverityToSARIFConfig maps severity to SARIF default config level
func SeverityToSARIFConfig(severity string) string {
	switch severity {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "none"
	}
}

// GenerateSARIF creates a full SARIF v2.1.0 report from scan results
func GenerateSARIF(findings []engine.Finding, scanDuration time.Duration) *SARIFReport {
	report := &SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []SARIFRun{},
	}

	// Build unique rules
	ruleMap := make(map[string]SARIFRule)
	for _, f := range findings {
		if _, exists := ruleMap[f.RuleID]; !exists {
			precision := "medium"
			if f.Confidence == "high" {
				precision = "high"
			} else if f.Confidence == "low" {
				precision = "low"
			}

			rule := SARIFRule{
				ID:   f.RuleID,
				Name: f.RuleName,
				ShortDescription: SARIFText{Text: f.RuleName},
				FullDescription:  SARIFText{Text: f.Message},
				DefaultConfiguration: SARIFConfig{
					Level: SeverityToSARIFConfig(string(f.Severity)),
				},
				Properties: SARIFRuleProps{
					Category:   string(f.Category),
					Confidence: string(f.Confidence),
					CWE:        []string{f.CWE},
					Language:   engine.DetectLanguage(f.File),
					Precision:  precision,
				},
			}

			// Add CWE relationship
			if f.CWE != "" {
				rule.Relationships = append(rule.Relationships, SARIFRelationship{
					Target: SARIFReference{
						ID:    f.CWE,
						Index: 0,
						ToolComponent: SARIFToolComponentRef{
							Name: "CWE",
							Index: 0,
						},
					},
					Kinds: []string{"relevant"},
				})
			}

			ruleMap[f.RuleID] = rule
		}
	}

	// Build results
	var results []SARIFResult
	for _, f := range findings {
		level := SeverityToSARIFLevel(string(f.Severity))
		result := SARIFResult{
			RuleID:  f.RuleID,
			Level:   level,
			Message: SARIFMessage{Text: f.Message},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: f.File,
					},
					Region: SARIFRegion{
						StartLine:   f.Line,
						StartColumn: f.Column,
						Snippet: &SARIFCodeSnippet{
							Text: f.Snippet,
						},
					},
				},
			}},
			Properties: SARIFResultProps{
				ConfidenceScore: f.ConfidenceScore,
			},
		}
		results = append(results, result)
	}

	// Build CWE taxonomy
	cweMap := make(map[string]string)
	for _, f := range findings {
		if f.CWE != "" {
			cweMap[f.CWE] = getCWEName(f.CWE)
		}
	}
	var taxa []SARIFTaxon
	for id, name := range cweMap {
		taxa = append(taxa, SARIFTaxon{
			ID:          id,
			Name:        name,
			ShortDescription: SARIFText{Text: name},
		})
	}

	// Build run
	var rules []SARIFRule
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:           "Raven",
				Version:        "2.5.0",
				InformationURI: "https://github.com/raven-security/raven",
				Rules:          rules,
				SupportedTaxonomies: []SARIFSupportedTaxonomy{
					{Name: "CWE", Index: 0},
				},
			},
		},
		Results: results,
		Taxonomies: []SARIFTaxonomy{
			{
				Name:         "CWE",
				Version:      "4.13",
				Organization: "MITRE",
				Taxa:         taxa,
			},
		},
		Invocations: []SARIFInvocation{
			{
				ExecutionSuccessful: true,
				StartTimeUTC:        time.Now().UTC().Add(-scanDuration).Format(time.RFC3339),
				EndTimeUTC:          time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	report.Runs = append(report.Runs, run)
	return report
}

// WriteSARIF writes SARIF report to file
func WriteSARIF(report *SARIFReport, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// getCWEName returns human-readable name for common CWEs
func getCWEName(cwe string) string {
	names := map[string]string{
		"CWE-79":   "Cross-site Scripting (XSS)",
		"CWE-89":   "SQL Injection",
		"CWE-78":   "OS Command Injection",
		"CWE-20":   "Improper Input Validation",
		"CWE-22":   "Path Traversal",
		"CWE-352":  "Cross-Site Request Forgery",
		"CWE-434":  "Unrestricted File Upload",
		"CWE-862":  "Missing Authorization",
		"CWE-476":  "NULL Pointer Dereference",
		"CWE-287":  "Improper Authentication",
		"CWE-190":  "Integer Overflow",
		"CWE-77":   "Command Injection",
		"CWE-798":  "Hardcoded Credentials",
		"CWE-918":  "Server-Side Request Forgery",
		"CWE-306":  "Missing Authentication",
		"CWE-362":  "Race Condition",
		"CWE-269":  "Improper Privilege Management",
		"CWE-94":   "Code Injection",
		"CWE-863":  "Incorrect Authorization",
		"CWE-200":  "Information Exposure",
		"CWE-787":  "Out-of-bounds Write",
		"CWE-416":  "Use After Free",
		"CWE-125":  "Out-of-bounds Read",
		"CWE-119":  "Improper Restriction of Operations",
		"CWE-276":  "Incorrect Default Permissions",
	}
	if name, ok := names[cwe]; ok {
		return name
	}
	return cwe
}

// ExportGitLabSAST exports findings in GitLab SAST JSON format
func ExportGitLabSAST(findings []engine.Finding, scanDuration time.Duration) map[string]interface{} {
	var vulnerabilities []map[string]interface{}

	for _, f := range findings {
		severity := string(f.Severity)
		if severity == "critical" {
			severity = "Critical"
		} else if severity == "high" {
			severity = "High"
		} else if severity == "medium" {
			severity = "Medium"
		} else {
			severity = "Low"
		}

		vuln := map[string]interface{}{
			"id":          f.RuleID,
			"category":    string(f.Category),
			"name":        f.RuleName,
			"message":     f.Message,
			"description": f.Message,
			"severity":    severity,
			"confidence":  string(f.Confidence),
			"scanner": map[string]string{
				"id":   "raven",
				"name": "Raven",
			},
			"location": map[string]interface{}{
				"file":      f.File,
				"start_line": f.Line,
				"class":     filepath.Base(f.File),
				"method":    "",
			},
			"identifiers": []map[string]string{
				{
					"type": "raven_rule_id",
					"name": f.RuleID,
					"value": f.RuleID,
				},
			},
		}

		if f.CWE != "" {
			vuln["identifiers"] = append(vuln["identifiers"].([]map[string]string), map[string]string{
				"type": "cwe",
				"name": f.CWE,
				"value": f.CWE,
				"url":  fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", f.CWE[4:]),
			})
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	return map[string]interface{}{
		"version":      "15.0.0",
		"scan": map[string]interface{}{
			"scanner": map[string]interface{}{
				"id":   "raven",
				"name": "Raven Security Scanner",
				"version": "2.5.0",
				"vendor": map[string]string{"name": "Raven Security"},
			},
			"analyzer": map[string]interface{}{
				"id":   "raven",
				"name": "Raven",
				"vendor": map[string]string{"name": "Raven Security"},
				"version": "2.5.0",
			},
			"start_time": time.Now().UTC().Add(-scanDuration).Format(time.RFC3339),
			"end_time":   time.Now().UTC().Format(time.RFC3339),
			"status":     "success",
			"type":       "sast",
		},
		"vulnerabilities": vulnerabilities,
	}
}

// WriteGitLabSAST writes GitLab SAST report to file
func WriteGitLabSAST(report map[string]interface{}, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}
