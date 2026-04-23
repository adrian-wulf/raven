package output

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/raven-security/raven/internal/engine"
	"github.com/raven-security/raven/internal/version"
)

func (f *Formatter) printHTML(result *engine.Result) error {
	bySev := result.BySeverity()
	data := htmlData{
		Version:       version.Version,
		Timestamp:     time.Now().Format("2006-01-02 15:04:05"),
		FilesScanned:  result.FilesScanned,
		RulesRun:      result.RulesRun,
		Duration:      result.Duration.String(),
		TotalFindings: len(result.Findings),
		Critical:      len(bySev[engine.Critical]),
		High:          len(bySev[engine.High]),
		Medium:        len(bySev[engine.Medium]),
		Low:           len(bySev[engine.Low]),
		Info:          len(bySev[engine.Info]),
		Findings:      make([]htmlFinding, 0, len(result.Findings)),
	}

	for _, f := range result.Findings {
		hf := htmlFinding{
			RuleID:     f.RuleID,
			RuleName:   f.RuleName,
			Severity:   string(f.Severity),
			Category:   f.Category,
			Message:    f.Message,
			File:       f.File,
			Line:       f.Line,
			Column:     f.Column,
			Snippet:    template.HTMLEscapeString(f.Snippet),
			Confidence: f.Confidence,
			References: f.References,
			Fix:        f.Fix != nil,
			FixDesc:    "",
		}
		if f.Fix != nil {
			hf.FixDesc = f.Fix.Description
		}
		data.Findings = append(data.Findings, hf)
	}

	for i, v := range result.Vulnerabilities {
		data.Vulns = append(data.Vulns, htmlVuln{
			ID:           v.ID,
			Package:      v.Package,
			Version:      v.Version,
			FixedVersion: v.FixedVersion,
			Summary:      v.Summary,
			Severity:     v.Severity,
		})
		if i >= 4 {
			break
		}
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": func(s string) string {
			switch s {
			case "critical":
				return "severity-critical"
			case "high":
				return "severity-high"
			case "medium":
				return "severity-medium"
			case "low":
				return "severity-low"
			default:
				return "severity-info"
			}
		},
		"severityColor": func(s string) string {
			switch s {
			case "critical":
				return "#FF0000"
			case "high":
				return "#FF6B6B"
			case "medium":
				return "#FDCB6E"
			case "low":
				return "#74B9FF"
			default:
				return "#A29BFE"
			}
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	return tmpl.Execute(os.Stdout, data)
}

type htmlData struct {
	Version       string
	Timestamp     string
	FilesScanned  int
	RulesRun      int
	Duration      string
	TotalFindings int
	Critical      int
	High          int
	Medium        int
	Low           int
	Info          int
	Findings      []htmlFinding
	Vulns         []htmlVuln
}

type htmlFinding struct {
	RuleID     string
	RuleName   string
	Severity   string
	Category   string
	CWE        string
	Message    string
	File       string
	Line       int
	Column     int
	Snippet    string
	Confidence string
	References []string
	Fix        bool
	FixDesc    string
}

type htmlVuln struct {
	ID           string
	Package      string
	Version      string
	FixedVersion string
	Summary      string
	Severity     string
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Raven Security Report</title>
<style>
:root{--bg:#0f0f1a;--card:#1a1a2e;--text:#e0e0e0;--muted:#888;--accent:#6C5CE7;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}
.container{max-width:1200px;margin:0 auto}
header{display:flex;align-items:center;gap:1rem;margin-bottom:2rem}
header h1{font-size:2rem;background:linear-gradient(90deg,#6C5CE7,#a29bfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
header .meta{color:var(--muted);font-size:.9rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:2rem}
.stat-card{background:var(--card);border-radius:12px;padding:1.5rem;text-align:center;border:1px solid #2a2a3e}
.stat-card .number{font-size:2.5rem;font-weight:700}
.stat-card .label{color:var(--muted);font-size:.85rem;text-transform:uppercase;letter-spacing:.05em}
.severity-critical .number{color:#FF0000}
.severity-high .number{color:#FF6B6B}
.severity-medium .number{color:#FDCB6E}
.severity-low .number{color:#74B9FF}
.severity-info .number{color:#A29BFE}
.filters{display:flex;gap:.5rem;margin-bottom:1.5rem;flex-wrap:wrap}
.filters button{background:var(--card);border:1px solid #2a2a3e;color:var(--text);padding:.5rem 1rem;border-radius:8px;cursor:pointer;font-size:.9rem;transition:.2s}
.filters button:hover,.filters button.active{background:var(--accent);border-color:var(--accent)}
.findings{display:flex;flex-direction:column;gap:1rem}
.finding{background:var(--card);border-radius:12px;padding:1.25rem;border:1px solid #2a2a3e;transition:.2s}
.finding:hover{border-color:var(--accent)}
.finding-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:.75rem;flex-wrap:wrap;gap:.5rem}
.finding-title{display:flex;align-items:center;gap:.75rem}
.severity-badge{padding:.25rem .75rem;border-radius:6px;font-size:.75rem;font-weight:700;text-transform:uppercase;color:#fff}
.finding-location{color:var(--muted);font-size:.85rem;font-family:monospace}
.finding-message{color:var(--text);margin-bottom:.75rem}
.finding-snippet{background:#0f0f1a;border-radius:8px;padding:1rem;font-family:'Fira Code',monospace;font-size:.85rem;overflow-x:auto;border:1px solid #2a2a3e;margin-bottom:.75rem}
.finding-meta{display:flex;gap:1rem;color:var(--muted);font-size:.85rem;flex-wrap:wrap}
.finding-fix{color:#55EFC4;font-size:.85rem}
.empty{text-align:center;padding:4rem;color:var(--muted)}
.empty h2{font-size:1.5rem;margin-bottom:.5rem;color:#55EFC4}
.vulns{margin-top:2rem}
.vuln-card{background:var(--card);border-radius:8px;padding:1rem;border:1px solid #2a2a3e;margin-bottom:.5rem}
.vuln-sev{font-weight:700;color:#FF6B6B}
footer{text-align:center;margin-top:3rem;color:var(--muted);font-size:.85rem}
</style>
</head>
<body>
<div class="container">
<header>
<h1>🐦‍⬛ Raven</h1>
<span class="meta">v{{.Version}} &middot; {{.Timestamp}} &middot; {{.FilesScanned}} files &middot; {{.Duration}}</span>
</header>

{{if eq .TotalFindings 0}}
<div class="empty">
<h2>✅ No security issues found!</h2>
<p>Your code looks clean. Keep up the good work!</p>
</div>
{{else}}
<div class="stats">
<div class="stat-card severity-critical"><div class="number">{{.Critical}}</div><div class="label">Critical</div></div>
<div class="stat-card severity-high"><div class="number">{{.High}}</div><div class="label">High</div></div>
<div class="stat-card severity-medium"><div class="number">{{.Medium}}</div><div class="label">Medium</div></div>
<div class="stat-card severity-low"><div class="number">{{.Low}}</div><div class="label">Low</div></div>
<div class="stat-card severity-info"><div class="number">{{.Info}}</div><div class="label">Info</div></div>
</div>

<div class="filters">
<button class="active" onclick="filter('all')">All ({{.TotalFindings}})</button>
<button onclick="filter('critical')">Critical ({{.Critical}})</button>
<button onclick="filter('high')">High ({{.High}})</button>
<button onclick="filter('medium')">Medium ({{.Medium}})</button>
<button onclick="filter('low')">Low ({{.Low}})</button>
</div>

<div class="findings">
{{range .Findings}}
<div class="finding" data-severity="{{.Severity}}">
<div class="finding-header">
<div class="finding-title">
<span class="severity-badge" style="background:{{severityColor .Severity}}">{{.Severity}}</span>
<strong>{{.RuleName}}</strong>
</div>
<div class="finding-location">{{.File}}:{{.Line}}:{{.Column}}</div>
</div>
<div class="finding-message">{{.Message}}</div>
{{if .Snippet}}<div class="finding-snippet"><pre>{{.Snippet}}</pre></div>{{end}}
<div class="finding-meta">
<span>ID: {{.RuleID}}</span>
<span>Category: {{.Category}}</span>
{{if .CWE}}<span>CWE: {{.CWE}}</span>{{end}}
<span>Confidence: {{.Confidence}}</span>
</div>
{{if .Fix}}<div class="finding-fix">💡 {{.FixDesc}}</div>{{end}}
</div>
{{end}}
</div>
{{end}}

{{if .Vulns}}
<div class="vulns">
<h2 style="margin-bottom:1rem">Vulnerable Dependencies</h2>
{{range .Vulns}}
<div class="vuln-card">
<span class="vuln-sev">{{.Severity}}</span> &middot; <strong>{{.ID}}</strong> &middot; {{.Package}}@{{.Version}} &rarr; {{.FixedVersion}}
{{if .Summary}}<p style="color:var(--muted);margin-top:.5rem;font-size:.9rem">{{.Summary}}</p>{{end}}
</div>
{{end}}
</div>
{{end}}

<footer>
Generated by Raven v{{.Version}} &middot; Open source security scanner for vibe coders
</footer>
</div>

<script>
function filter(sev){
  document.querySelectorAll('.filters button').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(f=>{
    f.style.display = (sev==='all' || f.dataset.severity===sev) ? 'block' : 'none';
  });
}
</script>
</body>
</html>
`
