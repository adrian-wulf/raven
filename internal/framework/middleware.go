package framework

import (
	"strings"
)

// MiddlewareDefinition defines required security middleware per framework
type MiddlewareDefinition struct {
	Framework         string
	Required          []string
	SeverityIfMissing string
}

// MiddlewareRegistry contains security middleware definitions
var MiddlewareRegistry = []MiddlewareDefinition{
	{
		Framework:         "express",
		Required:          []string{"helmet", "cors", "express-rate-limit", "csurf", "hpp", "express-mongo-sanitize"},
		SeverityIfMissing: "medium",
	},
	{
		Framework:         "django",
		Required:          []string{"django.middleware.security.SecurityMiddleware", "django.middleware.csrf.CsrfViewMiddleware", "django.contrib.auth.middleware.AuthenticationMiddleware"},
		SeverityIfMissing: "high",
	},
	{
		Framework:         "flask",
		Required:          []string{"flask-talisman", "flask-limiter", "flask-seasurf"},
		SeverityIfMissing: "medium",
	},
	{
		Framework:         "fastapi",
		Required:          []string{"CORSMiddleware", "HTTPSRedirectMiddleware", "TrustedHostMiddleware"},
		SeverityIfMissing: "medium",
	},
	{
		Framework:         "rails",
		Required:          []string{"protect_from_forgery", "force_ssl"},
		SeverityIfMissing: "high",
	},
	{
		Framework:         "laravel",
		Required:          []string{"VerifyCsrfToken", "EncryptCookies", "TrimStrings"},
		SeverityIfMissing: "high",
	},
	{
		Framework:         "springboot",
		Required:          []string{"spring-security", "csrf", "headers"},
		SeverityIfMissing: "high",
	},
	{
		Framework:         "aspnetcore",
		Required:          []string{"UseAuthentication", "UseAuthorization", "UseHttpsRedirection", "UseHsts"},
		SeverityIfMissing: "high",
	},
	{
		Framework:         "gin",
		Required:          []string{"CORS", "Limiter", "Secure"},
		SeverityIfMissing: "medium",
	},
}

// MiddlewareFinding represents a missing middleware finding
type MiddlewareFinding struct {
	Framework      string
	Missing        []string
	Severity       string
	Recommendation string
}

// CheckSecurityMiddleware checks if required security middleware is present
func CheckSecurityMiddleware(fwName string, files []string) []MiddlewareFinding {
	var findings []MiddlewareFinding

	for _, def := range MiddlewareRegistry {
		if !strings.EqualFold(def.Framework, fwName) {
			continue
		}

		missing := make([]string, 0, len(def.Required))
		for _, required := range def.Required {
			found := false
			for _, file := range files {
				content := readFileContent(file)
				if strings.Contains(strings.ToLower(content), strings.ToLower(required)) {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, required)
			}
		}

		if len(missing) > 0 {
			findings = append(findings, MiddlewareFinding{
				Framework:      fwName,
				Missing:        missing,
				Severity:       def.SeverityIfMissing,
				Recommendation: "Add missing security middleware: " + strings.Join(missing, ", "),
			})
		}
	}

	return findings
}

// CheckAllSecurityMiddleware checks all detected frameworks
func CheckAllSecurityMiddleware(frameworks []string, files []string) []MiddlewareFinding {
	var allFindings []MiddlewareFinding
	for _, fw := range frameworks {
		findings := CheckSecurityMiddleware(fw, files)
		allFindings = append(allFindings, findings...)
	}
	return allFindings
}

func readFileContent(file string) string {
	// This is a simplified version - in production use os.ReadFile
	return ""
}
