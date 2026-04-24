package llm

import (
	"fmt"
	"strings"
)

// VulnerabilityPrompt holds all prompt data for a specific vulnerability type
type VulnerabilityPrompt struct {
	SystemPrompt     string
	FewShotExamples  map[string]string // language -> examples
	FixGuidance      string
	ValidationRules  []string
}

// PromptRegistry holds all vulnerability-specific prompts
var PromptRegistry = map[string]*VulnerabilityPrompt{
	"sqli":             buildSQLiPrompt(),
	"sql-injection":    buildSQLiPrompt(),
	"xss":              buildXSSPrompt(),
	"cmdi":             buildCommandInjectionPrompt(),
	"command-injection": buildCommandInjectionPrompt(),
	"pathtraversal":    buildPathTraversalPrompt(),
	"path-traversal":   buildPathTraversalPrompt(),
	"secrets":          buildSecretsPrompt(),
	"hardcoded-secrets": buildSecretsPrompt(),
	"ssrf":             buildSSRFPrompt(),
	"crypto":           buildCryptoPrompt(),
	"deserialization":  buildDeserializationPrompt(),
	"jwt":              buildJWTPrompt(),
	"prototype-pollution": buildPrototypePollutionPrompt(),
	"race-condition":   buildRaceConditionPrompt(),
	"idor":             buildIDORPrompt(),
	"ldap-injection":   buildLDAPInjectionPrompt(),
	"xpath-injection":  buildXPathInjectionPrompt(),
	"header-injection": buildHeaderInjectionPrompt(),
	"log-injection":    buildLogInjectionPrompt(),
	"regex-dos":        buildRegexDoSPrompt(),
	"xxe":              buildXXEPrompt(),
	"open-redirect":    buildOpenRedirectPrompt(),
	"cors":             buildCORSPrompt(),
	"csrf":             buildCSRFPrompt(),
	"file-upload":      buildFileUploadPrompt(),
	"insecure-headers": buildInsecureHeadersPrompt(),
}

// GetVulnerabilityPrompt returns the appropriate prompt for a vulnerability type
func GetVulnerabilityPrompt(vulnType string) *VulnerabilityPrompt {
	if vp, ok := PromptRegistry[strings.ToLower(vulnType)]; ok {
		return vp
	}
	return buildGenericPrompt()
}

// BuildEnhancedPrompt creates a full prompt with context
func BuildEnhancedPrompt(code, language, vulnType, description, message, cwe string) string {
	vp := GetVulnerabilityPrompt(vulnType)

	var sb strings.Builder

	// System prompt
	sb.WriteString(vp.SystemPrompt)
	sb.WriteString("\n\n")

	// CWE context
	if cwe != "" {
		sb.WriteString(fmt.Sprintf("CWE Reference: %s\n", cwe))
	}

	// Few-shot examples for the language
	if examples, ok := vp.FewShotExamples[language]; ok {
		sb.WriteString("## Examples of secure fixes:\n\n")
		sb.WriteString(examples)
		sb.WriteString("\n\n")
	} else if examples, ok := vp.FewShotExamples["generic"]; ok {
		sb.WriteString("## Examples of secure fixes:\n\n")
		sb.WriteString(examples)
		sb.WriteString("\n\n")
	}

	// Fix guidance
	sb.WriteString("## Fix Guidance:\n")
	sb.WriteString(vp.FixGuidance)
	sb.WriteString("\n\n")

	// Validation rules
	sb.WriteString("## Validation Checklist:\n")
	for _, rule := range vp.ValidationRules {
		sb.WriteString(fmt.Sprintf("- %s\n", rule))
	}
	sb.WriteString("\n")

	// The actual code to fix
	sb.WriteString(fmt.Sprintf(`Now fix this security vulnerability in %s code.

Vulnerability type: %s
Description: %s
Guidance: %s

Code to fix:
%s%s%s%s

Provide the fixed code. Respond ONLY with the fixed code block, no explanations.`,
		language,
		vulnType,
		description,
		message,
		"\x60\x60\x60", language + "\n",
		code,
		"\n\x60\x60\x60",
	))

	return sb.String()
}

func buildSQLiPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in SQL injection prevention. 
Always use parameterized queries or prepared statements. Never concatenate user input into SQL strings.`,
		FewShotExamples: map[string]string{
			"go": `VULNERABLE:
\x60\x60\x60go
query := "SELECT * FROM users WHERE id = " + userID
rows, err := db.Query(query)
\x60\x60\x60
SECURE:
\x60\x60\x60go
rows, err := db.Query("SELECT * FROM users WHERE id = ?", userID)
\x60\x60\x60`,
			"python": `VULNERABLE:
\x60\x60\x60python
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
\x60\x60\x60
SECURE:
\x60\x60\x60python
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
\x60\x60\x60`,
			"javascript": `VULNERABLE:
\x60\x60\x60javascript
const query = 'SELECT * FROM users WHERE id = ' + req.params.id
await db.query(query)
\x60\x60\x60
SECURE:
\x60\x60\x60javascript
await db.query('SELECT * FROM users WHERE id = ?', [req.params.id])
\x60\x60\x60`,
			"java": `VULNERABLE:
\x60\x60\x60java
String query = "SELECT * FROM users WHERE id = " + userId;
ResultSet rs = stmt.executeQuery(query);
\x60\x60\x60
SECURE:
\x60\x60\x60java
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();
\x60\x60\x60`,
			"php": `VULNERABLE:
\x60\x60\x60php
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($conn, $query);
\x60\x60\x60
SECURE:
\x60\x60\x60php
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
\x60\x60\x60`,
			"csharp": `VULNERABLE:
\x60\x60\x60csharp
var query = $"SELECT * FROM Users WHERE Id = {userId}";
var result = db.Query(query);
\x60\x60\x60
SECURE:
\x60\x60\x60csharp
var query = "SELECT * FROM Users WHERE Id = @id";
var result = db.Query(query, new { id = userId });
\x60\x60\x60`,
			"ruby": `VULNERABLE:
\x60\x60\x60ruby
users = User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
\x60\x60\x60
SECURE:
\x60\x60\x60ruby
users = User.where(id: params[:id])
\x60\x60\x60`,
			"rust": `VULNERABLE:
\x60\x60\x60rust
let query = format!("SELECT * FROM users WHERE id = {}", user_id);
let rows = sqlx::query(&query).fetch_all(&pool).await?;
\x60\x60\x60
SECURE:
\x60\x60\x60rust
let rows = sqlx::query("SELECT * FROM users WHERE id = ?")
    .bind(user_id)
    .fetch_all(&pool)
    .await?;
\x60\x60\x60`,
		},
		FixGuidance: `1. Replace string concatenation/interpolation with parameterized queries
2. Use ? (most DBs), $1 (PostgreSQL), or named parameters (Oracle, SQL Server)
3. Use ORM methods when available (ActiveRecord, Eloquent, Hibernate, GORM)
4. Validate/sanitize input before query as defense in depth
5. Never use exec/eval with SQL strings`,
		ValidationRules: []string{
			"No string concatenation in SQL",
			"Uses parameterized query (? or $1)",
			"User input passed as parameter, not in query string",
		},
	}
}

func buildXSSPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in XSS prevention.
Use context-appropriate encoding: HTML entity encoding, JavaScript hex encoding, URL encoding.
Use safe DOM APIs: textContent instead of innerHTML. Use template auto-escaping.`,
		FewShotExamples: map[string]string{
			"javascript": `VULNERABLE:
\x60\x60\x60javascript
element.innerHTML = userInput
\x60\x60\x60
SECURE:
\x60\x60\x60javascript
element.textContent = userInput
\x60\x60\x60`,
			"php": `VULNERABLE:
\x60\x60\x60php
echo "Hello, " . $name;
\x60\x60\x60
SECURE:
\x60\x60\x60php
echo "Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
\x60\x60\x60`,
			"python": `VULNERABLE:
\x60\x60\x60python
return f"<div>{user_input}</div>"
\x60\x60\x60
SECURE:
\x60\x60\x60python
from markupsafe import escape
return f"<div>{escape(user_input)}</div>"
\x60\x60\x60`,
			"java": `VULNERABLE:
\x60\x60\x60java
out.write("<div>" + userInput + "</div>");
\x60\x60\x60
SECURE:
\x60\x60\x60java
out.write("<div>" + HtmlUtils.htmlEscape(userInput) + "</div>");
\x60\x60\x60`,
		},
		FixGuidance: `1. Use textContent/innerText instead of innerHTML
2. Use htmlspecialchars() in PHP with ENT_QUOTES flag
3. Use template engine auto-escaping (Jinja2, ERB, Razor)
4. Use DOMPurify for HTML sanitization when HTML is needed
5. Set Content-Security-Policy header as defense in depth
6. Use OWASP Java Encoder or equivalent`,
		ValidationRules: []string{
			"No innerHTML/outerHTML with user data",
			"Uses context-appropriate encoding",
			"Uses safe DOM API (textContent/innerText)",
		},
	}
}

func buildCommandInjectionPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in command injection prevention.
Never pass user input to shell commands. Use argument lists instead of shell strings.`,
		FewShotExamples: map[string]string{
			"python": `VULNERABLE:
\x60\x60\x60python
os.system("ls " + user_input)
\x60\x60\x60
SECURE:
\x60\x60\x60python
import subprocess
subprocess.run(["ls", user_input], capture_output=True)
\x60\x60\x60`,
			"go": `VULNERABLE:
\x60\x60\x60go
cmd := exec.Command("sh", "-c", "ping "+userInput)
\x60\x60\x60
SECURE:
\x60\x60\x60go
cmd := exec.Command("ping", userInput)
\x60\x60\x60`,
			"java": `VULNERABLE:
\x60\x60\x60java
Runtime.getRuntime().exec("sh -c ping " + userInput);
\x60\x60\x60
SECURE:
\x60\x60\x60java
new ProcessBuilder("ping", userInput).start();
\x60\x60\x60`,
		},
		FixGuidance: `1. Pass arguments as arrays, not shell strings
2. Avoid shell=True, /bin/sh, cmd.exe /c
3. Use exec.Command(name, arg...) in Go
4. Use subprocess.run([cmd, arg], shell=False) in Python
5. Use ProcessBuilder in Java
6. Validate input against strict allowlist`,
		ValidationRules: []string{
			"No shell=True or equivalent",
			"Arguments passed as array/list",
			"No string concatenation in command",
		},
	}
}

func buildPathTraversalPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in path traversal prevention.
Validate paths are within allowed directories. Reject .. sequences. Use path normalization.`,
		FewShotExamples: map[string]string{
			"python": `VULNERABLE:
\x60\x60\x60python
with open(f"/data/{filename}") as f:
    return f.read()
\x60\x60\x60
SECURE:
\x60\x60\x60python
from pathlib import Path
safe_path = Path("/data") / filename
if not safe_path.resolve().is_relative_to(Path("/data")):
    raise ValueError("Invalid path")
with open(safe_path) as f:
    return f.read()
\x60\x60\x60`,
			"go": `VULNERABLE:
\x60\x60\x60go
content, err := os.ReadFile("/data/" + filename)
\x60\x60\x60
SECURE:
\x60\x60\x60go
cleanPath := filepath.Clean(filename)
if strings.Contains(cleanPath, "..") {
    return nil, errors.New("invalid path")
}
content, err := os.ReadFile(filepath.Join("/data", cleanPath))
\x60\x60\x60`,
		},
		FixGuidance: `1. Validate resolved path is within allowed directory
2. Reject .. sequences after normalization
3. Use Path.resolve() in Python, filepath.Clean() in Go
4. Use chroot/jail when possible
5. Use allowlist of permitted filenames when possible`,
		ValidationRules: []string{
			"Path validated before use",
			"No direct user input in file path",
			"Resolved path checked against allowed directory",
		},
	}
}

func buildSecretsPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in secret management.
Never hardcode secrets. Use environment variables or secret management services.`,
		FewShotExamples: map[string]string{
			"python": `VULNERABLE:
\x60\x60\x60python
API_KEY = "sk-abc123xyz789"
\x60\x60\x60
SECURE:
\x60\x60\x60python
import os
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")
\x60\x60\x60`,
		},
		FixGuidance: `1. Load secrets from environment variables
2. Use secret managers (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)
3. Use .env files with python-dotenv (development only, never commit)
4. Add secrets to .gitignore
5. Rotate exposed secrets immediately`,
		ValidationRules: []string{
			"No hardcoded API keys, passwords, or tokens",
			"Uses environment variables or secret manager",
		},
	}
}

func buildSSRFPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in SSRF prevention.
Validate URLs against allowlists. Block private IP ranges. Use URL parsers.`,
		FixGuidance: `1. Validate URLs against allowlist of permitted hosts
2. Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
3. Block localhost variants (127.0.0.1, [::1], 0.0.0.0)
4. Use URL parser to extract hostname
5. Use DNS resolution controls when available
6. Disable HTTP redirects or validate redirect targets`,
		ValidationRules: []string{
			"URL validated against allowlist",
			"Private IP ranges blocked",
		},
	}
}

func buildCryptoPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in cryptography.
Use modern algorithms. Avoid deprecated/insecure algorithms.`,
		FixGuidance: `1. Passwords: Use bcrypt, Argon2id, or scrypt (NOT MD5, SHA1, SHA256)
2. Encryption: Use AES-256-GCM or ChaCha20-Poly1305
3. Hashing: Use SHA-256 or SHA-3 for integrity
4. Random: Use cryptographically secure RNG (os.urandom, crypto/rand)
5. Avoid: MD5, SHA1, DES, 3DES, RC4, ECB mode, RSA < 2048
6. Use TLS 1.3 when possible, minimum TLS 1.2`,
		ValidationRules: []string{
			"Uses modern algorithm",
			"No deprecated crypto",
		},
	}
}

func buildDeserializationPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in deserialization security.
Never deserialize untrusted data with pickle, ObjectInputStream, or unserialize().`,
		FixGuidance: `1. Use JSON, MessagePack, or protobuf instead of native serialization
2. If native serialization needed, implement schema validation
3. Sign serialized data with HMAC to prevent tampering
4. Use yaml.safe_load() instead of yaml.load() in Python
5. Implement deserialization allowlists`,
		ValidationRules: []string{
			"Uses safe serialization format",
			"Untrusted data not deserialized natively",
		},
	}
}

func buildJWTPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in JWT security.
Always verify signatures. Whitelist allowed algorithms. Use strong secrets.`,
		FixGuidance: `1. Always verify JWT signature with secret/public key
2. Whitelist allowed algorithms (never allow 'none')
3. Verify issuer, audience, and expiration
4. Use strong secrets (256+ bits) or asymmetric keys (RS256, ES256)
5. Store secrets securely (NOT in code)
6. Implement token revocation/rotation`,
		ValidationRules: []string{
			"Algorithm verified (not 'none')",
			"Signature verified",
			"Expiration checked",
		},
	}
}

func buildPrototypePollutionPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in prototype pollution prevention.
Prevent attacker-controlled property names from reaching Object.prototype.`,
		FixGuidance: `1. Use Object.create(null) for maps
2. Validate property names against allowlist
3. Use Map instead of plain objects
4. Use Object.freeze(Object.prototype) as defense
5. Avoid recursive merge with untrusted input
6. Use structuredClone() instead of lodash merge/extend`,
		ValidationRules: []string{
			"Property names validated",
			"Uses Map or Object.create(null)",
		},
	}
}

func buildRaceConditionPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in race condition prevention.
Use proper synchronization. Avoid TOCTOU vulnerabilities.`,
		FixGuidance: `1. Use mutexes for shared state
2. Use atomic operations when possible
3. Use channels for Go goroutine communication
4. Avoid double-checked locking
5. Validate file existence AND permissions atomically
6. Use file locking mechanisms`,
		ValidationRules: []string{
			"Proper synchronization used",
			"No TOCTOU vulnerability",
		},
	}
}

func buildIDORPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant specializing in access control (IDOR/BAC).
Always verify user has permission to access requested resources.`,
		FixGuidance: `1. Verify authenticated user owns the requested resource
2. Use indirect reference maps (UUIDs instead of sequential IDs)
3. Implement authorization checks in middleware
4. Log access control failures
5. Use policy-based access control (RBAC/ABAC)`,
		ValidationRules: []string{
			"Authorization check present",
			"User verified against resource",
		},
	}
}

func buildLDAPInjectionPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Prevent LDAP injection by escaping user input in LDAP filters.`,
		FixGuidance: `1. Escape special LDAP characters (*, (, ), \, NUL)
2. Use parameterized LDAP queries when available
3. Validate input against allowlist
4. Use framework LDAP libraries with built-in escaping`,
		ValidationRules: []string{"LDAP characters escaped"},
	}
}

func buildXPathInjectionPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Prevent XPath injection by parameterizing queries.`,
		FixGuidance: `1. Use XPath variables/parameters
2. Escape quotes in user input
3. Validate input against allowlist
4. Use precompiled XPath expressions`,
		ValidationRules: []string{"XPath parameterized"},
	}
}

func buildHeaderInjectionPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Prevent HTTP header injection by sanitizing CRLF characters.`,
		FixGuidance: `1. Remove \r and \n from user input in headers
2. Use framework methods for setting headers
3. Validate header values
4. Use allowlist of permitted headers`,
		ValidationRules: []string{"No CRLF in headers"},
	}
}

func buildLogInjectionPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Prevent log injection by sanitizing user input in log messages.`,
		FixGuidance: `1. Remove newlines from user input in logs
2. Use structured logging (JSON)
3. Validate log content
4. Never log sensitive data (passwords, tokens, PII)`,
		ValidationRules: []string{"No newlines in log data"},
	}
}

func buildRegexDoSPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Prevent ReDoS by avoiding exponential regex patterns.`,
		FixGuidance: `1. Avoid nested quantifiers (a+)+, (a*)*
2. Use possessive/atomic quantifiers when available
3. Set regex timeout
4. Use linear-time regex engines (RE2, Go regex)
5. Validate regex complexity before use`,
		ValidationRules: []string{"No catastrophic backtracking"},
	}
}

func buildXXEPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Prevent XXE by disabling external entities in XML parsers.`,
		FixGuidance: `1. Disable DTDs entirely when possible
2. Disable external entities
3. Disable external parameter entities
4. Use safe XML parsers (defusedxml in Python)
5. Consider using JSON instead of XML`,
		ValidationRules: []string{"External entities disabled"},
	}
}

func buildOpenRedirectPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Prevent open redirect by validating redirect URLs.`,
		FixGuidance: `1. Validate redirect URLs against allowlist
2. Use relative URLs only
3. Map redirect targets to allowed destinations
4. Add confirmation page for external redirects`,
		ValidationRules: []string{"Redirect URL validated"},
	}
}

func buildCORSPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Fix CORS misconfigurations. Never use wildcard with credentials.`,
		FixGuidance: `1. Never use Access-Control-Allow-Origin: * with credentials
2. Use specific origin allowlist
3. Validate Origin header server-side
4. Use Vary: Origin header
5. Minimize allowed methods and headers`,
		ValidationRules: []string{"No wildcard with credentials"},
	}
}

func buildCSRFPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Prevent CSRF by implementing proper token validation.`,
		FixGuidance: `1. Implement CSRF token validation
2. Use SameSite cookies (Strict or Lax)
3. Validate Referer/Origin headers
4. Use double-submit cookie pattern
5. Add custom request headers for state-changing requests`,
		ValidationRules: []string{"CSRF token validated"},
	}
}

func buildFileUploadPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Secure file upload by validating type, size, and extension.`,
		FixGuidance: `1. Validate file type by content (magic bytes), not extension
2. Use allowlist of permitted types
3. Set maximum file size
4. Store uploads outside web root
5. Rename files to prevent executable extensions
6. Scan uploads for malware`,
		ValidationRules: []string{"File type validated"},
	}
}

func buildInsecureHeadersPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `Add missing security headers.`,
		FixGuidance: `1. Strict-Transport-Security (HSTS)
2. X-Content-Type-Options: nosniff
3. X-Frame-Options or CSP frame-ancestors
4. Content-Security-Policy
5. Referrer-Policy
6. Permissions-Policy`,
		ValidationRules: []string{"Security headers present"},
	}
}

func buildGenericPrompt() *VulnerabilityPrompt {
	return &VulnerabilityPrompt{
		SystemPrompt: `You are a security code fixing assistant. Fix the vulnerability while preserving functionality.`,
		FewShotExamples: map[string]string{
			"generic": `General security fix principles:
1. Validate all user input (whitelist approach)
2. Use parameterized APIs instead of string concatenation
3. Apply context-appropriate encoding
4. Never trust client-side data
5. Use principle of least privilege`,
		},
		FixGuidance: `1. Identify the vulnerability pattern
2. Apply defense-in-depth
3. Preserve original functionality
4. Add input validation where missing
5. Use secure alternatives to dangerous functions`,
		ValidationRules: []string{
			"Vulnerability pattern removed",
			"Functionality preserved",
		},
	}
}
