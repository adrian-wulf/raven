package llm

import (
	"fmt"
	"strings"
)

// PromptBuilder creates optimized prompts per vulnerability category
type PromptBuilder struct {
	Category string
	Language string
}

// Build creates a tailored prompt with few-shot examples
func (pb *PromptBuilder) Build(code, vulnType, description, message string) string {
	// Select few-shot examples based on category
	examples := getFewShotExamples(pb.Category, pb.Language)

	var sb strings.Builder
	sb.WriteString(systemPrompt)
	sb.WriteString("\n\n")

	if examples != "" {
		sb.WriteString("## Examples of secure fixes:\n\n")
		sb.WriteString(examples)
		sb.WriteString("\n\n")
	}

	sb.WriteString(fmt.Sprintf(`Now fix this security vulnerability in %s code.

Vulnerability type: %s
Description: %s
Guidance: %s

Code to fix:
｠｠｠%s
%s
｠｠｠

Provide the fixed code.`,
		pb.Language,
		vulnType,
		description,
		message,
		pb.Language,
		code,
	))

	return sb.String()
}

// getFewShotExamples returns relevant examples for the vulnerability category
func getFewShotExamples(category, language string) string {
	switch strings.ToLower(category) {
	case "sqli", "sql-injection", "sql injection":
		return fewShotSQLi(language)
	case "xss", "cross-site scripting", "cross site scripting":
		return fewShotXSS(language)
	case "cmdi", "command-injection", "command injection":
		return fewShotCommandInjection(language)
	case "path-traversal", "path traversal", "lfi", "directory-traversal":
		return fewShotPathTraversal(language)
	case "secrets", "hardcoded-secrets", "hardcoded secrets":
		return fewShotSecrets(language)
	case "ssrf", "server-side request forgery":
		return fewShotSSRF(language)
	case "crypto", "weak-crypto", "weak crypto", "insecure-random":
		return fewShotCrypto(language)
	case "deserialization", "insecure-deserialization":
		return fewShotDeserialization(language)
	case "idor", "broken-access-control":
		return fewShotAccessControl(language)
	default:
		return fewShotGeneric(language)
	}
}

func fewShotSQLi(lang string) string {
	switch lang {
	case "go":
		return `Example 1 — SQL Injection (Go):
VULNERABLE:
｠｠｠go
query := "SELECT * FROM users WHERE id = " + userID
rows, err := db.Query(query)
｠｠｠
SECURE:
｠｠｠go
rows, err := db.Query("SELECT * FROM users WHERE id = ?", userID)
｠｠｠

Example 2 — SQL Injection with fmt.Sprintf (Go):
VULNERABLE:
｠｠｠go
query := fmt.Sprintf("SELECT * FROM products WHERE name = '%s'", name)
｠｠｠
SECURE:
｠｠｠go
query := "SELECT * FROM products WHERE name = ?"
rows, err := db.Query(query, name)
｠｠｠`
	case "python":
		return `Example 1 — SQL Injection (Python):
VULNERABLE:
｠｠｠python
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
｠｠｠
SECURE:
｠｠｠python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
｠｠｠

Example 2 — SQL Injection with f-string (Python):
VULNERABLE:
｠｠｠python
cursor.execute(f"SELECT * FROM products WHERE name = '{name}'")
｠｠｠
SECURE:
｠｠｠python
cursor.execute("SELECT * FROM products WHERE name = %s", (name,))
｠｠｠`
	case "javascript", "typescript":
		return `Example 1 — SQL Injection (Node.js):
VULNERABLE:
｠｠｠javascript
const query = 'SELECT * FROM users WHERE id = ' + userId
await db.query(query)
｠｠｠
SECURE:
｠｠｠javascript
await db.query('SELECT * FROM users WHERE id = ?', [userId])
｠｠｠

Example 2 — SQL Injection with string concat:
VULNERABLE:
｠｠｠javascript
const query = "SELECT * FROM products WHERE name = '" + name + "'"
｠｠｠
SECURE:
｠｠｠javascript
await db.query('SELECT * FROM products WHERE name = $1', [name])
｠｠｠`
	case "php":
		return `Example 1 — SQL Injection (PHP):
VULNERABLE:
｠｠｠php
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($conn, $query);
｠｠｠
SECURE:
｠｠｠php
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
｠｠｠`
	case "java":
		return `Example 1 — SQL Injection (Java):
VULNERABLE:
｠｠｠java
String query = "SELECT * FROM users WHERE id = " + userId;
ResultSet rs = stmt.executeQuery(query);
｠｠｠
SECURE:
｠｠｠java
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();
｠｠｠`
	default:
		return `Example — SQL Injection fix pattern:
ALWAYS use parameterized queries/prepared statements.
NEVER concatenate user input into SQL strings.
Use ? placeholders (most languages) or $1/$2 (PostgreSQL).`
	}
}

func fewShotXSS(lang string) string {
	switch lang {
	case "javascript", "typescript":
		return `Example 1 — Reflected XSS (JavaScript):
VULNERABLE:
｠｠｠javascript
element.innerHTML = userInput
｠｠｠
SECURE:
｠｠｠javascript
element.textContent = userInput  // Or: element.innerText = userInput
｠｠｠

Example 2 — Dangerous HTML rendering:
VULNERABLE:
｠｠｠javascript
document.write("<div>" + userData + "</div>")
｠｠｠
SECURE:
｠｠｠javascript
const div = document.createElement('div')
div.textContent = userData
document.body.appendChild(div)
｠｠｠`
	case "php":
		return `Example — XSS (PHP):
VULNERABLE:
｠｠｠php
echo "Hello, " . $_GET['name'];
｠｠｠
SECURE:
｠｠｠php
echo "Hello, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
｠｠｠`
	case "python":
		return `Example — XSS (Python/Flask):
VULNERABLE:
｠｠｠python
return f"<div>{user_input}</div>"
｠｠｠
SECURE:
｠｠｠python
from markupsafe import Markup
return Markup.escape(user_input)  # Or use Jinja2 autoescape
｠｠｠`
	default:
		return `Example — XSS fix pattern:
Use context-appropriate encoding: htmlspecialchars() in PHP, textContent in JS, autoescape in templates.
Never insert untrusted data directly into HTML without encoding.`
	}
}

func fewShotCommandInjection(lang string) string {
	switch lang {
	case "go":
		return `Example — Command Injection (Go):
VULNERABLE:
｠｠｠go
cmd := exec.Command("sh", "-c", "ping "+userInput)
｠｠｠
SECURE:
｠｠｠go
cmd := exec.Command("ping", userInput)  // Pass as argument, not shell string
｠｠｠`
	case "python":
		return `Example — Command Injection (Python):
VULNERABLE:
｠｠｠python
os.system("ls " + user_input)
｠｠｠
SECURE:
｠｠｠python
import subprocess
subprocess.run(["ls", user_input], capture_output=True)
｠｠｠`
	case "php":
		return `Example — Command Injection (PHP):
VULNERABLE:
｠｠｠php
system("ping " . $_GET['host']);
｠｠｠
SECURE:
｠｠｠php
exec("ping", [$_GET['host']]);  // Use array form, not string concatenation
｠｠｠`
	default:
		return `Example — Command Injection fix pattern:
Use library functions that accept arguments as arrays (exec.Command in Go, subprocess.run in Python).
Avoid shell=True and string concatenation with user input.`
	}
}

func fewShotPathTraversal(lang string) string {
	switch lang {
	case "go":
		return `Example — Path Traversal (Go):
VULNERABLE:
｠｠｠go
content, err := os.ReadFile("/data/" + filename)
｠｠｠
SECURE:
｠｠｠go
cleanPath := filepath.Clean(filename)
if strings.Contains(cleanPath, "..") {
    return errors.New("invalid path")
}
content, err := os.ReadFile(filepath.Join("/data", cleanPath))
｠｠｠`
	case "python":
		return `Example — Path Traversal (Python):
VULNERABLE:
｠｠｠python
with open(f"/data/{filename}") as f:
    return f.read()
｠｠｠
SECURE:
｠｠｠python
from pathlib import Path
safe_path = Path("/data") / Path(filename).name
if not safe_path.resolve().is_relative_to(Path("/data").resolve()):
    raise ValueError("invalid path")
with open(safe_path) as f:
    return f.read()
｠｠｠`
	default:
		return `Example — Path Traversal fix pattern:
Sanitize paths: reject "..", use filepath.Clean/Path.resolve(), validate the resolved path is within allowed directory.`
	}
}

func fewShotSecrets(lang string) string {
	return `Example — Hardcoded Secrets:
VULNERABLE:
｠｠｠python
API_KEY = "sk-abc123xyz789"
｠｠｠
SECURE:
｠｠｠python
import os
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")
｠｠｠

ALWAYS load secrets from environment variables, secret managers (AWS Secrets Manager, Vault), or encrypted config files.
NEVER commit secrets to version control.`
}

func fewShotSSRF(lang string) string {
	return `Example — SSRF fix pattern:
VULNERABLE:
｠｠｠python
import requests
requests.get(user_provided_url)
｠｠｠
SECURE:
｠｠｠python
from urllib.parse import urlparse
allowed_hosts = {"api.example.com", "cdn.example.com"}
parsed = urlparse(user_provided_url)
if parsed.hostname not in allowed_hosts:
    raise ValueError("URL not allowed")
requests.get(user_provided_url, timeout=5)
｠｠｠

Validate URLs against an allowlist of hosts. Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8).`
}

func fewShotCrypto(lang string) string {
	return `Example — Weak Cryptography:
VULNERABLE:
｠｠｠python
import hashlib
hashlib.md5(password).hexdigest()
｠｠｠
SECURE:
｠｠｠python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
｠｠｠

Use strong algorithms: bcrypt/Argon2 for passwords, AES-256-GCM for encryption, SHA-256+ for hashing, os.urandom for randomness.
Avoid: MD5, SHA1, DES, ECB mode, Math.random() for crypto.`
}

func fewShotDeserialization(lang string) string {
	return `Example — Insecure Deserialization:
VULNERABLE:
｠｠｠python
import pickle
data = pickle.loads(user_input)
｠｠｠
SECURE:
｠｠｠python
import json
data = json.loads(user_input)  # Use JSON instead of pickle
｠｠｠

Never deserialize untrusted data with pickle, yaml.load(unsafe), ObjectInputStream (Java), unserialize() (PHP).
Use safe formats: JSON, protobuf, MessagePack with schema validation.`
}

func fewShotAccessControl(lang string) string {
	return `Example — Broken Access Control:
VULNERABLE:
｠｠｠javascript
app.get('/api/user/:id', (req, res) => {
    db.getUser(req.params.id).then(user => res.json(user))
})
｠｠｠
SECURE:
｠｠｠javascript
app.get('/api/user/:id', authMiddleware, (req, res) => {
    if (req.user.id !== req.params.id && !req.user.isAdmin) {
        return res.status(403).json({error: "Forbidden"})
    }
    db.getUser(req.params.id).then(user => res.json(user))
})
｠｠｠

Always verify the authenticated user has permission to access the requested resource. Use authorization middleware.`
}

func fewShotGeneric(lang string) string {
	return `General security fix principles:
1. Validate all user input (whitelist approach)
2. Use parameterized APIs instead of string concatenation
3. Apply context-appropriate encoding (HTML, SQL, URL, JS)
4. Never trust client-side data
5. Use principle of least privilege
6. Keep security libraries updated`
}
