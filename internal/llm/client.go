package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Client is a LiteLLM-compatible LLM client
type Client struct {
	BaseURL    string
	APIKey     string
	Model      string
	MaxTokens  int
	Temperature float64
}

// NewClient creates a new LLM client from environment/config
func NewClient() *Client {
	return &Client{
		BaseURL:     getEnv("RAVEN_LLM_BASE_URL", "https://openrouter.ai/api/v1"),
		APIKey:      getEnv("RAVEN_LLM_API_KEY", os.Getenv("OPENROUTER_API_KEY")),
		Model:       getEnv("RAVEN_LLM_MODEL", "deepseek/deepseek-chat"),
		MaxTokens:   2048,
		Temperature: 0.1,
	}
}

// FixRequest represents a request to fix vulnerable code
type FixRequest struct {
	Code        string `json:"code"`
	Language    string `json:"language"`
	VulnType    string `json:"vuln_type"`
	Description string `json:"description"`
	Message     string `json:"message"`
}

// FixResponse represents the AI-generated fix
type FixResponse struct {
	FixedCode   string `json:"fixed_code"`
	Explanation string `json:"explanation"`
	Confidence  float64 `json:"confidence"`
}

// GenerateFix sends code to LLM and returns a secure replacement
func (c *Client) GenerateFix(req FixRequest) (*FixResponse, error) {
	if c.APIKey == "" {
		return nil, fmt.Errorf("no LLM API key configured. Set RAVEN_LLM_API_KEY or OPENROUTER_API_KEY")
	}

	prompt := buildFixPrompt(req)

	body := map[string]interface{}{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
		"max_tokens":  c.MaxTokens,
		"temperature": c.Temperature,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", c.BaseURL+"/chat/completions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	httpReq.Header.Set("HTTP-Referer", "https://github.com/raven-security/raven")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("LLM API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("LLM API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing LLM response: %w", err)
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response from LLM")
	}

	content := result.Choices[0].Message.Content
	return parseFixResponse(content, result.Usage.TotalTokens), nil
}

const systemPrompt = `You are an expert security engineer. Your task is to fix vulnerable code by providing a secure replacement.

Rules:
1. Only change what's necessary to fix the vulnerability
2. Keep the original code style and formatting
3. Add comments explaining the fix
4. If unsure, say so and explain why
5. Return ONLY the fixed code block, wrapped in markdown code fences with the language
6. After the code block, provide a brief explanation

Format your response like this:

｠｠｠language
// fixed code here
｠｠｠

**Explanation:** Brief explanation of the fix and why it's secure.`

func buildFixPrompt(req FixRequest) string {
	return fmt.Sprintf(`Fix this security vulnerability in %s code.

Vulnerability type: %s
Description: %s
Guidance: %s

Code to fix:
｠｠｠%s
%s
｠｠｠

Provide the fixed code.`,
		req.Language,
		req.VulnType,
		req.Description,
		req.Message,
		req.Language,
		req.Code,
	)
}

func parseFixResponse(content string, tokens int) *FixResponse {
	// Extract code block
	fixedCode := extractCodeBlock(content)
	explanation := extractExplanation(content)

	// Simple confidence heuristic
	confidence := 0.7
	if strings.Contains(content, "parameterized") || strings.Contains(content, "sanitize") {
		confidence = 0.9
	}
	if strings.Contains(content, "unsure") || strings.Contains(content, "cannot") {
		confidence = 0.3
	}

	return &FixResponse{
		FixedCode:   fixedCode,
		Explanation: explanation,
		Confidence:  confidence,
	}
}

func extractCodeBlock(content string) string {
	// Find code between ```language and ```
	start := strings.Index(content, "\uff60\uff60\uff60")
	if start == -1 {
		return content
	}
	end := strings.Index(content[start+3:], "\uff60\uff60\uff60")
	if end == -1 {
		return content[start+3:]
	}

	code := content[start+3 : start+3+end]
	// Remove language identifier on first line
	if idx := strings.Index(code, "\n"); idx != -1 {
		code = code[idx+1:]
	}
	return strings.TrimSpace(code)
}

func extractExplanation(content string) string {
	if idx := strings.Index(content, "**Explanation:**"); idx != -1 {
		return strings.TrimSpace(content[idx+16:])
	}
	if idx := strings.Index(content, "Explanation:"); idx != -1 {
		return strings.TrimSpace(content[idx+12:])
	}
	return "AI-generated security fix"
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
