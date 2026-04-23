package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// openAIProvider implements Provider for any OpenAI-compatible API
type openAIProvider struct {
	config ProviderConfig
}

func newOpenAIProvider(cfg ProviderConfig) *openAIProvider {
	return &openAIProvider{config: cfg}
}

func (p *openAIProvider) Name() string {
	return p.config.Name
}

func (p *openAIProvider) SupportsStreaming() bool {
	return false // Can be enabled later
}

func (p *openAIProvider) GenerateFix(req FixRequest) (*FixResponse, error) {
	if p.config.APIKey == "" && p.config.Name != "ollama" {
		return nil, fmt.Errorf("%s: no API key configured", p.config.Name)
	}

	body := map[string]interface{}{
		"model": p.config.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": buildFixPrompt(req)},
		},
		"max_tokens":  p.config.MaxTokens,
		"temperature": p.config.Temperature,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", p.config.BaseURL+"/chat/completions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if p.config.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	}

	// OpenRouter requires HTTP-Referer
	if p.config.Name == "openrouter" {
		httpReq.Header.Set("HTTP-Referer", "https://github.com/raven-security/raven")
		httpReq.Header.Set("X-Title", "Raven Security Scanner")
	}

	client := &http.Client{Timeout: p.config.Timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s API request failed: %w", p.config.Name, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		// Handle rate limits
		if resp.StatusCode == 429 {
			retryAfter := resp.Header.Get("Retry-After")
			return nil, fmt.Errorf("%s: rate limited (429). Retry after: %s. Consider upgrading or waiting.", p.config.Name, retryAfter)
		}
		return nil, fmt.Errorf("%s API error (%d): %s", p.config.Name, resp.StatusCode, string(respBody))
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
		Error *struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error,omitempty"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing %s response: %w", p.config.Name, err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("%s API error: %s (code: %s)", p.config.Name, result.Error.Message, result.Error.Code)
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response from %s", p.config.Name)
	}

	content := result.Choices[0].Message.Content
	return parseFixResponse(content, result.Usage.TotalTokens), nil
}

// --- Prompts and parsing (shared) ---

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
	fixedCode := extractCodeBlock(content)
	explanation := extractExplanation(content)

	confidence := 0.7
	if strings.Contains(content, "parameterized") || strings.Contains(content, "sanitize") ||
		strings.Contains(content, "escape") || strings.Contains(content, "validate") {
		confidence = 0.9
	}
	if strings.Contains(content, "unsure") || strings.Contains(content, "cannot") ||
		strings.Contains(content, "not possible") {
		confidence = 0.3
	}

	return &FixResponse{
		FixedCode:   fixedCode,
		Explanation: explanation,
		Confidence:  confidence,
	}
}

func extractCodeBlock(content string) string {
	// Try standard markdown fences first
	for _, fence := range []string{"```", "｠｠｠"} {
		start := strings.Index(content, fence)
		if start != -1 {
			// Skip language identifier
			afterFence := content[start+len(fence):]
			if nl := strings.Index(afterFence, "\n"); nl != -1 {
				afterFence = afterFence[nl+1:]
			}
			end := strings.Index(afterFence, fence)
			if end != -1 {
				return strings.TrimSpace(afterFence[:end])
			}
			return strings.TrimSpace(afterFence)
		}
	}
	return content
}

func extractExplanation(content string) string {
	for _, prefix := range []string{"**Explanation:**", "Explanation:", "## Explanation", "### Explanation"} {
		if idx := strings.Index(content, prefix); idx != -1 {
			return strings.TrimSpace(content[idx+len(prefix):])
		}
	}
	return "AI-generated security fix"
}
