package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// BatchFixRequest groups multiple findings for a single API call
type BatchFixRequest struct {
	Language string
	Items    []BatchFixItem
}

type BatchFixItem struct {
	ID          int    `json:"id"`
	Code        string `json:"code"`
	VulnType    string `json:"vuln_type"`
	Description string `json:"description"`
	Message     string `json:"message"`
}

// BatchFixResponse contains fixes for all items
type BatchFixResponse struct {
	Fixes []BatchFixResult `json:"fixes"`
}

type BatchFixResult struct {
	ID          int     `json:"id"`
	FixedCode   string  `json:"fixed_code"`
	Explanation string  `json:"explanation"`
	Confidence  float64 `json:"confidence"`
}

// BatchProvider is an optional interface for providers that support batching
type BatchProvider interface {
	BatchGenerateFix(req BatchFixRequest) (*BatchFixResponse, error)
}

// --- OpenAI batch implementation ---

func (p *openAIProvider) BatchGenerateFix(req BatchFixRequest) (*BatchFixResponse, error) {
	if p.config.APIKey == "" && p.config.Name != "ollama" {
		return nil, fmt.Errorf("%s: no API key configured", p.config.Name)
	}

	prompt := buildBatchPrompt(req)

	body := map[string]interface{}{
		"model": p.config.Model,
		"messages": []map[string]string{
			{"role": "system", "content": batchSystemPrompt},
			{"role": "user", "content": prompt},
		},
		"max_tokens":  p.config.MaxTokens * len(req.Items),
		"temperature": p.config.Temperature,
		"response_format": map[string]string{"type": "json_object"},
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
		if resp.StatusCode == 429 {
			return nil, fmt.Errorf("%s: rate limited (429)", p.config.Name)
		}
		return nil, fmt.Errorf("%s API error (%d): %s", p.config.Name, resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error,omitempty"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing %s response: %w", p.config.Name, err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("%s API error: %s", p.config.Name, result.Error.Message)
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response from %s", p.config.Name)
	}

	content := result.Choices[0].Message.Content
	return parseBatchResponse(content)
}

const batchSystemPrompt = `You are an expert security engineer. Fix multiple vulnerabilities in the provided code snippets.

Rules:
1. Fix each vulnerability independently
2. Only change what's necessary to fix the vulnerability
3. Keep the original code style
4. Return your response as a JSON object with this exact structure:

{
  "fixes": [
    {
      "id": 1,
      "fixed_code": "the fixed code snippet",
      "explanation": "why this fix is secure",
      "confidence": 0.95
    }
  ]
}

The "id" must match the input ID exactly. "confidence" is a number 0.0-1.0.`

func buildBatchPrompt(req BatchFixRequest) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Fix the following %d security vulnerabilities in %s code.\n\n",
		len(req.Items), req.Language))

	for _, item := range req.Items {
		sb.WriteString(fmt.Sprintf("--- VULNERABILITY %d ---\n", item.ID))
		sb.WriteString(fmt.Sprintf("Type: %s\n", item.VulnType))
		sb.WriteString(fmt.Sprintf("Description: %s\n", item.Description))
		sb.WriteString(fmt.Sprintf("Code:\n｠｠｠%s\n%s\n｠｠｠\n\n",
			req.Language, item.Code))
	}

	sb.WriteString("Return the fixes as JSON with the exact structure specified in your instructions.")
	return sb.String()
}

func parseBatchResponse(content string) (*BatchFixResponse, error) {
	// Try to extract JSON from markdown fences
	cleanContent := content
	if start := strings.Index(content, "```json"); start != -1 {
		start += 7
		if nl := strings.Index(content[start:], "\n"); nl != -1 {
			start += nl + 1
		}
		if end := strings.Index(content[start:], "```"); end != -1 {
			cleanContent = content[start : start+end]
		}
	} else if start := strings.Index(content, "{"); start != -1 {
		if end := strings.LastIndex(content, "}"); end != -1 && end > start {
			cleanContent = content[start : end+1]
		}
	}

	cleanContent = strings.TrimSpace(cleanContent)

	var result BatchFixResponse
	if err := json.Unmarshal([]byte(cleanContent), &result); err != nil {
		return nil, fmt.Errorf("parsing batch response JSON: %w. Raw content: %s", err, truncate(content, 200))
	}

	return &result, nil
}

// Utility
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
