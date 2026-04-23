package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// anthropicProvider implements Provider for Anthropic (Claude) API
type anthropicProvider struct {
	config ProviderConfig
}

func newAnthropicProvider(cfg ProviderConfig) *anthropicProvider {
	return &anthropicProvider{config: cfg}
}

func (p *anthropicProvider) Name() string {
	return p.config.Name
}

func (p *anthropicProvider) SupportsStreaming() bool {
	return false
}

func (p *anthropicProvider) GenerateFix(req FixRequest) (*FixResponse, error) {
	if p.config.APIKey == "" {
		return nil, fmt.Errorf("anthropic: no API key configured. Set ANTHROPIC_API_KEY")
	}

	body := map[string]interface{}{
		"model":      p.config.Model,
		"max_tokens": p.config.MaxTokens,
		"temperature": p.config.Temperature,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": buildFixPrompt(req)},
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", p.config.BaseURL+"/v1/messages", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Api-Key", p.config.APIKey)
	httpReq.Header.Set("Anthropic-Version", "2023-06-01")

	client := &http.Client{Timeout: p.config.Timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if resp.StatusCode == 429 {
			return nil, fmt.Errorf("anthropic: rate limited (429). Wait and retry.")
		}
		return nil, fmt.Errorf("anthropic API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
		Error *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing anthropic response: %w", err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("anthropic API error: %s", result.Error.Message)
	}

	var content string
	for _, c := range result.Content {
		if c.Type == "text" {
			content = c.Text
			break
		}
	}

	if content == "" {
		return nil, fmt.Errorf("no text response from anthropic")
	}

	totalTokens := result.Usage.InputTokens + result.Usage.OutputTokens
	return parseFixResponse(content, totalTokens), nil
}
