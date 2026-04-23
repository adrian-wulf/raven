package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ollamaProvider implements Provider for Ollama (local LLM)
type ollamaProvider struct {
	config ProviderConfig
}

func newOllamaProvider(cfg ProviderConfig) *ollamaProvider {
	return &ollamaProvider{config: cfg}
}

func (p *ollamaProvider) Name() string {
	return p.config.Name
}

func (p *ollamaProvider) SupportsStreaming() bool {
	return false
}

func (p *ollamaProvider) GenerateFix(req FixRequest) (*FixResponse, error) {
	body := map[string]interface{}{
		"model": p.config.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": buildFixPrompt(req)},
		},
		"stream": false,
		"options": map[string]interface{}{
			"temperature": p.config.Temperature,
			"num_predict": p.config.MaxTokens,
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := p.config.BaseURL + "/api/chat"
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: p.config.Timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed (is ollama running at %s?): %w", p.config.BaseURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ollama error (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		Done    bool `json:"done"`
		EvalCount int `json:"eval_count"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing ollama response: %w", err)
	}

	if result.Message.Content == "" {
		return nil, fmt.Errorf("no response from ollama (model: %s)", p.config.Model)
	}

	return parseFixResponse(result.Message.Content, result.EvalCount), nil
}
