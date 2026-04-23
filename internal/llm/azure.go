package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// azureProvider implements Provider for Azure OpenAI
type azureProvider struct {
	config ProviderConfig
}

func newAzureProvider(cfg ProviderConfig) *azureProvider {
	return &azureProvider{config: cfg}
}

func (p *azureProvider) Name() string {
	return p.config.Name
}

func (p *azureProvider) SupportsStreaming() bool {
	return false
}

func (p *azureProvider) GenerateFix(req FixRequest) (*FixResponse, error) {
	if p.config.APIKey == "" {
		return nil, fmt.Errorf("azure: no API key configured. Set AZURE_OPENAI_API_KEY")
	}
	if p.config.BaseURL == "" {
		return nil, fmt.Errorf("azure: no endpoint configured. Set AZURE_OPENAI_ENDPOINT")
	}

	body := map[string]interface{}{
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

	// Azure endpoint format: {endpoint}/openai/deployments/{deployment}/chat/completions?api-version=...
	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=2024-02-01",
		p.config.BaseURL, p.config.Model)

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("api-key", p.config.APIKey)

	client := &http.Client{Timeout: p.config.Timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("azure API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if resp.StatusCode == 429 {
			return nil, fmt.Errorf("azure: rate limited (429). Check your quota.")
		}
		return nil, fmt.Errorf("azure API error (%d): %s", resp.StatusCode, string(respBody))
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
		return nil, fmt.Errorf("parsing azure response: %w", err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("azure API error: %s (code: %s)", result.Error.Message, result.Error.Code)
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response from azure")
	}

	content := result.Choices[0].Message.Content
	return parseFixResponse(content, result.Usage.TotalTokens), nil
}
