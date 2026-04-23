package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// googleProvider implements Provider for Google Gemini API
type googleProvider struct {
	config ProviderConfig
}

func newGoogleProvider(cfg ProviderConfig) *googleProvider {
	return &googleProvider{config: cfg}
}

func (p *googleProvider) Name() string {
	return p.config.Name
}

func (p *googleProvider) SupportsStreaming() bool {
	return false
}

func (p *googleProvider) GenerateFix(req FixRequest) (*FixResponse, error) {
	if p.config.APIKey == "" {
		return nil, fmt.Errorf("gemini: no API key configured. Set GEMINI_API_KEY")
	}

	body := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": systemPrompt + "\n\n" + buildFixPrompt(req)},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"maxOutputTokens": p.config.MaxTokens,
			"temperature":     p.config.Temperature,
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s",
		p.config.BaseURL, p.config.Model, p.config.APIKey)

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: p.config.Timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if resp.StatusCode == 429 {
			return nil, fmt.Errorf("gemini: rate limited (429). Wait and retry.")
		}
		return nil, fmt.Errorf("gemini API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		UsageMetadata struct {
			TotalTokenCount int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
		Error *struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error,omitempty"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing gemini response: %w", err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("gemini API error: %s", result.Error.Message)
	}

	var content string
	if len(result.Candidates) > 0 && len(result.Candidates[0].Content.Parts) > 0 {
		content = result.Candidates[0].Content.Parts[0].Text
	}

	if content == "" {
		return nil, fmt.Errorf("no response from gemini")
	}

	return parseFixResponse(content, result.UsageMetadata.TotalTokenCount), nil
}
