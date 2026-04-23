package llm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// StreamChunk represents a piece of streaming response
type StreamChunk struct {
	Content string
	Done    bool
	Error   error
}

// StreamProvider is an optional interface for providers that support streaming
type StreamProvider interface {
	GenerateFixStream(req FixRequest, out chan<- StreamChunk) error
}

// openAIProvider streaming implementation
func (p *openAIProvider) GenerateFixStream(req FixRequest, out chan<- StreamChunk) error {
	if p.config.APIKey == "" && p.config.Name != "ollama" {
		return fmt.Errorf("%s: no API key configured", p.config.Name)
	}

	body := map[string]interface{}{
		"model": p.config.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": buildFixPrompt(req)},
		},
		"max_tokens":  p.config.MaxTokens,
		"temperature": p.config.Temperature,
		"stream":      true,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequest("POST", p.config.BaseURL+"/chat/completions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
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
		return fmt.Errorf("%s API request failed: %w", p.config.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s API error (%d): %s", p.config.Name, resp.StatusCode, string(bodyBytes))
	}

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				out <- StreamChunk{Done: true}
				return nil
			}
			out <- StreamChunk{Error: err, Done: true}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "data: [DONE]" {
			out <- StreamChunk{Done: true}
			return nil
		}

		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error,omitempty"`
		}

		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue // Skip malformed chunks
		}

		if chunk.Error != nil {
			out <- StreamChunk{Error: fmt.Errorf("stream error: %s", chunk.Error.Message), Done: true}
			return nil
		}

		if len(chunk.Choices) > 0 {
			if chunk.Choices[0].FinishReason != "" {
				out <- StreamChunk{Done: true}
				return nil
			}
			if content := chunk.Choices[0].Delta.Content; content != "" {
				out <- StreamChunk{Content: content, Done: false}
			}
		}
	}
}

// anthropicProvider streaming implementation
func (p *anthropicProvider) GenerateFixStream(req FixRequest, out chan<- StreamChunk) error {
	if p.config.APIKey == "" {
		return fmt.Errorf("anthropic: no API key configured")
	}

	body := map[string]interface{}{
		"model":      p.config.Model,
		"max_tokens": p.config.MaxTokens,
		"temperature": p.config.Temperature,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": buildFixPrompt(req)},
		},
		"stream": true,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequest("POST", p.config.BaseURL+"/v1/messages", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Api-Key", p.config.APIKey)
	httpReq.Header.Set("Anthropic-Version", "2023-06-01")

	client := &http.Client{Timeout: p.config.Timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("anthropic stream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("anthropic API error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				out <- StreamChunk{Done: true}
				return nil
			}
			out <- StreamChunk{Error: err, Done: true}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		var event struct {
			Type string `json:"type"`
			Delta *struct {
				Text string `json:"text"`
			} `json:"delta,omitempty"`
		}

		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}

		if event.Type == "content_block_delta" && event.Delta != nil {
			out <- StreamChunk{Content: event.Delta.Text, Done: false}
		}
		if event.Type == "message_stop" {
			out <- StreamChunk{Done: true}
			return nil
		}
	}
}
