package llm

import (
	"fmt"
)

// Client is the high-level LLM client that auto-detects and uses available providers
type Client struct {
	provider Provider
}

// NewClient creates a new LLM client from environment/config.
// It auto-detects available providers based on environment variables.
//
// Supported environment variables:
//   - RAVEN_LLM_PROVIDER: preferred provider name (openrouter, nvidia, openai, anthropic, groq, deepseek, together, gemini, ollama, azure)
//   - RAVEN_LLM_API_KEY: generic API key fallback
//   - RAVEN_LLM_BASE_URL: custom base URL
//   - RAVEN_LLM_MODEL: model override
//
// Provider-specific keys (detected automatically):
//   - OPENROUTER_API_KEY / OPENROUTER_BASE_URL
//   - NVIDIA_API_KEY / NVCF_API_KEY / NVIDIA_BASE_URL (free tier: 40 req/min!)
//   - OPENAI_API_KEY / OPENAI_BASE_URL
//   - ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL
//   - GROQ_API_KEY / GROQ_BASE_URL
//   - DEEPSEEK_API_KEY / DEEPSEEK_BASE_URL
//   - TOGETHER_API_KEY / TOGETHER_BASE_URL
//   - GEMINI_API_KEY / GOOGLE_API_KEY / GEMINI_BASE_URL
//   - OLLAMA_HOST / OLLAMA_MODEL (local, no API key needed)
//   - AZURE_OPENAI_API_KEY / AZURE_OPENAI_ENDPOINT
func NewClient() *Client {
	registry := NewRegistry()
	provider, err := registry.Default()
	if err != nil {
		// Return a client that will fail gracefully with a helpful message
		return &Client{provider: &unconfiguredProvider{err: err}}
	}
	return &Client{provider: provider}
}

// NewClientWithProvider creates a client with a specific provider
func NewClientWithProvider(name string) (*Client, error) {
	registry := NewRegistry()
	provider, err := registry.Get(name)
	if err != nil {
		return nil, err
	}
	return &Client{provider: provider}, nil
}

// AvailableProviders returns the names of all detected providers
func AvailableProviders() []string {
	return NewRegistry().Names()
}

// GenerateFix sends code to the LLM and returns a secure replacement
func (c *Client) GenerateFix(req FixRequest) (*FixResponse, error) {
	if c.provider == nil {
		return nil, fmt.Errorf("no LLM provider configured. See: https://github.com/adrian-wulf/raven#-llm-configuration")
	}
	return c.provider.GenerateFix(req)
}

// ProviderName returns the name of the currently active provider
func (c *Client) ProviderName() string {
	if c.provider == nil {
		return "none"
	}
	return c.provider.Name()
}

// unconfiguredProvider is a placeholder that returns a helpful error
type unconfiguredProvider struct {
	err error
}

func (p *unconfiguredProvider) Name() string { return "unconfigured" }
func (p *unconfiguredProvider) SupportsStreaming() bool { return false }
func (p *unconfiguredProvider) GenerateFix(req FixRequest) (*FixResponse, error) {
	return nil, p.err
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
	FixedCode   string  `json:"fixed_code"`
	Explanation string  `json:"explanation"`
	Confidence  float64 `json:"confidence"`
}
