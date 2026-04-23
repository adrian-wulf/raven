package llm

import (
	"fmt"
)

// Client is the high-level LLM client with caching, batching, and streaming
type Client struct {
	provider Provider
	cache    *AICache
}

// NewClient creates a new LLM client from environment/config.
// It auto-detects available providers based on environment variables.
//
// Supported environment variables:
//   - RAVEN_LLM_PROVIDER: preferred provider name
//   - RAVEN_LLM_API_KEY: generic API key fallback
//   - RAVEN_LLM_BASE_URL: custom base URL
//   - RAVEN_LLM_MODEL: model override
//
// Provider-specific keys (detected automatically):
//   - OPENROUTER_API_KEY, NVIDIA_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY,
//   - GROQ_API_KEY, DEEPSEEK_API_KEY, TOGETHER_API_KEY,
//   - GEMINI_API_KEY, OLLAMA_HOST, AZURE_OPENAI_API_KEY
func NewClient() *Client {
	registry := NewRegistry()
	provider, err := registry.Default()
	if err != nil {
		return &Client{provider: &unconfiguredProvider{err: err}}
	}
	return &Client{
		provider: provider,
		cache:    NewAICache(),
	}
}

// NewClientWithProvider creates a client with a specific provider
func NewClientWithProvider(name string) (*Client, error) {
	registry := NewRegistry()
	provider, err := registry.Get(name)
	if err != nil {
		return nil, err
	}
	return &Client{
		provider: provider,
		cache:    NewAICache(),
	}, nil
}

// AvailableProviders returns the names of all detected providers
func AvailableProviders() []string {
	return NewRegistry().Names()
}

// GenerateFix sends code to the LLM and returns a secure replacement.
// Uses cache if available to avoid redundant API calls.
func (c *Client) GenerateFix(req FixRequest) (*FixResponse, error) {
	return c.generateFixInternal(req, true)
}

// GenerateFixNoCache bypasses the cache and always calls the API
func (c *Client) GenerateFixNoCache(req FixRequest) (*FixResponse, error) {
	return c.generateFixInternal(req, false)
}

func (c *Client) generateFixInternal(req FixRequest, useCache bool) (*FixResponse, error) {
	if c.provider == nil {
		return nil, fmt.Errorf("no LLM provider configured. See: https://github.com/adrian-wulf/raven#-llm-configuration")
	}

	// Check cache first
	if useCache && c.cache != nil {
		model := c.getModel()
		if cached, ok := c.cache.Get(req.Code, req.VulnType, req.Language, model, c.ProviderName()); ok {
			return cached, nil
		}
	}

	resp, err := c.provider.GenerateFix(req)
	if err != nil {
		return nil, err
	}

	// Store in cache
	if useCache && c.cache != nil {
		c.cache.Set(req.Code, req.VulnType, req.Language, c.getModel(), c.ProviderName(), resp)
		_ = c.cache.Save() // Best-effort save
	}

	return resp, nil
}

// GenerateFixStream sends a streaming request and returns chunks via channel.
// Useful for showing live AI output to the user.
func (c *Client) GenerateFixStream(req FixRequest, out chan<- StreamChunk) error {
	if c.provider == nil {
		return fmt.Errorf("no LLM provider configured")
	}

	// Check if provider supports streaming
	if sp, ok := c.provider.(StreamProvider); ok {
		return sp.GenerateFixStream(req, out)
	}

	// Fallback: use regular GenerateFix and emit as single chunk
	resp, err := c.GenerateFix(req)
	if err != nil {
		out <- StreamChunk{Error: err, Done: true}
		return err
	}

	out <- StreamChunk{Content: resp.FixedCode + "\n\n" + resp.Explanation, Done: false}
	out <- StreamChunk{Done: true}
	return nil
}

// BatchGenerateFix sends multiple vulnerabilities in a single API call.
// Groups findings by rule ID for efficiency. Falls back to sequential calls
// if the provider doesn't support batching.
func (c *Client) BatchGenerateFix(req BatchFixRequest) (*BatchFixResponse, error) {
	if c.provider == nil {
		return nil, fmt.Errorf("no LLM provider configured")
	}

	// Try provider's native batch support
	if bp, ok := c.provider.(BatchProvider); ok {
		return bp.BatchGenerateFix(req)
	}

	// Fallback: sequential calls with cache
	var fixes []BatchFixResult
	for _, item := range req.Items {
		fixReq := FixRequest{
			Code:        item.Code,
			Language:    req.Language,
			VulnType:    item.VulnType,
			Description: item.Description,
			Message:     item.Message,
		}

		resp, err := c.GenerateFix(fixReq)
		if err != nil {
			fixes = append(fixes, BatchFixResult{
				ID:          item.ID,
				FixedCode:   "",
				Explanation: fmt.Sprintf("Error: %v", err),
				Confidence:  0,
			})
			continue
		}
		fixes = append(fixes, BatchFixResult{
			ID:          item.ID,
			FixedCode:   resp.FixedCode,
			Explanation: resp.Explanation,
			Confidence:  resp.Confidence,
		})
	}

	return &BatchFixResponse{Fixes: fixes}, nil
}

// CacheStats returns cache hit/miss statistics
func (c *Client) CacheStats() (total, valid int) {
	if c.cache == nil {
		return 0, 0
	}
	return c.cache.Stats()
}

// SaveCache persists the AI fix cache to disk
func (c *Client) SaveCache() error {
	if c.cache == nil {
		return nil
	}
	return c.cache.Save()
}

// ProviderName returns the name of the currently active provider
func (c *Client) ProviderName() string {
	if c.provider == nil {
		return "none"
	}
	return c.provider.Name()
}

func (c *Client) getModel() string {
	// Try to extract model from provider config
	// This is a best-effort for cache key generation
	switch p := c.provider.(type) {
	case *openAIProvider:
		return p.config.Model
	case *anthropicProvider:
		return p.config.Model
	case *googleProvider:
		return p.config.Model
	case *ollamaProvider:
		return p.config.Model
	case *azureProvider:
		return p.config.Model
	default:
		return "unknown"
	}
}

// unconfiguredProvider is a placeholder that returns a helpful error
type unconfiguredProvider struct {
	err error
}

func (p *unconfiguredProvider) Name() string                { return "unconfigured" }
func (p *unconfiguredProvider) SupportsStreaming() bool     { return false }
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
