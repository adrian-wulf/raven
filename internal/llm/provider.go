package llm

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Provider is the interface for LLM API providers
type Provider interface {
	Name() string
	GenerateFix(req FixRequest) (*FixResponse, error)
	SupportsStreaming() bool
}

// ProviderConfig holds configuration for creating a provider
type ProviderConfig struct {
	Name        string
	BaseURL     string
	APIKey      string
	Model       string
	MaxTokens   int
	Temperature float64
	Timeout     time.Duration
}

// Registry holds all available providers
type Registry struct {
	providers map[string]Provider
}

// NewRegistry creates a provider registry with auto-detected providers
func NewRegistry() *Registry {
	r := &Registry{providers: make(map[string]Provider)}
	r.autoDetect()
	return r
}

// Register adds a provider to the registry
func (r *Registry) Register(name string, p Provider) {
	r.providers[strings.ToLower(name)] = p
}

// Get returns a provider by name
func (r *Registry) Get(name string) (Provider, error) {
	p, ok := r.providers[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown LLM provider: %q. Available: %s", name, strings.Join(r.Names(), ", "))
	}
	return p, nil
}

// Names returns all registered provider names
func (r *Registry) Names() []string {
	var names []string
	for n := range r.providers {
		names = append(names, n)
	}
	return names
}

// Default returns the first available provider, or error if none
func (r *Registry) Default() (Provider, error) {
	// Priority order: user-configured > env-detected
	preferred := []string{
		os.Getenv("RAVEN_LLM_PROVIDER"),
	}
	for _, name := range preferred {
		if name != "" {
			if p, ok := r.providers[strings.ToLower(name)]; ok {
				return p, nil
			}
		}
	}
	// Return first available
	for _, p := range r.providers {
		return p, nil
	}
	return nil, fmt.Errorf("no LLM provider configured. Set one of: OPENAI_API_KEY, OPENROUTER_API_KEY, ANTHROPIC_API_KEY, NVIDIA_API_KEY, GROQ_API_KEY, DEEPSEEK_API_KEY, TOGETHER_API_KEY, GEMINI_API_KEY, or OLLAMA_HOST")
}

// autoDetect registers providers based on environment variables
func (r *Registry) autoDetect() {
	// OpenRouter
	if key := coalesceEnv("OPENROUTER_API_KEY", "RAVEN_LLM_API_KEY"); key != "" {
		baseURL := getEnv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
		model := getEnv("OPENROUTER_MODEL", "deepseek/deepseek-chat")
		r.Register("openrouter", newOpenAIProvider(ProviderConfig{
			Name:        "openrouter",
			BaseURL:     baseURL,
			APIKey:      key,
			Model:       model,
			MaxTokens:   2048,
			Temperature: 0.1,
			Timeout:     60 * time.Second,
		}))
	}

	// NVIDIA NIM (free tier: 40 req/min!)
	if key := coalesceEnv("NVIDIA_API_KEY", "NVCF_API_KEY", "RAVEN_LLM_API_KEY"); key != "" && isNVIDIAConfigured() {
		baseURL := getEnv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
		model := getEnv("NVIDIA_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct")
		r.Register("nvidia", newOpenAIProvider(ProviderConfig{
			Name:        "nvidia",
			BaseURL:     baseURL,
			APIKey:      key,
			Model:       model,
			MaxTokens:   2048,
			Temperature: 0.1,
			Timeout:     60 * time.Second,
		}))
	}

	// OpenAI
	if key := coalesceEnv("OPENAI_API_KEY", "RAVEN_LLM_API_KEY"); key != "" && isOpenAIConfigured() {
		baseURL := getEnv("OPENAI_BASE_URL", "https://api.openai.com/v1")
		model := getEnv("OPENAI_MODEL", "gpt-4o-mini")
		r.Register("openai", newOpenAIProvider(ProviderConfig{
			Name:        "openai",
			BaseURL:     baseURL,
			APIKey:      key,
			Model:       model,
			MaxTokens:   2048,
			Temperature: 0.1,
			Timeout:     60 * time.Second,
		}))
	}

	// Anthropic (Claude)
	if key := coalesceEnv("ANTHROPIC_API_KEY", "RAVEN_LLM_API_KEY"); key != "" && isAnthropicConfigured() {
		baseURL := getEnv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
		model := getEnv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
		r.Register("anthropic", newAnthropicProvider(ProviderConfig{
			Name:        "anthropic",
			BaseURL:     baseURL,
			APIKey:      key,
			Model:       model,
			MaxTokens:   4096,
			Temperature: 0.1,
			Timeout:     60 * time.Second,
		}))
	}

	// Groq (very fast, cheap)
	if key := coalesceEnv("GROQ_API_KEY", "RAVEN_LLM_API_KEY"); key != "" && isGroqConfigured() {
		baseURL := getEnv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
		model := getEnv("GROQ_MODEL", "llama-3.3-70b-versatile")
		r.Register("groq", newOpenAIProvider(ProviderConfig{
			Name:        "groq",
			BaseURL:     baseURL,
			APIKey:      key,
			Model:       model,
			MaxTokens:   2048,
			Temperature: 0.1,
			Timeout:     30 * time.Second,
		}))
	}

	// DeepSeek
	if key := coalesceEnv("DEEPSEEK_API_KEY", "RAVEN_LLM_API_KEY"); key != "" && isDeepSeekConfigured() {
		baseURL := getEnv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
		model := getEnv("DEEPSEEK_MODEL", "deepseek-chat")
		r.Register("deepseek", newOpenAIProvider(ProviderConfig{
			Name:        "deepseek",
			BaseURL:     baseURL,
			APIKey:      key,
			Model:       model,
			MaxTokens:   2048,
			Temperature: 0.1,
			Timeout:     60 * time.Second,
		}))
	}

	// Together.ai
	if key := coalesceEnv("TOGETHER_API_KEY", "RAVEN_LLM_API_KEY"); key != "" && isTogetherConfigured() {
		baseURL := getEnv("TOGETHER_BASE_URL", "https://api.together.xyz/v1")
		model := getEnv("TOGETHER_MODEL", "meta-llama/Llama-3.3-70B-Instruct-Turbo")
		r.Register("together", newOpenAIProvider(ProviderConfig{
			Name:        "together",
			BaseURL:     baseURL,
			APIKey:      key,
			Model:       model,
			MaxTokens:   2048,
			Temperature: 0.1,
			Timeout:     60 * time.Second,
		}))
	}

	// Google Gemini
	if key := coalesceEnv("GEMINI_API_KEY", "GOOGLE_API_KEY", "RAVEN_LLM_API_KEY"); key != "" && isGeminiConfigured() {
		baseURL := getEnv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com")
		model := getEnv("GEMINI_MODEL", "gemini-1.5-flash")
		r.Register("gemini", newGoogleProvider(ProviderConfig{
			Name:        "gemini",
			BaseURL:     baseURL,
			APIKey:      key,
			Model:       model,
			MaxTokens:   2048,
			Temperature: 0.1,
			Timeout:     60 * time.Second,
		}))
	}

	// Ollama (local)
	if host := getEnv("OLLAMA_HOST", ""); host != "" || ollamaDefaultAvailable() {
		baseURL := getEnv("OLLAMA_HOST", "http://localhost:11434")
		model := getEnv("OLLAMA_MODEL", "codellama")
		r.Register("ollama", newOllamaProvider(ProviderConfig{
			Name:        "ollama",
			BaseURL:     baseURL,
			APIKey:      "", // Ollama doesn't need API key
			Model:       model,
			MaxTokens:   2048,
			Temperature: 0.1,
			Timeout:     120 * time.Second,
		}))
	}

	// Azure OpenAI
	if key := coalesceEnv("AZURE_OPENAI_API_KEY", "RAVEN_LLM_API_KEY"); key != "" && isAzureConfigured() {
		baseURL := getEnv("AZURE_OPENAI_ENDPOINT", "")
		model := getEnv("AZURE_OPENAI_MODEL", "gpt-4o")
		r.Register("azure", newAzureProvider(ProviderConfig{
			Name:        "azure",
			BaseURL:     baseURL,
			APIKey:      key,
			Model:       model,
			MaxTokens:   2048,
			Temperature: 0.1,
			Timeout:     60 * time.Second,
		}))
	}
}

// --- Detection helpers ---

func isNVIDIAConfigured() bool {
	return getEnv("NVIDIA_API_KEY", "") != "" ||
		getEnv("NVCF_API_KEY", "") != "" ||
		strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "nvidia") ||
		strings.Contains(getEnv("RAVEN_LLM_MODEL", ""), "nvidia")
}

func isOpenAIConfigured() bool {
	return getEnv("OPENAI_API_KEY", "") != "" ||
		(!strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "openrouter") &&
			!strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "groq") &&
			!strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "nvidia") &&
			!strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "deepseek") &&
			!strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "together") &&
			getEnv("RAVEN_LLM_BASE_URL", "") != "")
}

func isAnthropicConfigured() bool {
	return getEnv("ANTHROPIC_API_KEY", "") != "" ||
		strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "anthropic")
}

func isGroqConfigured() bool {
	return getEnv("GROQ_API_KEY", "") != "" ||
		strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "groq")
}

func isDeepSeekConfigured() bool {
	return getEnv("DEEPSEEK_API_KEY", "") != "" ||
		strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "deepseek")
}

func isTogetherConfigured() bool {
	return getEnv("TOGETHER_API_KEY", "") != "" ||
		strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "together")
}

func isGeminiConfigured() bool {
	return getEnv("GEMINI_API_KEY", "") != "" ||
		getEnv("GOOGLE_API_KEY", "") != "" ||
		strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "google") ||
		strings.Contains(getEnv("RAVEN_LLM_MODEL", ""), "gemini")
}

func isAzureConfigured() bool {
	return getEnv("AZURE_OPENAI_ENDPOINT", "") != "" ||
		strings.Contains(getEnv("RAVEN_LLM_BASE_URL", ""), "azure")
}

func ollamaDefaultAvailable() bool {
	// We don't actually check here; user must set OLLAMA_HOST explicitly
	// or we'll try localhost when explicitly requested
	return false
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func coalesceEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
