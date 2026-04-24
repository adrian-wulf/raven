package llm

import (
	"os"
	"testing"
)

func TestRegistryAutoDetect(t *testing.T) {
	// Save and restore env
	oldProvider := os.Getenv("RAVEN_LLM_PROVIDER")
	oldOpenAI := os.Getenv("OPENAI_API_KEY")
	oldNVIDIA := os.Getenv("NVIDIA_API_KEY")
	defer func() {
		os.Setenv("RAVEN_LLM_PROVIDER", oldProvider)
		os.Setenv("OPENAI_API_KEY", oldOpenAI)
		os.Setenv("NVIDIA_API_KEY", oldNVIDIA)
	}()

	// Test: no providers configured
	os.Unsetenv("RAVEN_LLM_PROVIDER")
	os.Unsetenv("OPENAI_API_KEY")
	os.Unsetenv("NVIDIA_API_KEY")
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("GROQ_API_KEY")
	os.Unsetenv("DEEPSEEK_API_KEY")
	os.Unsetenv("OPENROUTER_API_KEY")
	os.Unsetenv("RAVEN_LLM_API_KEY")
	os.Unsetenv("RAVEN_LLM_BASE_URL")

	r := NewRegistry()
	if len(r.Names()) > 0 {
		t.Fatalf("Expected no providers with empty env, got: %v", r.Names())
	}

	_, err := r.Default()
	if err == nil {
		t.Fatal("Expected error with no providers")
	}

	// Test: OpenAI detected
	os.Setenv("OPENAI_API_KEY", "test-key")
	r = NewRegistry()
	if !contains(r.Names(), "openai") {
		t.Fatalf("Expected openai provider, got: %v", r.Names())
	}

	p, err := r.Get("openai")
	if err != nil {
		t.Fatalf("Failed to get openai provider: %v", err)
	}
	if p.Name() != "openai" {
		t.Fatalf("Expected name 'openai', got %q", p.Name())
	}

	// Test: NVIDIA detected
	os.Setenv("NVIDIA_API_KEY", "nvidia-test-key")
	r = NewRegistry()
	if !contains(r.Names(), "nvidia") {
		t.Fatalf("Expected nvidia provider, got: %v", r.Names())
	}

	// Test: preferred provider via env
	os.Setenv("RAVEN_LLM_PROVIDER", "nvidia")
	p, err = r.Default()
	if err != nil {
		t.Fatalf("Failed to get default: %v", err)
	}
	if p.Name() != "nvidia" {
		t.Fatalf("Expected nvidia as default, got %q", p.Name())
	}
}

func TestRegistryGetUnknown(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get("nonexistent")
	if err == nil {
		t.Fatal("Expected error for unknown provider")
	}
}

func TestNewClient(t *testing.T) {
	oldKey := os.Getenv("OPENAI_API_KEY")
	os.Setenv("OPENAI_API_KEY", "test-key")
	defer os.Setenv("OPENAI_API_KEY", oldKey)

	client := NewClient()
	if client.ProviderName() != "openai" {
		t.Fatalf("Expected provider 'openai', got %q", client.ProviderName())
	}
}

func TestNewClientUnconfigured(t *testing.T) {
	// Ensure no providers are configured
	for _, key := range []string{
		"OPENAI_API_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY",
		"NVIDIA_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY",
		"TOGETHER_API_KEY", "GEMINI_API_KEY", "OLLAMA_HOST",
		"AZURE_OPENAI_API_KEY", "RAVEN_LLM_API_KEY",
	} {
		os.Unsetenv(key)
	}

	client := NewClient()
	if client.ProviderName() != "unconfigured" {
		t.Fatalf("Expected 'unconfigured', got %q", client.ProviderName())
	}

	_, err := client.GenerateFix(FixRequest{})
	if err == nil {
		t.Fatal("Expected error from unconfigured provider")
	}
}

func TestNewClientWithProvider(t *testing.T) {
	oldKey := os.Getenv("OPENAI_API_KEY")
	os.Setenv("OPENAI_API_KEY", "test-key")
	defer os.Setenv("OPENAI_API_KEY", oldKey)

	client, err := NewClientWithProvider("openai")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	if client.ProviderName() != "openai" {
		t.Fatalf("Expected 'openai', got %q", client.ProviderName())
	}

	_, err = NewClientWithProvider("nonexistent")
	if err == nil {
		t.Fatal("Expected error for unknown provider")
	}
}

func TestAvailableProviders(t *testing.T) {
	oldKey := os.Getenv("GROQ_API_KEY")
	os.Setenv("GROQ_API_KEY", "test-key")
	defer os.Setenv("GROQ_API_KEY", oldKey)

	providers := AvailableProviders()
	if !contains(providers, "groq") {
		t.Fatalf("Expected groq in providers, got: %v", providers)
	}
}

func TestProviderConfigHelpers(t *testing.T) {
	// Test getEnv
	os.Setenv("TEST_VAR_1", "value1")
	if getEnv("TEST_VAR_1", "fallback") != "value1" {
		t.Error("getEnv should return env value")
	}
	if getEnv("TEST_VAR_NONEXISTENT", "fallback") != "fallback" {
		t.Error("getEnv should return fallback")
	}

	// Test coalesceEnv
	os.Setenv("TEST_A", "a")
	os.Unsetenv("TEST_B")
	if coalesceEnv("TEST_B", "TEST_A") != "a" {
		t.Error("coalesceEnv should return first existing")
	}
	if coalesceEnv("TEST_NON_A", "TEST_NON_B") != "" {
		t.Error("coalesceEnv should return empty if none exist")
	}
}

func TestIsProviderConfigured(t *testing.T) {
	// NVIDIA
	os.Unsetenv("NVIDIA_API_KEY")
	os.Unsetenv("NVCF_API_KEY")
	os.Unsetenv("RAVEN_LLM_BASE_URL")
	os.Unsetenv("RAVEN_LLM_MODEL")
	if isNVIDIAConfigured() {
		t.Error("isNVIDIAConfigured should be false with empty env")
	}
	os.Setenv("NVIDIA_API_KEY", "x")
	if !isNVIDIAConfigured() {
		t.Error("isNVIDIAConfigured should be true with NVIDIA_API_KEY")
	}
	os.Unsetenv("NVIDIA_API_KEY")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
