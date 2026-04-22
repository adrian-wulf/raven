package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Rules    RulesConfig    `mapstructure:"rules"`
	Output   OutputConfig   `mapstructure:"output"`
	Fix      FixConfig      `mapstructure:"fix"`
	Watch    WatchConfig    `mapstructure:"watch"`
	Severity SeverityConfig `mapstructure:"severity"`
}

type RulesConfig struct {
	Paths       []string `mapstructure:"paths"`
	Exclude     []string `mapstructure:"exclude"`
	Languages   []string `mapstructure:"languages"`
	Confidence  string   `mapstructure:"confidence"`
}

type OutputConfig struct {
	Format   string `mapstructure:"format"`
	Color    bool   `mapstructure:"color"`
	ShowCode bool   `mapstructure:"show_code"`
}

type FixConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	AutoApply bool     `mapstructure:"auto_apply"`
	DryRun    bool     `mapstructure:"dry_run"`
	Exclude   []string `mapstructure:"exclude"`
}

type WatchConfig struct {
	DebounceMs int      `mapstructure:"debounce_ms"`
	Ignore     []string `mapstructure:"ignore"`
}

type SeverityConfig struct {
	Min string `mapstructure:"min"`
}

func DefaultConfig() *Config {
	return &Config{
		Rules: RulesConfig{
			Paths:      []string{"."},
			Exclude:    []string{"node_modules", "vendor", "dist", "build", ".git", "*.min.js"},
			Languages:  []string{}, // auto-detect
			Confidence: "medium",
		},
		Output: OutputConfig{
			Format:   "pretty",
			Color:    true,
			ShowCode: true,
		},
		Fix: FixConfig{
			Enabled:   true,
			AutoApply: false,
			DryRun:    true,
		},
		Watch: WatchConfig{
			DebounceMs: 500,
			Ignore:     []string{"node_modules", ".git", "dist", "build"},
		},
		Severity: SeverityConfig{
			Min: "low",
		},
	}
}

func Load() (*Config, error) {
	cfg := DefaultConfig()
	v := viper.New()
	v.SetConfigName("raven")
	v.SetConfigType("yaml")

	home, err := os.UserHomeDir()
	if err == nil {
		v.AddConfigPath(filepath.Join(home, ".config", "raven"))
	}
	v.AddConfigPath(".")

	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	v.SetEnvPrefix("RAVEN")
	v.AutomaticEnv()

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("rules.paths", []string{"."})
	v.SetDefault("rules.exclude", []string{"node_modules", "vendor", "dist", "build", ".git"})
	v.SetDefault("rules.confidence", "medium")
	v.SetDefault("output.format", "pretty")
	v.SetDefault("output.color", true)
	v.SetDefault("output.show_code", true)
	v.SetDefault("fix.enabled", true)
	v.SetDefault("fix.auto_apply", false)
	v.SetDefault("fix.dry_run", true)
	v.SetDefault("watch.debounce_ms", 500)
	v.SetDefault("severity.min", "low")
}

func ConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".raven"
	}
	return filepath.Join(home, ".config", "raven")
}

func EnsureConfigDir() error {
	return os.MkdirAll(ConfigDir(), 0755)
}
