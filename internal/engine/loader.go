package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/raven-security/raven/internal/utils"
	"gopkg.in/yaml.v3"
)

// LoadRules loads all YAML rule files from the given directory
type RulesLoader struct {
	Dirs []string
}

func NewRulesLoader() *RulesLoader {
	dirs := []string{
		"rules",                         // local development
		"/usr/share/raven/rules",        // system install
		"/usr/local/share/raven/rules",  // Homebrew / manual install
	}

	// Add directory relative to the executable (for go install / binary releases)
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		// Try ../share/raven/rules (FHS layout)
		dirs = append(dirs, filepath.Join(exeDir, "..", "share", "raven", "rules"))
		// Try ../rules (side-by-side with binary)
		dirs = append(dirs, filepath.Join(exeDir, "..", "rules"))
	}

	// Add user config directory
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".config", "raven", "rules"))
	}

	return &RulesLoader{Dirs: dirs}
}

func (rl *RulesLoader) Load() ([]Rule, error) {
	var rules []Rule
	seen := make(map[string]bool)

	for _, dir := range rl.Dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		err := utils.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				// Skip hidden directories (e.g. .disabled-broken, .git)
				if strings.HasPrefix(info.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
				return nil
			}

			rule, err := rl.loadRuleFile(path)
			if err != nil {
				return nil // skip malformed rules
			}

			if !seen[rule.ID] {
				seen[rule.ID] = true
				rules = append(rules, rule)
			}

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return rules, nil
}

func (rl *RulesLoader) loadRuleFile(path string) (Rule, error) {
	var rule Rule
	data, err := os.ReadFile(path)
	if err != nil {
		return rule, err
	}
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return rule, fmt.Errorf("parsing %s: %w", path, err)
	}
	if rule.ID == "" {
		return rule, fmt.Errorf("rule missing id in %s", path)
	}
	return rule, nil
}
