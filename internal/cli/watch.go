package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/raven-security/raven/internal/engine"
	"github.com/raven-security/raven/internal/output"
	"github.com/raven-security/raven/internal/utils"
	"github.com/spf13/cobra"
)

func watchCmd() *cobra.Command {
	var (
		debounce int
		sev      string
	)

	cmd := &cobra.Command{
		Use:   "watch [paths...]",
		Short: "Watch files and scan on change",
		Long: `Watch your project files and automatically scan when changes are detected.

This is perfect for development - catch security issues as you code.

Examples:
  raven watch              # Watch current directory
  raven watch ./src        # Watch specific directory
  raven watch --debounce 1000`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}

			loader := engine.NewRulesLoader()
			rules, err := loader.Load()
			if err != nil {
				return fmt.Errorf("loading rules: %w", err)
			}

			scanConfig := engine.ScanConfig{
				Paths:       paths,
				Exclude:     cfg.Rules.Exclude,
				MinSeverity: engine.Severity(sev),
			}

			fmt.Println("👁️  Watching for changes... (Ctrl+C to stop)")
			fmt.Println()

			// Simple polling watcher
			fileTimes := make(map[string]time.Time)
			var mu sync.Mutex
			lastScan := time.Now()

			for {
				time.Sleep(500 * time.Millisecond)

				changed := false
				for _, root := range paths {
					utils.Walk(root, func(path string, info os.FileInfo, err error) error {
						if err != nil || info.IsDir() {
							return nil
						}
						if isExcluded(path, cfg.Rules.Exclude) {
							return nil
						}

						mu.Lock()
						lastMod, seen := fileTimes[path]
						fileTimes[path] = info.ModTime()
						mu.Unlock()

						if seen && info.ModTime().After(lastMod) {
							changed = true
						}
						return nil
					})
				}

				if changed && time.Since(lastScan) > time.Duration(debounce)*time.Millisecond {
					lastScan = time.Now()
					fmt.Printf("\n🔄 Change detected, scanning...\n\n")

					scanner := engine.NewScanner(rules, scanConfig)
					result, err := scanner.Scan()
					if err != nil {
						fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
						continue
					}

					formatter := output.Formatter{
						Format:   "pretty",
						Color:    true,
						ShowCode: true,
					}
					formatter.Print(result)
					fmt.Println("---")
				}
			}
		},
	}

	cmd.Flags().IntVarP(&debounce, "debounce", "d", 1000, "Debounce time in milliseconds")
	cmd.Flags().StringVar(&sev, "min-sev", "low", "Minimum severity")

	return cmd
}

func isExcluded(path string, exclude []string) bool {
	for _, pattern := range exclude {
		if strings.Contains(path, pattern) {
			return true
		}
		matched, _ := filepath.Match(pattern, filepath.Base(path))
		if matched {
			return true
		}
	}
	return false
}
