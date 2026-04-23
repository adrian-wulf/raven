package hooks

import (
	"fmt"
	"os"
	"path/filepath"
)

// InstallHook installs the Raven pre-commit hook in the current git repository
func InstallHook() error {
	gitDir := ".git"
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository (no .git directory found)")
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")

	// Check if hook already exists
	if _, err := os.Stat(hookPath); err == nil {
		// Append to existing hook
		return appendToHook(hookPath)
	}

	// Create new hook
	return createHook(hookPath)
}

func createHook(hookPath string) error {
	hookContent := `#!/bin/sh
# Raven Security Scanner pre-commit hook
# https://github.com/raven-security/raven

echo "🐦‍⬛ Raven: Scanning for security vulnerabilities..."

# Run Raven scan
raven scan --staged --format pretty --min-sev high

# Check exit code
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Raven found security issues. Commit blocked."
    echo "   Fix the issues or use 'git commit --no-verify' to bypass (not recommended)."
    echo "   Run 'raven fix' to auto-fix issues where possible."
    exit 1
fi

echo "✅ Raven: No security issues found."
`

	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("writing pre-commit hook: %w", err)
	}

	fmt.Printf("✅ Pre-commit hook installed at %s\n", hookPath)
	fmt.Println("   Raven will scan your code before each commit.")
	fmt.Println("   Use 'git commit --no-verify' to bypass in emergencies.")
	return nil
}

func appendToHook(hookPath string) error {
	content, err := os.ReadFile(hookPath)
	if err != nil {
		return err
	}

	// Check if Raven hook is already installed
	if contains(string(content), "Raven Security Scanner") {
		fmt.Println("⚠️  Raven pre-commit hook is already installed.")
		return nil
	}

	ravenHook := `

# --- Raven Security Scanner ---
# https://github.com/raven-security/raven
echo "🐦‍⬛ Raven: Scanning for security vulnerabilities..."
raven scan --staged --format pretty --min-sev high
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Raven found security issues. Commit blocked."
    echo "   Fix the issues or use 'git commit --no-verify' to bypass."
    exit 1
fi
echo "✅ Raven: No security issues found."
# --- End Raven ---
`

	newContent := string(content) + ravenHook
	if err := os.WriteFile(hookPath, []byte(newContent), 0755); err != nil {
		return fmt.Errorf("appending to pre-commit hook: %w", err)
	}

	fmt.Printf("✅ Raven appended to existing pre-commit hook at %s\n", hookPath)
	return nil
}

// UninstallHook removes the Raven pre-commit hook
func UninstallHook() error {
	gitDir := ".git"
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository")
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		return fmt.Errorf("reading pre-commit hook: %w", err)
	}

	if !contains(string(content), "Raven Security Scanner") {
		fmt.Println("⚠️  Raven pre-commit hook not found.")
		return nil
	}

	// Remove Raven section
	startMarker := "# --- Raven Security Scanner ---"
	endMarker := "# --- End Raven ---"

	start := findIndex(string(content), startMarker)
	end := findIndex(string(content), endMarker)

	if start != -1 && end != -1 {
		end += len(endMarker)
		newContent := string(content)[:start] + string(content)[end:]
		if err := os.WriteFile(hookPath, []byte(newContent), 0755); err != nil {
			return err
		}
		fmt.Println("✅ Raven pre-commit hook removed.")
		return nil
	}

	// If we can't find markers, remove the whole hook
	if err := os.Remove(hookPath); err != nil {
		return err
	}
	fmt.Println("✅ Pre-commit hook removed.")
	return nil
}

func contains(s, substr string) bool {
	return findIndex(s, substr) != -1
}

func findIndex(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
