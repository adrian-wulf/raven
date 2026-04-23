package cli

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/raven-security/raven/internal/config"
	"github.com/raven-security/raven/internal/version"
	"github.com/spf13/cobra"
)

var (
	cfg     *config.Config
	verbose bool
)

var styles = struct {
	Title    lipgloss.Style
	Subtitle lipgloss.Style
	Box      lipgloss.Style
	Error    lipgloss.Style
	Warning  lipgloss.Style
	Success  lipgloss.Style
	Info     lipgloss.Style
	Code     lipgloss.Style
}{
	Title:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#6C5CE7")).MarginLeft(2),
	Subtitle: lipgloss.NewStyle().Foreground(lipgloss.Color("#A29BFE")).MarginLeft(2),
	Box: lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#6C5CE7")).
		Padding(1, 2).
		Margin(1, 2),
	Error:   lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6B6B")).Bold(true),
	Warning: lipgloss.NewStyle().Foreground(lipgloss.Color("#FDCB6E")).Bold(true),
	Success: lipgloss.NewStyle().Foreground(lipgloss.Color("#55EFC4")).Bold(true),
	Info:    lipgloss.NewStyle().Foreground(lipgloss.Color("#74B9FF")),
	Code:    lipgloss.NewStyle().Background(lipgloss.Color("#2D3436")).Foreground(lipgloss.Color("#DFE6E9")).Padding(0, 1),
}

var rootCmd = &cobra.Command{
	Use:   "raven",
	Short: "Security scanner for vibe coders",
	Long: styles.Box.Render(
		fmt.Sprintf(
			"%s\n%s\n\n%s",
			styles.Title.Render("🐦‍⬛ Raven"),
			styles.Subtitle.Render("Catch security bugs before you ship"),
			"Raven scans your AI-generated code for vulnerabilities.\n"+
				"It finds SQL injection, XSS, hardcoded secrets, and more.\n\n"+
				"Commands:\n"+
				"  raven scan          Scan your project\n"+
				"  raven watch         Watch for changes and scan\n"+
				"  raven fix           Auto-fix what can be fixed\n"+
				"  raven rules         List available rules\n"+
				"  raven ci            CI mode (exit 1 on findings)",
		),
	),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		cfg, err = config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		return nil
	},
	SilenceUsage: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().String("config", "", "config file path")

	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(watchCmd())
	rootCmd.AddCommand(fixCmd())
	rootCmd.AddCommand(rulesCmd())
	rootCmd.AddCommand(ciCmd())
	rootCmd.AddCommand(learnCmd())
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(lspCmd())
	rootCmd.AddCommand(hookCmd())
	rootCmd.AddCommand(aiFixCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(completionCmd())
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Raven version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Raven v" + version.Version)
			fmt.Println("Security scanner for vibe coders")
		},
	}
}

func completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate shell completion script for Raven.

To load completions:

Bash:
  $ source <(raven completion bash)
  # Or add to ~/.bashrc:
  $ echo 'source <(raven completion bash)' >> ~/.bashrc

Zsh:
  $ source <(raven completion zsh)
  $ compdef _raven raven
  # Or add to ~/.zshrc:
  $ echo 'source <(raven completion zsh)' >> ~/.zshrc

Fish:
  $ raven completion fish | source
  $ raven completion fish > ~/.config/fish/completions/raven.fish

PowerShell:
  PS> raven completion powershell | Out-String | Invoke-Expression
  PS> raven completion powershell > raven.ps1
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				cmd.Root().GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				cmd.Root().GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			}
		},
	}
}
