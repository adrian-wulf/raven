package cli

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/raven-security/raven/internal/config"
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
	rootCmd.AddCommand(versionCmd())
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Raven version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Raven v0.1.0-alpha")
			fmt.Println("Security scanner for vibe coders")
		},
	}
}
