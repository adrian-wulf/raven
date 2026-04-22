package cli

import (
	"github.com/raven-security/raven/internal/hooks"
	"github.com/spf13/cobra"
)

func hookCmd() *cobra.Command {
	var uninstall bool

	cmd := &cobra.Command{
		Use:   "install-hook",
		Short: "Install pre-commit hook",
		Long: `Install Raven as a pre-commit hook in your git repository.

This will scan your code for security vulnerabilities before each commit
and block the commit if critical/high severity issues are found.

Examples:
  raven install-hook              # Install hook
  raven install-hook --uninstall  # Remove hook`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if uninstall {
				return hooks.UninstallHook()
			}
			return hooks.InstallHook()
		},
	}

	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "Remove the pre-commit hook")

	return cmd
}
