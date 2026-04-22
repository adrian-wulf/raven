package cli

import (
	"fmt"
	"os"

	"github.com/raven-security/raven/internal/lsp"
	"github.com/spf13/cobra"
)

func lspCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lsp",
		Short: "Start Language Server Protocol (LSP) server",
		Long: `Start the Raven LSP server for IDE integration.

This communicates with VS Code, Cursor, Vim, or any LSP-compatible editor
over stdin/stdout. It provides:
  - Real-time security diagnostics as you type
  - Code actions ("Fix this vulnerability")
  - Hover information about security issues

The LSP server is automatically started by the VS Code extension.
You typically don't need to run this manually.

Example:
  raven lsp  # Starts LSP server on stdio`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stderr, "🐦‍⬛ Raven LSP server starting...")

			server := lsp.NewServer(os.Stdin, os.Stdout)
			if err := server.Run(); err != nil {
				return fmt.Errorf("LSP server error: %w", err)
			}

			return nil
		},
	}
}
