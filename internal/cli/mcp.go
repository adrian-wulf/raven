package cli

import (
	"fmt"
	"os"

	"github.com/raven-security/raven/internal/mcp"
	"github.com/spf13/cobra"
)

func mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start Raven MCP server (Model Context Protocol)",
		Long: `Start Raven as an MCP server for AI integration.

The Model Context Protocol allows AI assistants (Claude, Codex, etc.) to
invoke Raven's security scanning capabilities as tools.

To use with Claude Desktop, add to your claude_desktop_config.json:
  {
    "mcpServers": {
      "raven": {
        "command": "raven",
        "args": ["mcp"]
      }
    }
  }

Available tools:
  raven_scan_workspace   Scan a directory for vulnerabilities
  raven_scan_file        Scan a specific file
  raven_scan_snippet     Scan a code snippet (great for AI-generated code)
  raven_list_rules       List all 500+ security rules
  raven_get_rule         Get details of a specific rule
  raven_explain_finding  Get detailed explanation of a vulnerability
`,
		Example: `  raven mcp  # Starts MCP server on stdio`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stderr, "🐦‍⬛ Raven MCP server started")
			fmt.Fprintf(os.Stderr, "   Rules loaded: ready\n")
			fmt.Fprintf(os.Stderr, "   Protocol: Model Context Protocol v2024-11-05\n")
			fmt.Fprintf(os.Stderr, "   Waiting for connections...\n\n")

			server := mcp.NewServer(os.Stdin, os.Stdout)
			return server.Run()
		},
	}
}
