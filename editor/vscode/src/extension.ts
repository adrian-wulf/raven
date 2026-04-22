import * as vscode from 'vscode';
import * as path from 'path';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  const config = vscode.workspace.getConfiguration('raven');
  const enabled = config.get<boolean>('enabled', true);

  if (!enabled) {
    return;
  }

  // Status bar item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.text = '$(shield) Raven';
  statusBarItem.tooltip = 'Raven Security Scanner — click to scan workspace';
  statusBarItem.command = 'raven.scanWorkspace';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Start LSP client
  const ravenPath = config.get<string>('path', 'raven');
  const serverOptions: ServerOptions = {
    command: ravenPath,
    args: ['lsp'],
    transport: TransportKind.stdio,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: 'file', language: 'javascript' },
      { scheme: 'file', language: 'typescript' },
      { scheme: 'file', language: 'python' },
      { scheme: 'file', language: 'go' },
      { scheme: 'file', language: 'php' },
      { scheme: 'file', language: 'rust' },
      { scheme: 'file', language: 'java' },
    ],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher('**/.raven.yaml'),
    },
    outputChannelName: 'Raven Security',
  };

  client = new LanguageClient('raven', 'Raven Security Scanner', serverOptions, clientOptions);
  client.start();

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('raven.scanWorkspace', async () => {
      const terminal = vscode.window.createTerminal('Raven');
      terminal.sendText('raven scan');
      terminal.show();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('raven.fixAll', async () => {
      const terminal = vscode.window.createTerminal('Raven');
      terminal.sendText('raven fix --apply');
      terminal.show();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('raven.showOutput', () => {
      if (client) {
        client.outputChannel.show();
      }
    })
  );

  // Listen for diagnostics to update status bar
  if (client) {
    client.onNotification('textDocument/publishDiagnostics', (params: any) => {
      const diagnostics = params.diagnostics || [];
      const errors = diagnostics.filter((d: any) => d.severity === 1).length;
      const warnings = diagnostics.filter((d: any) => d.severity === 2).length;

      if (errors > 0) {
        statusBarItem.text = `$(shield) Raven $(error) ${errors}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
      } else if (warnings > 0) {
        statusBarItem.text = `$(shield) Raven $(warning) ${warnings}`;
        statusBarItem.backgroundColor = undefined;
      } else {
        statusBarItem.text = '$(shield) Raven $(check)';
        statusBarItem.backgroundColor = undefined;
      }
    });
  }

  vscode.window.showInformationMessage('🐦‍⬛ Raven Security Scanner activated');
}

export function deactivate(): Thenable<void> | undefined {
  if (statusBarItem) {
    statusBarItem.dispose();
  }
  if (client) {
    return client.stop();
  }
  return undefined;
}
