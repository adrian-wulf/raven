import * as vscode from 'vscode';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
  Diagnostic,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let statusBarItem: vscode.StatusBarItem;
let findingsTreeProvider: FindingsTreeProvider;
let findingsTreeView: vscode.TreeView<FindingItem>;

// Global findings store
interface FindingInfo {
  uri: string;
  file: string;
  line: number;
  severity: string;
  ruleId: string;
  message: string;
  diagnostic: Diagnostic;
}

let allFindings: FindingInfo[] = [];

export function activate(context: vscode.ExtensionContext) {
  const config = vscode.workspace.getConfiguration('raven');

  // Create status bar item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'raven.showFindings';
  updateStatusBar(0, 0, 0);
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Setup LSP client
  const executablePath = config.get<string>('executablePath', 'raven');
  const serverOptions: ServerOptions = {
    command: executablePath,
    args: ['lsp'],
    transport: TransportKind.stdio,
    options: {
      env: process.env,
    },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: 'file', language: 'javascript' },
      { scheme: 'file', language: 'typescript' },
      { scheme: 'file', language: 'python' },
      { scheme: 'file', language: 'go' },
      { scheme: 'file', language: 'java' },
      { scheme: 'file', language: 'php' },
      { scheme: 'file', language: 'rust' },
      { scheme: 'file', language: 'ruby' },
      { scheme: 'file', language: 'kotlin' },
      { scheme: 'file', language: 'swift' },
      { scheme: 'file', language: 'csharp' },
    ],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher('**/*'),
    },
    initializationOptions: {
      minSeverity: config.get<string>('minSeverity', 'low'),
      languages: config.get<string[]>('languages', []),
    },
  };

  client = new LanguageClient(
    'ravenSecurity',
    'Raven Security Scanner',
    serverOptions,
    clientOptions
  );

  // Listen for diagnostics to populate our findings panel
  client.start().then(() => {
    client!.onNotification('textDocument/publishDiagnostics', (params: {
      uri: string;
      diagnostics: Diagnostic[];
    }) => {
      // Remove old findings for this URI
      allFindings = allFindings.filter(f => f.uri !== params.uri);

      // Add new findings
      for (const d of params.diagnostics) {
        if (d.source === 'raven' && d.code) {
          const severity = extractSeverity(d.message);
          allFindings.push({
            uri: params.uri,
            file: vscode.Uri.parse(params.uri).fsPath,
            line: (d.range?.start?.line ?? 0) + 1,
            severity,
            ruleId: String(d.code),
            message: d.message.replace(/^\[[^\]]+\]\s*/, ''),
            diagnostic: d,
          });
        }
      }

      refreshFindingsPanel();
      updateStatusBarFromFindings();
    });
  });

  client.start();
  context.subscriptions.push(client);

  // Setup findings tree view
  findingsTreeProvider = new FindingsTreeProvider();
  findingsTreeView = vscode.window.createTreeView('ravenFindings', {
    treeDataProvider: findingsTreeProvider,
    showCollapseAll: true,
  });
  context.subscriptions.push(findingsTreeView);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('raven.scanWorkspace', scanWorkspace)
  );
  context.subscriptions.push(
    vscode.commands.registerCommand('raven.scanFile', scanFile)
  );
  context.subscriptions.push(
    vscode.commands.registerCommand('raven.showFindings', showFindings)
  );
  context.subscriptions.push(
    vscode.commands.registerCommand('raven.openRule', openRule)
  );
  context.subscriptions.push(
    vscode.commands.registerCommand('raven.clearFindings', clearFindings)
  );
  context.subscriptions.push(
    vscode.commands.registerCommand('raven.refreshPanel', refreshFindingsPanel)
  );
  context.subscriptions.push(
    vscode.commands.registerCommand('raven.goToFinding', goToFinding)
  );

  // Show welcome message
  vscode.window.showInformationMessage(
    '🐦‍⬛ Raven Security Scanner activated. Run "Raven: Scan Workspace" to start.',
    'Scan Workspace'
  ).then(selection => {
    if (selection === 'Scan Workspace') {
      scanWorkspace();
    }
  });
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}

// Commands

async function scanWorkspace() {
  const config = vscode.workspace.getConfiguration('raven');
  const executablePath = config.get<string>('executablePath', 'raven');
  const workspaceFolders = vscode.workspace.workspaceFolders;

  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage('No workspace folder open.');
    return;
  }

  const rootPath = workspaceFolders[0].uri.fsPath;

  vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: '🐦‍⬛ Raven: Scanning workspace...',
      cancellable: false,
    },
    async () => {
      const { execFile } = await import('child_process');
      const { promisify } = await import('util');
      const execFileAsync = promisify(execFile);

      try {
        const minSeverity = config.get<string>('minSeverity', 'low');
        const languages = config.get<string[]>('languages', []);

        const args = ['scan', '--severity', minSeverity, '--format', 'json'];
        if (languages.length > 0) {
          args.push('--languages', languages.join(','));
        }
        args.push(rootPath);

        const { stdout } = await execFileAsync(executablePath, args, {
          cwd: rootPath,
          maxBuffer: 50 * 1024 * 1024, // 50MB
        });

        const result = JSON.parse(stdout);
        const findings = result.findings || [];

        // Update findings
        allFindings = findings.map((f: any) => ({
          uri: vscode.Uri.file(f.file).toString(),
          file: f.file,
          line: f.line,
          severity: f.severity,
          ruleId: f.rule_id,
          message: f.message,
          diagnostic: null as any,
        }));

        refreshFindingsPanel();
        updateStatusBarFromFindings();

        if (findings.length === 0) {
          vscode.window.showInformationMessage(
            `✅ Raven: No issues found! Scanned ${result.files_scanned} files.`
          );
        } else {
          const bySev: Record<string, number> = {};
          for (const f of findings) {
            bySev[f.severity] = (bySev[f.severity] || 0) + 1;
          }
          const summary = Object.entries(bySev)
            .sort(([a], [b]) => severityRank(b) - severityRank(a))
            .map(([sev, count]) => `${count} ${sev}`)
            .join(', ');

          vscode.window.showWarningMessage(
            `🐦‍⬛ Raven found ${findings.length} issue(s): ${summary}`,
            'Show Details'
          ).then(sel => {
            if (sel === 'Show Details') {
              showFindings();
            }
          });
        }
      } catch (err: any) {
        vscode.window.showErrorMessage(
          `Raven scan failed: ${err.message || err}`
        );
      }
    }
  );
}

async function scanFile(uri?: vscode.Uri) {
  const config = vscode.workspace.getConfiguration('raven');
  const executablePath = config.get<string>('executablePath', 'raven');

  let targetUri = uri;
  if (!targetUri) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('No file open to scan.');
      return;
    }
    targetUri = editor.document.uri;
  }

  if (targetUri.scheme !== 'file') {
    vscode.window.showWarningMessage('Can only scan local files.');
    return;
  }

  const filePath = targetUri.fsPath;

  vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `🐦‍⬛ Raven: Scanning ${pathBasename(filePath)}...`,
      cancellable: false,
    },
    async () => {
      const { execFile } = await import('child_process');
      const { promisify } = await import('util');
      const execFileAsync = promisify(execFile);

      try {
        const minSeverity = config.get<string>('minSeverity', 'low');
        const args = ['scan', '--severity', minSeverity, '--format', 'json', filePath];

        const { stdout } = await execFileAsync(executablePath, args, {
          maxBuffer: 10 * 1024 * 1024,
        });

        const result = JSON.parse(stdout);
        const findings = result.findings || [];

        // Update only for this file
        allFindings = allFindings.filter(f => f.uri !== targetUri!.toString());
        for (const f of findings) {
          allFindings.push({
            uri: targetUri!.toString(),
            file: f.file,
            line: f.line,
            severity: f.severity,
            ruleId: f.rule_id,
            message: f.message,
            diagnostic: null as any,
          });
        }

        refreshFindingsPanel();
        updateStatusBarFromFindings();

        if (findings.length === 0) {
          vscode.window.showInformationMessage(
            `✅ Raven: No issues in ${pathBasename(filePath)}`
          );
        } else {
          vscode.window.showWarningMessage(
            `🐦‍⬛ Found ${findings.length} issue(s) in ${pathBasename(filePath)}`
          );
        }
      } catch (err: any) {
        vscode.window.showErrorMessage(
          `Raven scan failed: ${err.message || err}`
        );
      }
    }
  );
}

function showFindings() {
  if (allFindings.length === 0) {
    vscode.window.showInformationMessage('No findings to show. Run a scan first.');
    return;
  }
  vscode.commands.executeCommand('ravenFindings.focus');
}

function openRule(ruleId: string) {
  // Try to find rule details via MCP or just show info
  const panel = vscode.window.createWebviewPanel(
    'ravenRule',
    `Raven Rule: ${ruleId}`,
    vscode.ViewColumn.One,
    { enableScripts: true }
  );

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: var(--vscode-font-family); padding: 20px; color: var(--vscode-foreground); }
        h1 { color: #6C5CE7; }
        code { background: var(--vscode-textCodeBlock-background); padding: 2px 6px; border-radius: 3px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; margin-right: 8px; }
        .critical { background: #FF6B6B; color: white; }
        .high { background: #E17055; color: white; }
        .medium { background: #FDCB6E; color: black; }
        .low { background: #74B9FF; color: white; }
      </style>
    </head>
    <body>
      <h1>🐦‍⬛ ${ruleId}</h1>
      <p>Rule documentation would be loaded here.</p>
      <p>Run <code>raven rules</code> in your terminal to see all rules.</p>
    </body>
    </html>
  `;
}

function clearFindings() {
  allFindings = [];
  refreshFindingsPanel();
  updateStatusBar(0, 0, 0);

  // Clear LSP diagnostics too
  if (client) {
    const uris = new Set(allFindings.map(f => f.uri));
    for (const uri of uris) {
      // We can't easily clear LSP diagnostics from client side
      // They'll refresh on next document change
    }
  }

  vscode.window.showInformationMessage('Raven findings cleared.');
}

function goToFinding(uri: string, line: number) {
  const docUri = vscode.Uri.parse(uri);
  vscode.window.showTextDocument(docUri).then(editor => {
    const pos = new vscode.Position(line - 1, 0);
    editor.selection = new vscode.Selection(pos, pos);
    editor.revealRange(
      new vscode.Range(pos, pos),
      vscode.TextEditorRevealType.InCenterIfOutsideViewport
    );
  });
}

// Helpers

function updateStatusBar(criticalHigh: number, medium: number, low: number) {
  if (criticalHigh > 0) {
    statusBarItem.text = `$(warning) Raven: ${criticalHigh} critical/high`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else if (medium > 0) {
    statusBarItem.text = `$(info) Raven: ${medium} medium`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  } else if (low > 0) {
    statusBarItem.text = `$(shield) Raven: ${low} info`;
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = `$(shield) Raven: clean`;
    statusBarItem.backgroundColor = undefined;
  }
}

function updateStatusBarFromFindings() {
  let criticalHigh = 0;
  let medium = 0;
  let low = 0;

  for (const f of allFindings) {
    if (f.severity === 'critical' || f.severity === 'high') {
      criticalHigh++;
    } else if (f.severity === 'medium') {
      medium++;
    } else {
      low++;
    }
  }

  updateStatusBar(criticalHigh, medium, low);
}

function extractSeverity(message: string): string {
  const match = message.match(/^\[([^\]]+)\]/);
  return match ? match[1].toLowerCase() : 'info';
}

function severityRank(sev: string): number {
  switch (sev.toLowerCase()) {
    case 'critical': return 5;
    case 'high': return 4;
    case 'medium': return 3;
    case 'low': return 2;
    default: return 1;
  }
}

function pathBasename(p: string): string {
  return p.replace(/\\/g, '/').split('/').pop() || p;
}

function refreshFindingsPanel() {
  findingsTreeProvider.refresh();
}

// Tree Data Provider

class FindingsTreeProvider implements vscode.TreeDataProvider<FindingItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<FindingItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingItem): Thenable<FindingItem[]> {
    if (!element) {
      // Top level: group by severity
      const bySeverity: Record<string, FindingInfo[]> = {};
      for (const f of allFindings) {
        if (!bySeverity[f.severity]) bySeverity[f.severity] = [];
        bySeverity[f.severity].push(f);
      }

      const severities = Object.keys(bySeverity).sort((a, b) => severityRank(b) - severityRank(a));
      return Promise.resolve(
        severities.map(sev => {
          const count = bySeverity[sev].length;
          const icon = sev === 'critical' || sev === 'high'
            ? new vscode.ThemeIcon('error')
            : sev === 'medium'
            ? new vscode.ThemeIcon('warning')
            : new vscode.ThemeIcon('info');

          return new FindingItem(
            `${sev.toUpperCase()} (${count})`,
            vscode.TreeItemCollapsibleState.Expanded,
            icon,
            undefined,
            sev
          );
        })
      );
    }

    // Children: individual findings
    if (element.severity) {
      const findings = allFindings.filter(f => f.severity === element.severity);
      return Promise.resolve(
        findings.map(f => {
          const label = `${pathBasename(f.file)}:${f.line} — ${f.ruleId}`;
          const item = new FindingItem(
            label,
            vscode.TreeItemCollapsibleState.None,
            new vscode.ThemeIcon('circle-filled'),
            f.message,
            undefined,
            f.uri,
            f.line
          );
          item.command = {
            command: 'raven.goToFinding',
            title: 'Go to Finding',
            arguments: [f.uri, f.line],
          };
          return item;
        })
      );
    }

    return Promise.resolve([]);
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    icon: vscode.ThemeIcon,
    tooltip?: string,
    public severity?: string,
    public uri?: string,
    public line?: number,
  ) {
    super(label, collapsibleState);
    this.iconPath = icon;
    if (tooltip) {
      this.tooltip = tooltip;
    }
  }
}
