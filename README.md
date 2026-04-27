# Claude Connectors Scanner

A small local script that scans your machine for installed Claude connectors,
plugins, and extensions, and prints a list you can look up on
[claudesec.pluto.security](https://claudesec.pluto.security).

**The scanner runs entirely on your machine. Nothing is uploaded.**

## Quick install

No dependencies required — uses your shell's native tooling.

### macOS / Linux (bash)

```bash
curl -fsSL https://raw.githubusercontent.com/plutosecurity/Claude-Sec/main/scan.sh | bash
```

> If you have [jq](https://jqlang.github.io/jq/) installed, the script will pick up
> richer metadata (versions, publishers). Without it, names still work.

### Windows (PowerShell)

```powershell
$t="$env:TEMP\scan.ps1"; iwr https://raw.githubusercontent.com/plutosecurity/Claude-Sec/main/scan.ps1 -OutFile $t -UseBasicParsing; powershell -ExecutionPolicy Bypass -File $t
```

> Why not `irm | iex`? PowerShell 5.1 (the default on Windows) decodes web
> responses as ISO-8859-1, which corrupts the UTF-8 banner. Downloading to a
> file first and then executing avoids that and also handles execution-policy
> restrictions cleanly.

## Manual install

1. Download `scan.sh` (macOS / Linux) or `scan.ps1` (Windows) from this repo.
2. Run it:
   - macOS / Linux: `bash scan.sh` (or `chmod +x scan.sh && ./scan.sh`)
   - Windows: `powershell -File scan.ps1` or right-click → Run with PowerShell

## Options

```
bash scan.sh                # default colored output
NO_COLOR=1 bash scan.sh     # plain text, no ANSI colors

.\scan.ps1                  # default colored output
.\scan.ps1 -NoColor         # plain text, no ANSI colors
```

## What it scans

Output is grouped to match how things appear on
[claudesec.pluto.security](https://claudesec.pluto.security):

**Connectors** — anything Claude Desktop loads as an extension or talks to
as an MCP server:

| Source on disk | Maps to |
|---|---|
| `Claude/Claude Extensions/` | `.dxt` extensions installed in Claude Desktop |
| `Claude/claude_desktop_config.json` | MCP servers declared in the desktop config |

**Plugins** — anything loaded by Claude Code or the skill marketplace:

| Source on disk | Maps to |
|---|---|
| `~/.claude/plugins/installed_plugins.json` | Plugins installed via the Claude Code CLI |
| `Claude/local-agent-mode-sessions/.../knowledge-work-plugins/` | Anthropic skill plugins (Productivity, Sales, …) |
| `Claude/local-agent-mode-sessions/.../rpm/` | Runtime-loaded plugins |

Paths checked per OS:

- **macOS**: `~/.claude/`, `~/Library/Application Support/Claude/`
- **Windows**: `%USERPROFILE%\.claude\`, `%APPDATA%\Claude\`
- **Linux**: `~/.claude/`, `$XDG_CONFIG_HOME/Claude/` (defaults to `~/.config/Claude/`)

## Privacy

No network calls. No telemetry. No file modifications. The script reads a
handful of well-known JSON files and prints the names it finds.

## What to do with the output

Each name in the printed list can be searched on
[claudesec.pluto.security](https://claudesec.pluto.security) to see:

- Risk severity (high / medium / low)
- Tool-by-tool capability breakdown with Block / Review recommendations
- Plain-English impact descriptions
- Remediation steps tailored to each risk

## Issues

Spotted something the scanner missed, or want it to support another path?
[Open an issue.](https://github.com/plutosecurity/Claude-Sec/issues)
