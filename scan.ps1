# Claude Connectors Scanner (Windows)
#
# Lists Claude connectors and plugins installed on this machine.
# Output is printed to the terminal only — nothing leaves your computer.
#
# Look up the listed names on https://claudesec.pluto.security to see
# security risk analysis, tools breakdown, and remediation guidance.
#
# Usage:
#   powershell -File scan.ps1
#   .\scan.ps1
#   .\scan.ps1 -NoColor
param(
    [switch]$NoColor
)

$ErrorActionPreference = 'SilentlyContinue'

# ── ANSI escape codes (modern PowerShell on Windows 10+ supports them) ──
$ESC = [char]27
if ($NoColor) {
    $RESET = ''; $BOLD = ''; $DIM = ''
    $PEACH = ''; $ORANGE = ''; $GREEN = ''; $CYAN = ''; $GRAY = ''
} else {
    $RESET  = "$ESC[0m"
    $BOLD   = "$ESC[1m"
    $DIM    = "$ESC[2m"
    $PEACH  = "$ESC[38;5;216m"   # matches the homepage peach background
    $ORANGE = "$ESC[38;5;208m"
    $GREEN  = "$ESC[38;5;76m"
    $CYAN   = "$ESC[38;5;87m"
    $GRAY   = "$ESC[38;5;245m"
}

# ── Paths ──────────────────────────────────────────────────────────────
$UserDir = Join-Path $env:USERPROFILE '.claude'
$AppData = if ($env:APPDATA) { Join-Path $env:APPDATA 'Claude' } else { Join-Path $env:USERPROFILE 'AppData\Roaming\Claude' }

# ── Banner ─────────────────────────────────────────────────────────────
$banner = @(
'██████╗ ██╗     ██╗   ██╗████████╗ ██████╗',
'██╔══██╗██║     ██║   ██║╚══██╔══╝██╔═══██╗',
'██████╔╝██║     ██║   ██║   ██║   ██║   ██║',
'██╔═══╝ ██║     ██║   ██║   ██║   ██║   ██║',
'██║     ███████╗╚██████╔╝   ██║   ╚██████╔╝',
'╚═╝     ╚══════╝ ╚═════╝    ╚═╝    ╚═════╝'
)

Write-Host ''
Write-Host "${GRAY}              P O W E R E D   B Y${RESET}"
foreach ($line in $banner) { Write-Host "${PEACH}${BOLD}${line}${RESET}" }
Write-Host ''
Write-Host "       ${GRAY}S E C U R I T Y   .   C L A U D E S E C   F L E E T   S C A N N E R${RESET}"
Write-Host ''
Write-Host "  ${DIM}Scanning Windows | home: $env:USERPROFILE${RESET}"
Write-Host ''

# ── Item builder ──────────────────────────────────────────────────────
function New-ScanItem ([string]$Name, [string]$Version, [string]$Publisher, [string]$Subtype) {
    [pscustomobject]@{
        Name      = $Name
        Version   = $Version
        Publisher = $Publisher
        Subtype   = $Subtype
    }
}

function Read-JsonFile ([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch { return $null }
}

# ── Scan: Connectors ─────────────────────────────────────────────────
$connectors = New-Object System.Collections.ArrayList

$extDir = Join-Path $AppData 'Claude Extensions'
if (Test-Path -LiteralPath $extDir -PathType Container) {
    Get-ChildItem -LiteralPath $extDir -Directory | Sort-Object Name | ForEach-Object {
        $manifest = Read-JsonFile (Join-Path $_.FullName 'manifest.json')
        $name = if ($manifest -and $manifest.display_name) { $manifest.display_name } `
                elseif ($manifest -and $manifest.name) { $manifest.name } `
                else { $_.Name }
        $version = if ($manifest -and $manifest.version) { $manifest.version } else { '' }
        $publisher = ''
        if ($manifest -and $manifest.author) {
            $publisher = if ($manifest.author -is [string]) { $manifest.author } `
                         elseif ($manifest.author.name) { $manifest.author.name } `
                         else { '' }
        }
        [void]$connectors.Add((New-ScanItem $name $version $publisher 'extension'))
    }
}

$cfg = Read-JsonFile (Join-Path $AppData 'claude_desktop_config.json')
if ($cfg -and $cfg.mcpServers) {
    foreach ($prop in $cfg.mcpServers.PSObject.Properties) {
        [void]$connectors.Add((New-ScanItem $prop.Name '' '' 'MCP server'))
    }
}

# ── Scan: Plugins ────────────────────────────────────────────────────
$plugins = New-Object System.Collections.ArrayList

$installed = Read-JsonFile (Join-Path $UserDir 'plugins\installed_plugins.json')
if ($installed -and $installed.plugins) {
    foreach ($prop in $installed.plugins.PSObject.Properties) {
        $key = $prop.Name
        $name, $marketplace = $key -split '@', 2
        $instances = $prop.Value
        if (-not $instances) { continue }
        foreach ($inst in $instances) {
            $version = if ($inst.version) { $inst.version } else { '' }
            [void]$plugins.Add((New-ScanItem $name $version $marketplace 'Claude Code'))
        }
    }
}

$sessions = Join-Path $AppData 'local-agent-mode-sessions'
$seen = @{}
if (Test-Path -LiteralPath $sessions -PathType Container) {
    Get-ChildItem -LiteralPath $sessions -Recurse -File -Filter 'plugin.json' | Where-Object {
        $_.Directory.Name -eq '.claude-plugin'
    } | ForEach-Object {
        $manifest = Read-JsonFile $_.FullName
        if (-not $manifest -or -not $manifest.name) { return }
        if ($seen.ContainsKey($manifest.name)) { return }
        $seen[$manifest.name] = $true
        $version = if ($manifest.version) { $manifest.version } else { '' }
        $publisher = ''
        if ($manifest.author) {
            $publisher = if ($manifest.author -is [string]) { $manifest.author } `
                         elseif ($manifest.author.name) { $manifest.author.name } `
                         else { '' }
        }
        [void]$plugins.Add((New-ScanItem $manifest.name $version $publisher 'skill plugin'))
    }
}

# ── Render ───────────────────────────────────────────────────────────
function Show-Section ([string]$Title, [System.Collections.IEnumerable]$Items) {
    $count = ($Items | Measure-Object).Count
    if ($count -eq 0) { return }
    Write-Host "  ${ORANGE}${BOLD}${Title}${RESET}  ${GRAY}($count)${RESET}"
    Write-Host "  ${DIM}$('-' * 64)${RESET}"
    foreach ($item in $Items) {
        $line = "  ${GREEN}*${RESET} ${BOLD}$($item.Name)${RESET}"
        if ($item.Version)   { $line += " ${GRAY}$($item.Version)${RESET}" }
        if ($item.Publisher) { $line += " ${DIM}by $($item.Publisher)${RESET}" }
        if ($item.Subtype)   { $line += " ${DIM}[$($item.Subtype)]${RESET}" }
        Write-Host $line
    }
    Write-Host ''
}

Show-Section 'Connectors' $connectors
Show-Section 'Plugins'    $plugins

$total = $connectors.Count + $plugins.Count
if ($total -eq 0) {
    Write-Host "  ${PEACH}No Claude connectors or plugins found on this machine.${RESET}"
    Write-Host ''
    return
}

Write-Host "  ${BOLD}${total}${RESET} ${GRAY}items found.${RESET}"
Write-Host ''
Write-Host "  ${GRAY}Search any of these on${RESET} ${CYAN}${BOLD}https://claudesec.pluto.security${RESET}"
Write-Host "  ${GRAY}to see risk severity, tool-by-tool analysis, and remediation tips.${RESET}"
Write-Host ''
