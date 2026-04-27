# Claude Connectors Scanner (Windows)
#
# Lists Claude connectors and plugins installed on this machine.
# Output is printed to the terminal only - nothing leaves your computer.
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

# ---- Color helpers --------------------------------------------------
# Native PowerShell -ForegroundColor only has the 16 console colors, none
# of which is peach. On modern hosts (PS Core 7+, Windows Terminal) we can
# emit ANSI 256-color escapes for a true peach banner; on classic PS 5.1
# conhost we fall back to the native palette (Yellow as the closest match).

# PS 6+ (Core) supports ANSI on every platform. On PS 5.1 + Windows we
# can probe for ANSI support via $Host.UI.SupportsVirtualTerminal (set
# when conhost has VT mode enabled).
$script:UseAnsi = $false
try {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $script:UseAnsi = $true
    } elseif ($Host -and $Host.UI -and $Host.UI.SupportsVirtualTerminal) {
        $script:UseAnsi = $true
    }
} catch {}

# Map of high-level color names -> { ansi, native } pair so the rest of
# the script can ask for a single name and we route appropriately.
$script:ColorMap = @{
    Peach    = @{ Ansi = "$([char]27)[38;5;216m"; Native = 'Yellow'    }
    Yellow   = @{ Ansi = "$([char]27)[38;5;220m"; Native = 'Yellow'    }
    Orange   = @{ Ansi = "$([char]27)[38;5;208m"; Native = 'DarkYellow'}
    Green    = @{ Ansi = "$([char]27)[38;5;76m";  Native = 'Green'     }
    Cyan     = @{ Ansi = "$([char]27)[38;5;87m";  Native = 'Cyan'      }
    Gray     = @{ Ansi = "$([char]27)[38;5;245m"; Native = 'DarkGray'  }
    DarkGray = @{ Ansi = "$([char]27)[38;5;240m"; Native = 'DarkGray'  }
    White    = @{ Ansi = "$([char]27)[38;5;255m"; Native = 'White'     }
}
$script:AnsiReset = "$([char]27)[0m"

function Out-Color {
    param(
        [Parameter(Mandatory=$true, Position=0)][string]$Text,
        [Parameter(Position=1)][string]$Color = 'White',
        [switch]$NoNewline
    )
    if ($NoColor) {
        if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }
        return
    }
    $entry = $script:ColorMap[$Color]
    if ($script:UseAnsi -and $entry) {
        $line = "$($entry.Ansi)$Text$script:AnsiReset"
        if ($NoNewline) { Write-Host $line -NoNewline } else { Write-Host $line }
    } else {
        $native = if ($entry) { $entry.Native } else { 'White' }
        if ($NoNewline) {
            Write-Host $Text -ForegroundColor $native -NoNewline
        } else {
            Write-Host $Text -ForegroundColor $native
        }
    }
}

# ---- Paths ----------------------------------------------------------
# Use string concat instead of Join-Path because Join-Path with a null
# parent silently swallows the surrounding hashtable entry under
# $ErrorActionPreference='SilentlyContinue'.
$UserDir = if ($env:USERPROFILE) { "$env:USERPROFILE\.claude" } else { '' }
$AppData = if ($env:APPDATA) { "$env:APPDATA\Claude" }
           elseif ($env:USERPROFILE) { "$env:USERPROFILE\AppData\Roaming\Claude" }
           else { '' }

$scannedPaths = @(
    @{ Label = 'Claude Code installed plugins'; Path = "$UserDir\plugins\installed_plugins.json"; Kind = 'file' }
    @{ Label = 'Claude Desktop extensions';     Path = "$AppData\Claude Extensions";              Kind = 'dir'  }
    @{ Label = 'Claude Desktop config';         Path = "$AppData\claude_desktop_config.json";     Kind = 'file' }
    @{ Label = 'Claude skill plugins';          Path = "$AppData\local-agent-mode-sessions";      Kind = 'dir'  }
)

# ---- Banner (ASCII only) -------------------------------------------
$banner = @(
    '  ____   _      _   _   _____    ___  ',
    ' |  _ \ | |    | | | | |_   _|  / _ \ ',
    ' | |_) || |    | | | |   | |   | | | |',
    ' |  __/ | |    | | | |   | |   | | | |',
    ' | |    | |___ | |_| |   | |   | |_| |',
    ' |_|    |_____| \___/    |_|    \___/ '
)

Write-Host ''
Out-Color '              P O W E R E D   B Y' 'DarkGray'
Write-Host ''
foreach ($line in $banner) { Out-Color $line 'Peach' }
Write-Host ''
Out-Color '       S E C U R I T Y  -  C L A U D E S E C  F L E E T  S C A N N E R' 'DarkGray'
Write-Host ''
Out-Color "  Scanning Windows | home: $env:USERPROFILE" 'DarkGray'
Write-Host ''

# ---- Item builder --------------------------------------------------
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

# ---- Scan: Connectors ----------------------------------------------
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

# ---- Scan: Plugins -------------------------------------------------
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

# ---- Render --------------------------------------------------------
function Show-Section ([string]$Title, [System.Collections.IEnumerable]$Items) {
    $count = ($Items | Measure-Object).Count
    if ($count -eq 0) { return }
    Out-Color "  $Title" 'DarkYellow' -NoNewline
    Out-Color "  ($count)" 'DarkGray'
    Out-Color ('  ' + ('-' * 64)) 'DarkGray'
    foreach ($item in $Items) {
        Out-Color '  * ' 'Green' -NoNewline
        Out-Color $item.Name 'White' -NoNewline
        if ($item.Version)   { Out-Color " $($item.Version)" 'DarkGray' -NoNewline }
        if ($item.Publisher) { Out-Color " by $($item.Publisher)" 'DarkGray' -NoNewline }
        if ($item.Subtype)   { Out-Color " [$($item.Subtype)]" 'DarkGray' -NoNewline }
        Write-Host ''
    }
    Write-Host ''
}

Show-Section 'Connectors' $connectors
Show-Section 'Plugins'    $plugins

$total = $connectors.Count + $plugins.Count
if ($total -eq 0) {
    Out-Color '  No Claude connectors or plugins found on this machine.' 'Yellow'
    Write-Host ''
    Out-Color '  Scanned paths:' 'DarkGray'
    foreach ($p in $scannedPaths) {
        $exists = if ($p.Kind -eq 'file') {
            Test-Path -LiteralPath $p.Path -PathType Leaf
        } else {
            Test-Path -LiteralPath $p.Path -PathType Container
        }
        $status = if ($exists) { '[ found ]' } else { '[missing]' }
        $color  = if ($exists) { 'Green' } else { 'DarkGray' }
        Out-Color "    $status " $color -NoNewline
        Out-Color "$($p.Label):" 'White' -NoNewline
        Out-Color " $($p.Path)" 'DarkGray'
    }
    Write-Host ''
    Out-Color '  If you have Claude Desktop or Claude Code installed and this still' 'DarkGray'
    Out-Color '  shows nothing, file an issue at https://github.com/plutosecurity/Claude-Sec/issues' 'DarkGray'
    Write-Host ''
    return
}

Out-Color "  $total" 'White' -NoNewline
Out-Color ' items found.' 'DarkGray'
Write-Host ''
Out-Color '  Search any of these on ' 'DarkGray' -NoNewline
Out-Color 'https://claudesec.pluto.security' 'Cyan'
Out-Color '  to see risk severity, tool-by-tool analysis, and remediation tips.' 'DarkGray'
Write-Host ''
