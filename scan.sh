#!/usr/bin/env bash
# Claude Connectors Scanner (macOS / Linux)
#
# Lists Claude connectors and plugins installed on this machine.
# Output is printed to the terminal only — nothing leaves your computer.
#
# Look up the listed names on https://claudesec.pluto.security to see
# security risk analysis, tools breakdown, and remediation guidance.
#
# Usage:
#   ./scan.sh                # human-readable output (default)
#   NO_COLOR=1 ./scan.sh     # disable ANSI colors
#
# Optional: install `jq` for prettier metadata (version, publisher).

set -u

# ── Colors ────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  RESET=$'\033[0m'; BOLD=$'\033[1m'; DIM=$'\033[2m'
  PEACH=$'\033[38;5;216m'   # matches the homepage peach background
  ORANGE=$'\033[38;5;208m'
  GREEN=$'\033[38;5;76m'; CYAN=$'\033[38;5;87m'; GRAY=$'\033[38;5;245m'
else
  RESET=''; BOLD=''; DIM=''; PEACH=''; ORANGE=''; GREEN=''; CYAN=''; GRAY=''
fi

# ── Paths ─────────────────────────────────────────────────────────────
case "$(uname -s)" in
  Darwin) APP_DATA="$HOME/Library/Application Support/Claude" ;;
  Linux)  APP_DATA="${XDG_CONFIG_HOME:-$HOME/.config}/Claude" ;;
  *)      APP_DATA="${XDG_CONFIG_HOME:-$HOME/.config}/Claude" ;;
esac
USER_DIR="$HOME/.claude"

# ── Banner ────────────────────────────────────────────────────────────
printf '\n              %sP O W E R E D   B Y%s\n' "$GRAY" "$RESET"
printf '%s' "${PEACH}${BOLD}"
cat <<'BANNER'
██████╗ ██╗     ██╗   ██╗████████╗ ██████╗
██╔══██╗██║     ██║   ██║╚══██╔══╝██╔═══██╗
██████╔╝██║     ██║   ██║   ██║   ██║   ██║
██╔═══╝ ██║     ██║   ██║   ██║   ██║   ██║
██║     ███████╗╚██████╔╝   ██║   ╚██████╔╝
╚═╝     ╚══════╝ ╚═════╝    ╚═╝    ╚═════╝
BANNER
printf '%s\n\n' "${RESET}"
printf '       %sS E C U R I T Y   ·   C L A U D E S E C   F L E E T   S C A N N E R%s\n\n' "$GRAY" "$RESET"
printf '  %sScanning %s · home: %s%s\n\n' "$DIM" "$(uname -s)" "$HOME" "$RESET"

# ── Helpers ───────────────────────────────────────────────────────────
have_jq() { command -v jq >/dev/null 2>&1; }

json_str() {
  [ -f "$1" ] || return 0
  grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null \
    | head -n1 \
    | sed -E "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\1/"
}

print_item() {
  local name="$1" version="$2" publisher="$3" sub="$4"
  local v="" p="" s=""
  [ -n "$version" ]   && v=" ${GRAY}${version}${RESET}"
  [ -n "$publisher" ] && p=" ${DIM}by ${publisher}${RESET}"
  [ -n "$sub" ]       && s=" ${DIM}[${sub}]${RESET}"
  printf '  %s•%s %s%s%s%s%s%s\n' "$GREEN" "$RESET" "$BOLD" "$name" "$RESET" "$v" "$p" "$s"
}

print_section() {
  local title="$1" count="$2"
  printf '  %s%s%s%s  %s(%d)%s\n' "$ORANGE" "$BOLD" "$title" "$RESET" "$GRAY" "$count" "$RESET"
  printf '  %s' "$DIM"
  printf '%.0s─' {1..64}
  printf '%s\n' "$RESET"
}

# ── Scan: Connectors ─────────────────────────────────────────────────
connectors_count=0
connectors_buf=""

EXT_DIR="$APP_DATA/Claude Extensions"
if [ -d "$EXT_DIR" ]; then
  for d in "$EXT_DIR"/*/; do
    [ -d "$d" ] || continue
    manifest="${d}manifest.json"
    name="" ; version="" ; publisher=""
    if [ -f "$manifest" ]; then
      if have_jq; then
        name=$(jq -r '.display_name // .name // empty' "$manifest" 2>/dev/null)
        version=$(jq -r '.version // empty' "$manifest" 2>/dev/null)
        publisher=$(jq -r '(.author.name // .author // empty) | if type=="string" then . else "" end' "$manifest" 2>/dev/null)
      else
        name=$(json_str "$manifest" "display_name")
        [ -z "$name" ] && name=$(json_str "$manifest" "name")
        version=$(json_str "$manifest" "version")
      fi
    fi
    [ -z "$name" ] && name=$(basename "$d")
    connectors_buf="${connectors_buf}${name}|${version}|${publisher}|extension
"
    connectors_count=$((connectors_count + 1))
  done
fi

CFG="$APP_DATA/claude_desktop_config.json"
if [ -f "$CFG" ]; then
  if have_jq; then
    while IFS= read -r srv; do
      [ -n "$srv" ] || continue
      connectors_buf="${connectors_buf}${srv}|||MCP server
"
      connectors_count=$((connectors_count + 1))
    done < <(jq -r '.mcpServers // {} | keys[]' "$CFG" 2>/dev/null)
  fi
fi

# ── Scan: Plugins ────────────────────────────────────────────────────
plugins_count=0
plugins_buf=""

INSTALLED="$USER_DIR/plugins/installed_plugins.json"
if [ -f "$INSTALLED" ]; then
  if have_jq; then
    while IFS=$'\t' read -r key version path; do
      [ -n "$key" ] || continue
      name="${key%@*}"
      mp="${key#*@}"
      [ "$mp" = "$key" ] && mp=""
      plugins_buf="${plugins_buf}${name}|${version}|${mp}|Claude Code
"
      plugins_count=$((plugins_count + 1))
    done < <(jq -r '.plugins // {} | to_entries[] | .key as $k | .value[]? | [$k, (.version // ""), (.installPath // "")] | @tsv' "$INSTALLED" 2>/dev/null)
  else
    while IFS= read -r raw; do
      key="${raw//\"/}"
      name="${key%@*}"
      mp="${key#*@}"
      plugins_buf="${plugins_buf}${name}||${mp}|Claude Code
"
      plugins_count=$((plugins_count + 1))
    done < <(grep -oE '"[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+"' "$INSTALLED" 2>/dev/null | sort -u)
  fi
fi

SESSIONS="$APP_DATA/local-agent-mode-sessions"
if [ -d "$SESSIONS" ]; then
  seen_names=""
  while IFS= read -r manifest; do
    [ -f "$manifest" ] || continue
    name=""; version=""; publisher=""
    if have_jq; then
      name=$(jq -r '.name // empty' "$manifest" 2>/dev/null)
      version=$(jq -r '.version // empty' "$manifest" 2>/dev/null)
      publisher=$(jq -r '(.author.name // .author // empty) | if type=="string" then . else "" end' "$manifest" 2>/dev/null)
    else
      name=$(json_str "$manifest" "name")
      version=$(json_str "$manifest" "version")
    fi
    [ -z "$name" ] && continue
    case "$seen_names" in
      *"|$name|"*) continue ;;
    esac
    seen_names="${seen_names}|${name}|"
    plugins_buf="${plugins_buf}${name}|${version}|${publisher}|skill plugin
"
    plugins_count=$((plugins_count + 1))
  done < <(find "$SESSIONS" -type f -path '*/.claude-plugin/plugin.json' 2>/dev/null)
fi

# ── Render ───────────────────────────────────────────────────────────
total=$((connectors_count + plugins_count))

if [ "$connectors_count" -gt 0 ]; then
  print_section "Connectors" "$connectors_count"
  printf '%s' "$connectors_buf" | while IFS='|' read -r n v p sub; do
    [ -n "$n" ] && print_item "$n" "$v" "$p" "$sub"
  done
  echo
fi

if [ "$plugins_count" -gt 0 ]; then
  print_section "Plugins" "$plugins_count"
  printf '%s' "$plugins_buf" | while IFS='|' read -r n v p sub; do
    [ -n "$n" ] && print_item "$n" "$v" "$p" "$sub"
  done
  echo
fi

if [ "$total" -eq 0 ]; then
  printf '  %sNo Claude connectors or plugins found on this machine.%s\n\n' "$PEACH" "$RESET"
  printf '  %sScanned paths:%s\n' "$GRAY" "$RESET"
  for entry in \
    "file|Claude Code installed plugins|$USER_DIR/plugins/installed_plugins.json" \
    "dir|Claude Desktop extensions|$APP_DATA/Claude Extensions" \
    "file|Claude Desktop config|$APP_DATA/claude_desktop_config.json" \
    "dir|Claude skill plugins|$APP_DATA/local-agent-mode-sessions"
  do
    IFS='|' read -r kind label path <<EOF
$entry
EOF
    if [ "$kind" = "file" ] && [ -f "$path" ]; then
      printf '    %s[ found ]%s %s%s:%s %s%s%s\n' "$GREEN" "$RESET" "$BOLD" "$label" "$RESET" "$DIM" "$path" "$RESET"
    elif [ "$kind" = "dir" ] && [ -d "$path" ]; then
      printf '    %s[ found ]%s %s%s:%s %s%s%s\n' "$GREEN" "$RESET" "$BOLD" "$label" "$RESET" "$DIM" "$path" "$RESET"
    else
      printf '    %s[missing]%s %s%s:%s %s%s%s\n' "$GRAY" "$RESET" "$BOLD" "$label" "$RESET" "$DIM" "$path" "$RESET"
    fi
  done
  printf '\n  %sIf you have Claude Desktop or Claude Code installed and this still%s\n' "$GRAY" "$RESET"
  printf '  %sshows nothing, file an issue at https://github.com/plutosecurity/Claude-Sec/issues%s\n\n' "$GRAY" "$RESET"
  exit 0
fi

printf '  %s%d%s %sitems found.%s\n\n' "$BOLD" "$total" "$RESET" "$GRAY" "$RESET"
printf '  %sSearch any of these on%s %s%shttps://claudesec.pluto.security%s\n' "$GRAY" "$RESET" "$CYAN" "$BOLD" "$RESET"
printf '  %sto see risk severity, tool-by-tool analysis, and remediation tips.%s\n\n' "$GRAY" "$RESET"
