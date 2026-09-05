#!/usr/bin/env bash
# common.sh - shared helpers for the Azure CLI (bash + az + jq) audit scripts.
#
# Source this from an audit script:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=lib/common.sh
#   source "$SCRIPT_DIR/lib/common.sh"
#
# Provides:
#   log LEVEL "message"          - timestamped, colorized console logging (INFO/WARN/ERROR/SUCCESS)
#   require_cmd NAME             - exits with a clear message if a required binary is missing
#   add_finding CAT RES SEV FIND [REC] [REF]  - records one standardized finding
#   write_report TITLE OUTDIR    - writes CSV + JSON, then upgrades to HTML/Excel/PDF via
#                                   PowerShell + SecurityToolkitCommon if pwsh is on PATH

set -uo pipefail

log() {
    local level="$1"; shift
    local msg="$*"
    local ts color reset
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    reset=$'\033[0m'
    case "$level" in
        INFO)    color=$'\033[36m' ;;
        WARN)    color=$'\033[33m' ;;
        ERROR)   color=$'\033[31m' ;;
        SUCCESS) color=$'\033[32m' ;;
        *)       color='' ;;
    esac
    printf '%s[%s] [%s] %s%s\n' "$color" "$ts" "$level" "$msg" "$reset" >&2
}

require_cmd() {
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log ERROR "Required command '$cmd' was not found on PATH. Install it before running this script."
            exit 1
        fi
    done
}

require_cmd az jq

# Fail fast with a clear message if not logged in to the Azure CLI.
if ! az account show >/dev/null 2>&1; then
    log ERROR "Not logged in to the Azure CLI. Run 'az login' (and 'az account set --subscription <id>' if needed) first."
    exit 1
fi

COMMON_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$COMMON_SH_DIR/../.." && pwd)"
PS_COMMON_MODULE="$REPO_ROOT/modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"

FINDINGS_FILE="$(mktemp)"
trap 'rm -f "$FINDINGS_FILE"' EXIT
: > "$FINDINGS_FILE"

add_finding() {
    # add_finding <category> <resource> <severity> <finding> [<recommendation>] [<reference>]
    local category="$1" resource="$2" severity="$3" finding="$4" recommendation="${5:-}" reference="${6:-}"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    jq -n \
        --arg ts "$ts" --arg cat "$category" --arg res "$resource" --arg sev "$severity" \
        --arg find "$finding" --arg rec "$recommendation" --arg ref "$reference" \
        '{Timestamp:$ts, Category:$cat, Resource:$res, Severity:$sev, Finding:$find, Recommendation:$rec, Reference:$ref}' \
        >> "$FINDINGS_FILE"
}

write_report() {
    # write_report <title> <output_dir>
    local title="$1" outdir="$2"
    mkdir -p "$outdir"
    local safe_title stamp base count
    safe_title=$(printf '%s' "$title" | tr -c '[:alnum:]-' '_')
    stamp=$(date '+%Y%m%d_%H%M%S')
    base="${outdir%/}/${safe_title}_${stamp}"
    count=$(jq -s 'length' "$FINDINGS_FILE")

    jq -s '.' "$FINDINGS_FILE" > "${base}.json"
    log SUCCESS "JSON report written to ${base}.json"

    jq -s -r '
        ["Timestamp","Category","Resource","Severity","Finding","Recommendation","Reference"] as $cols
        | ([$cols] + (map([.[$cols[]]])))[]
        | @csv
    ' "$FINDINGS_FILE" > "${base}.csv"
    log SUCCESS "CSV report written to ${base}.csv"

    log INFO "Total findings: $count"
    if [ "$count" -gt 0 ]; then
        jq -s -r 'group_by(.Severity) | map({Severity: .[0].Severity, Count: length}) | .[] | "\(.Severity): \(.Count)"' "$FINDINGS_FILE"
    fi

    if command -v pwsh >/dev/null 2>&1 && [ -f "$PS_COMMON_MODULE" ]; then
        log INFO "pwsh found - generating HTML/Excel/PDF from the findings via SecurityToolkitCommon..."
        if pwsh -NoLogo -NoProfile -Command "
            \$ErrorActionPreference = 'Stop'
            Import-Module '$PS_COMMON_MODULE' -Force
            \$findings = Get-Content -Raw '${base}.json' | ConvertFrom-Json
            \$findings | Export-SecurityReport -Title '$title' -OutputPath '$outdir' -Format Polished
        " 2>&1 | while IFS= read -r line; do echo "  $line" >&2; done; then
            log SUCCESS "HTML/Excel/PDF reports written to $outdir (Excel/PDF need ImportExcel/PSWriteOffice - see README)"
        else
            log WARN "pwsh was found but the report upgrade step failed; CSV/JSON above are still valid. See the messages above for details."
        fi
    else
        log WARN "pwsh (PowerShell 7+) not found on PATH - only CSV/JSON were produced."
        log INFO "To get HTML/Excel/PDF from this data, install PowerShell 7 and run:"
        log INFO "  Import-Module '$PS_COMMON_MODULE'; Get-Content -Raw '${base}.json' | ConvertFrom-Json | Export-SecurityReport -Title '$title' -OutputPath '$outdir' -Format Polished"
    fi

    echo "${base}.json"
}
