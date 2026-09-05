#!/usr/bin/env bash
# invoke-full-security-audit.sh
#
# Orchestrator for the Azure-Resources-CLI scripts - runs all of them (or a chosen subset)
# against the current `az` subscription and writes one consolidated CSV/JSON report on top
# of each script's own report. Mirrors ../Invoke-FullSecurityAudit.ps1 for the PowerShell side.
#
# Usage:
#   ./invoke-full-security-audit.sh [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID]

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

OUTPUT_DIR="./reports"
SUBSCRIPTION=""

while getopts "o:s:h" opt; do
    case "$opt" in
        o) OUTPUT_DIR="$OPTARG" ;;
        s) SUBSCRIPTION="$OPTARG" ;;
        h) echo "Usage: $0 [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID]"; exit 0 ;;
        *) echo "Usage: $0 [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID]"; exit 1 ;;
    esac
done

SCRIPTS=(
    "audit-network-security-groups.sh"
    "audit-storage-account-security.sh"
    "audit-keyvault-security.sh"
    "audit-public-ip-exposure.sh"
    "audit-rbac-assignments.sh"
    "audit-vm-disk-encryption.sh"
    "get-defender-secure-score.sh"
)

CONSOLIDATED_FILE="$(mktemp)"
trap 'rm -f "$CONSOLIDATED_FILE"' EXIT

for script in "${SCRIPTS[@]}"; do
    log INFO "==== Running $script ===="
    args=(-o "$OUTPUT_DIR")
    [ -n "$SUBSCRIPTION" ] && args+=(-s "$SUBSCRIPTION")

    if jsonPath=$("$SCRIPT_DIR/$script" "${args[@]}" | tail -n1) && [ -f "$jsonPath" ]; then
        jq -c '.[]' "$jsonPath" >> "$CONSOLIDATED_FILE" 2>/dev/null || true
    else
        log ERROR "$script did not complete successfully; its findings are not in the consolidated report."
    fi
done

count=$(jq -s 'length' "$CONSOLIDATED_FILE")
log SUCCESS "Full CLI audit run complete: $count total findings across ${#SCRIPTS[@]} script(s)."
if [ "$count" -gt 0 ]; then
    jq -s -r 'group_by(.Severity) | map({Severity: .[0].Severity, Count: length}) | sort_by(
        {"Critical":0,"High":1,"Medium":2,"Low":3,"Informational":4}[.Severity]
    ) | .[] | "\(.Severity): \(.Count)"' "$CONSOLIDATED_FILE"
fi

mkdir -p "$OUTPUT_DIR"
stamp=$(date '+%Y%m%d_%H%M%S')
jq -s '.' "$CONSOLIDATED_FILE" > "${OUTPUT_DIR%/}/Consolidated-Security-Audit-CLI_${stamp}.json"
log SUCCESS "Consolidated JSON written to ${OUTPUT_DIR%/}/Consolidated-Security-Audit-CLI_${stamp}.json"

if command -v pwsh >/dev/null 2>&1; then
    PS_COMMON_MODULE="$SCRIPT_DIR/../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
    log INFO "pwsh found - generating a consolidated HTML/Excel/PDF report too..."
    pwsh -NoLogo -NoProfile -Command "
        \$ErrorActionPreference = 'Stop'
        Import-Module '$PS_COMMON_MODULE' -Force
        \$findings = Get-Content -Raw '${OUTPUT_DIR%/}/Consolidated-Security-Audit-CLI_${stamp}.json' | ConvertFrom-Json
        \$findings | Export-SecurityReport -Title 'Consolidated-Security-Audit-CLI' -OutputPath '$OUTPUT_DIR' -Format Polished
    " 2>&1 | while IFS= read -r line; do echo "  $line" >&2; done || log WARN "Consolidated HTML/Excel/PDF generation failed; the JSON above is still valid."
fi
