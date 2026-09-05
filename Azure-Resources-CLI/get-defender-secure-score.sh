#!/usr/bin/env bash
# get-defender-secure-score.sh
#
# Azure CLI equivalent of ../Azure-Resources/Get-DefenderForCloudSecureScore.ps1.
# Uses `az rest` against the Microsoft Defender for Cloud (Microsoft.Security) REST API
# directly, so it works whether or not the `az security` extension/module is installed.
#
# Usage:
#   ./get-defender-secure-score.sh [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID]

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

if [ -n "$SUBSCRIPTION" ]; then
    log INFO "Setting active subscription to $SUBSCRIPTION"
    az account set --subscription "$SUBSCRIPTION"
fi

SUB_ID=$(az account show --query id -o tsv)
log INFO "Retrieving Defender for Cloud secure score for subscription $SUB_ID..."

TS=$(date '+%Y-%m-%d %H:%M:%S')

SCORE_JSON=$(az rest --method get \
    --url "https://management.azure.com/subscriptions/$SUB_ID/providers/Microsoft.Security/secureScores?api-version=2020-01-01" \
    -o json 2>/dev/null || echo '{"value":[]}')

echo "$SCORE_JSON" | jq --arg ts "$TS" '
    [.value[] | . as $s |
     ($s.properties.score.current // 0) as $current | ($s.properties.score.max // 0) as $max |
     {Category:"Defender for Cloud", Resource:$s.name, Severity:"Informational",
      Finding:("Secure score: "+($current|tostring)+"/"+($max|tostring)+
               (if $max > 0 then " ("+(($current/$max*100)|floor|tostring)+"%)" else "" end)+"."),
      Recommendation:"Track trend over time; target continuous improvement, not a single point-in-time snapshot.",
      Reference:"", Timestamp:$ts}]
    | .[]
' -c >> "$FINDINGS_FILE"

log INFO "Retrieving unhealthy security assessments..."
ASSESS_JSON=$(az rest --method get \
    --url "https://management.azure.com/subscriptions/$SUB_ID/providers/Microsoft.Security/assessments?api-version=2021-06-01" \
    -o json 2>/dev/null || echo '{"value":[]}')

UNHEALTHY_COUNT=$(echo "$ASSESS_JSON" | jq '[.value[] | select(.properties.status.code == "Unhealthy")] | length')
log INFO "$UNHEALTHY_COUNT unhealthy recommendation(s) found."

echo "$ASSESS_JSON" | jq --arg ts "$TS" '
    [.value[] | select(.properties.status.code == "Unhealthy") |
     {Category:"Defender for Cloud",
      Resource:(.properties.displayName // .name),
      Severity:(if .properties.status.severity == "High" then "High"
                elif .properties.status.severity == "Medium" then "Medium"
                else "Low" end),
      Finding:("Unhealthy recommendation: "+(.properties.displayName // .name)+"."),
      Recommendation:"Open in Defender for Cloud recommendations blade for the exact remediation steps and affected resources.",
      Reference:.id, Timestamp:$ts}]
    | .[]
' -c >> "$FINDINGS_FILE"

write_report "Azure-DefenderForCloud-SecureScore-CLI" "$OUTPUT_DIR"
