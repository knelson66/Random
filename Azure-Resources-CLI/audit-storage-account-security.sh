#!/usr/bin/env bash
# audit-storage-account-security.sh
#
# Azure CLI equivalent of ../Azure-Resources/Audit-StorageAccountSecurity.ps1.
# Flags public blob access, missing HTTPS/TLS enforcement, shared key auth, open network
# firewall defaults, and missing soft delete/versioning/CMK on every storage account.
#
# Usage:
#   ./audit-storage-account-security.sh [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID]

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
log INFO "Scanning subscription $SUB_ID for storage accounts..."

ENRICHED_FILE="$(mktemp)"
trap 'rm -f "$ENRICHED_FILE"' EXIT

ACCOUNT_COUNT=0
while IFS= read -r row; do
    ACCOUNT_COUNT=$((ACCOUNT_COUNT + 1))
    name=$(echo "$row" | jq -r '.name')
    rg=$(echo "$row" | jq -r '.resourceGroup')
    log INFO "Checking blob service properties for $rg/$name..."
    blobprops=$(az storage account blob-service-properties show --account-name "$name" --resource-group "$rg" -o json 2>/dev/null || echo '{}')
    echo "$row" | jq -c --argjson bp "$blobprops" '. + {blobServiceProperties: $bp}'
done < <(az storage account list -o json | jq -c '.[]') > "$ENRICHED_FILE"

log INFO "Evaluating $ACCOUNT_COUNT storage account(s)..."
TS=$(date '+%Y-%m-%d %H:%M:%S')

jq -s --arg ts "$TS" '
[
  .[] as $sa | ($sa.resourceGroup + "/" + $sa.name) as $res |
  (if $sa.allowBlobPublicAccess != false then
    [{Category:"Storage Account",Resource:$res,Severity:"High",
      Finding:"Public blob access is allowed at the account level.",
      Recommendation:"Set AllowBlobPublicAccess to false unless a specific container requires anonymous read access.",Reference:""}]
   else [] end)
  + (if $sa.enableHttpsTrafficOnly != true then
    [{Category:"Storage Account",Resource:$res,Severity:"Critical",
      Finding:"Secure transfer (HTTPS-only) is not enforced.",
      Recommendation:"Enable \"Secure transfer required\" to prevent plaintext HTTP access.",Reference:""}]
   else [] end)
  + (if ($sa.minimumTlsVersion // "") != "TLS1_2" then
    [{Category:"Storage Account",Resource:$res,Severity:"High",
      Finding:("Minimum TLS version is set to "+($sa.minimumTlsVersion // "unset")+" instead of TLS1_2."),
      Recommendation:"Raise minimum TLS version to 1.2.",Reference:""}]
   else [] end)
  + (if $sa.allowSharedKeyAccess != false then
    [{Category:"Storage Account",Resource:$res,Severity:"Medium",
      Finding:"Shared Key (access key) authorization is enabled.",
      Recommendation:"Disable shared key access and require Azure AD (Entra ID) authorization where application support allows it.",Reference:""}]
   else [] end)
  + (if ($sa.networkRuleSet.defaultAction // "") == "Allow" then
    [{Category:"Storage Account",Resource:$res,Severity:"High",
      Finding:"Network firewall default action is Allow (accessible from all networks).",
      Recommendation:"Set default action to Deny and add explicit VNet/IP allow rules or use Private Endpoints.",Reference:""}]
   else [] end)
  + (if ($sa.blobServiceProperties.deleteRetentionPolicy.enabled // false) != true then
    [{Category:"Storage Account",Resource:$res,Severity:"Medium",
      Finding:"Blob soft delete is not enabled.",
      Recommendation:"Enable soft delete (and versioning) to protect against accidental or malicious deletion/ransomware.",Reference:""}]
   else [] end)
  + (if ($sa.blobServiceProperties.isVersioningEnabled // false) != true then
    [{Category:"Storage Account",Resource:$res,Severity:"Low",
      Finding:"Blob versioning is not enabled.",
      Recommendation:"Enable versioning for tamper/ransomware recovery on critical data.",Reference:""}]
   else [] end)
  + (if ($sa.encryption.keySource // "") != "Microsoft.Keyvault" then
    [{Category:"Storage Account",Resource:$res,Severity:"Low",
      Finding:"Storage account is not using customer-managed keys (CMK) via Key Vault for encryption at rest.",
      Recommendation:"Consider CMK for regulatory/compliance requirements needing key control and rotation.",Reference:""}]
   else [] end)
] | flatten | map(. + {Timestamp: $ts}) | .[]
' "$ENRICHED_FILE" -c >> "$FINDINGS_FILE"

write_report "Azure-Storage-Account-Audit-CLI" "$OUTPUT_DIR"
