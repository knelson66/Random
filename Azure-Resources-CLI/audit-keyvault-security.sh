#!/usr/bin/env bash
# audit-keyvault-security.sh
#
# Azure CLI equivalent of ../Azure-Resources/Audit-KeyVaultSecurity.ps1.
# Checks purge protection/soft delete, network ACLs, overly broad access policies,
# expiring secrets, and missing diagnostic logging for every Key Vault in scope.
#
# Usage:
#   ./audit-keyvault-security.sh [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID] [-e EXPIRY_WARNING_DAYS]
#
# Note: requires GNU date (date -d) for expiry calculations, which is the default on Linux
# (including Azure Cloud Shell). On macOS, install coreutils and use gdate, or run this
# under Cloud Shell/WSL instead.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

OUTPUT_DIR="./reports"
SUBSCRIPTION=""
EXPIRY_WARNING_DAYS=30

while getopts "o:s:e:h" opt; do
    case "$opt" in
        o) OUTPUT_DIR="$OPTARG" ;;
        s) SUBSCRIPTION="$OPTARG" ;;
        e) EXPIRY_WARNING_DAYS="$OPTARG" ;;
        h) echo "Usage: $0 [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID] [-e EXPIRY_WARNING_DAYS]"; exit 0 ;;
        *) echo "Usage: $0 [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID] [-e EXPIRY_WARNING_DAYS]"; exit 1 ;;
    esac
done

if [ -n "$SUBSCRIPTION" ]; then
    log INFO "Setting active subscription to $SUBSCRIPTION"
    az account set --subscription "$SUBSCRIPTION"
fi

SUB_ID=$(az account show --query id -o tsv)
log INFO "Scanning subscription $SUB_ID for Key Vaults..."

VAULTS_JSON=$(az keyvault list -o json)
VAULT_COUNT=$(echo "$VAULTS_JSON" | jq 'length')
log INFO "Found $VAULT_COUNT Key Vault(s). Evaluating..."

while IFS= read -r vault; do
    name=$(echo "$vault" | jq -r '.name')
    vaultId=$(echo "$vault" | jq -r '.id')
    purge=$(echo "$vault" | jq -r '.properties.enablePurgeProtection // false')
    softdel=$(echo "$vault" | jq -r '.properties.enableSoftDelete // false')
    defaultAction=$(echo "$vault" | jq -r '.properties.networkAcls.defaultAction // "Allow"')
    rbac=$(echo "$vault" | jq -r '.properties.enableRbacAuthorization // false')

    log INFO "Checking $name..."

    if [ "$purge" != "true" ]; then
        add_finding "Key Vault" "$name" "High" "Purge protection is not enabled." \
            "Enable purge protection to prevent permanent deletion of secrets/keys by a malicious or compromised admin during the retention window."
    fi
    if [ "$softdel" != "true" ]; then
        add_finding "Key Vault" "$name" "High" "Soft delete is not enabled." \
            "Enable soft delete (default in newer vaults; required going forward by Azure)."
    fi
    if [ "$defaultAction" = "Allow" ]; then
        add_finding "Key Vault" "$name" "High" "Network ACL default action is Allow (reachable from all networks)." \
            "Restrict to selected networks/Private Endpoint and set default action to Deny."
    fi

    if [ "$rbac" != "true" ]; then
        add_finding "Key Vault" "$name" "Low" "Vault is using legacy access policies instead of Azure RBAC authorization." \
            "Migrate to RBAC-based permission model for consistency with the rest of Azure IAM and easier auditing via PIM."

        echo "$vault" | jq -c '.properties.accessPolicies[]?' | while IFS= read -r policy; do
            objectId=$(echo "$policy" | jq -r '.objectId')
            hasFull=$(echo "$policy" | jq -r '
                ((.permissions.secrets // []) + (.permissions.keys // []) + (.permissions.certificates // [])) as $all
                | ($all | map(ascii_downcase) | index("all") != null)
            ')
            if [ "$hasFull" = "true" ]; then
                add_finding "Key Vault" "$name" "Medium" "Access policy for principal $objectId grants 'All' permissions." \
                    "Apply least-privilege access policies, or migrate to Azure RBAC-based Key Vault authorization."
            fi
        done
    fi

    SECRETS_JSON=$(az keyvault secret list --vault-name "$name" -o json 2>/dev/null || echo '[]')
    echo "$SECRETS_JSON" | jq -c '.[]' | while IFS= read -r secret; do
        sname=$(echo "$secret" | jq -r '.name')
        expires=$(echo "$secret" | jq -r '.attributes.expires // empty')
        if [ -z "$expires" ]; then
            add_finding "Key Vault" "$name/$sname" "Low" "Secret has no expiration date set." \
                "Set an expiration date and rotation policy for all secrets."
        else
            expiry_epoch=$(date -d "$expires" +%s 2>/dev/null || echo "")
            if [ -n "$expiry_epoch" ]; then
                now_epoch=$(date +%s)
                days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                if [ "$days_left" -lt 0 ]; then
                    add_finding "Key Vault" "$name/$sname" "Medium" "Secret expired $(( -days_left )) days ago." \
                        "Rotate or remove the expired secret."
                elif [ "$days_left" -le "$EXPIRY_WARNING_DAYS" ]; then
                    add_finding "Key Vault" "$name/$sname" "High" "Secret expires in $days_left days." \
                        "Rotate before expiry to avoid application outage."
                fi
            fi
        fi
    done

    DIAG_JSON=$(az monitor diagnostic-settings list --resource "$vaultId" -o json 2>/dev/null || echo '{"value":[]}')
    DIAG_COUNT=$(echo "$DIAG_JSON" | jq '.value | length')
    if [ "$DIAG_COUNT" -eq 0 ]; then
        add_finding "Key Vault" "$name" "Medium" "No diagnostic settings configured (no audit log export)." \
            "Send AuditEvent logs to a Log Analytics workspace / SIEM for access monitoring."
    fi
done < <(echo "$VAULTS_JSON" | jq -c '.[]')

write_report "Azure-KeyVault-Audit-CLI" "$OUTPUT_DIR"
