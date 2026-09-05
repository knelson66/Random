#!/usr/bin/env bash
# connect-azure-cli.sh
#
# Convenience login/subscription-selection helper for the Azure-Resources-CLI scripts.
# Source it (not execute) if you want its subscription selection to affect your current
# shell's `az` context for subsequent commands too:
#   source ./connect-azure-cli.sh
#
# Usage:
#   ./connect-azure-cli.sh                      # az login if needed, show current subscription
#   ./connect-azure-cli.sh -s SUBSCRIPTION_ID    # az login if needed, then switch to it

set -uo pipefail

log() {
    local level="$1"; shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" >&2
}

SUBSCRIPTION=""
while getopts "s:h" opt; do
    case "$opt" in
        s) SUBSCRIPTION="$OPTARG" ;;
        h) echo "Usage: $0 [-s SUBSCRIPTION_ID]"; exit 0 ;;
        *) echo "Usage: $0 [-s SUBSCRIPTION_ID]"; exit 1 ;;
    esac
done

if ! command -v az >/dev/null 2>&1; then
    log ERROR "Azure CLI (az) is not installed. See https://learn.microsoft.com/cli/azure/install-azure-cli"
    exit 1
fi

if ! az account show >/dev/null 2>&1; then
    log INFO "Not logged in - running 'az login'..."
    az login --output none
fi

if [ -n "$SUBSCRIPTION" ]; then
    log INFO "Setting active subscription to $SUBSCRIPTION"
    az account set --subscription "$SUBSCRIPTION"
fi

log INFO "Active account/subscription:"
az account show --query "{User:user.name, Subscription:name, SubscriptionId:id, Tenant:tenantId}" -o table

log INFO "Ready. Run any script in this folder, e.g.: ./audit-network-security-groups.sh"
