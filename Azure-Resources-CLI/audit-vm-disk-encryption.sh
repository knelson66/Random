#!/usr/bin/env bash
# audit-vm-disk-encryption.sh
#
# Azure CLI equivalent of ../Azure-Resources/Audit-VMDiskEncryption.ps1.
# Checks disk/host encryption, boot diagnostics, missing Defender/Azure Monitor Agent
# extensions, and VM Agent health for every VM in scope.
#
# Usage:
#   ./audit-vm-disk-encryption.sh [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID]

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
log INFO "Scanning subscription $SUB_ID for VM security posture..."

VM_LIST=$(az vm list -o json | jq -r '.[] | "\(.resourceGroup)/\(.name)"')
VM_COUNT=$(echo "$VM_LIST" | grep -c . || true)
log INFO "Found $VM_COUNT VM(s). Evaluating each (this calls several az commands per VM)..."

has_security_extension() {
    # $1 = extension list JSON array. Matches on any field, since the exact property name
    # that carries the extension "type" (e.g. MDE.Windows) varies across az cli versions.
    echo "$1" | jq '
        [.[] | select( (tostring) | test("MDE\\.(Windows|Linux)|AzureMonitor(Windows|Linux)Agent|MicrosoftMonitoringAgent"; "i") )]
        | length
    '
}

while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    rg="${entry%%/*}"
    name="${entry#*/}"
    resource="$rg/$name"
    log INFO "Checking $resource..."

    vm=$(az vm show -g "$rg" -n "$name" -d -o json 2>/dev/null || echo '{}')
    powerState=$(echo "$vm" | jq -r '.powerState // .instanceView.statuses[]?.displayStatus // "unknown"' | head -n1)
    encryptionAtHost=$(echo "$vm" | jq -r '.securityProfile.encryptionAtHost // false')
    bootDiag=$(echo "$vm" | jq -r '.diagnosticsProfile.bootDiagnostics.enabled // false')
    vmAgentVersion=$(echo "$vm" | jq -r '.instanceView.vmAgent.vmAgentVersion // empty')
    vmAgentReady=$(echo "$vm" | jq -r '[.instanceView.vmAgent.statuses[]?.displayStatus] | any(test("Ready"; "i"))' 2>/dev/null || echo "false")

    if [[ "$powerState" != *"running"* ]]; then
        add_finding "VM Security Posture" "$resource" "Informational" \
            "VM power state is '$powerState'; some checks may be incomplete for stopped VMs." "None - informational."
    fi

    adeStatus=$(az vm encryption show -g "$rg" -n "$name" -o json 2>/dev/null | jq -r '.osVolumeEncrypted // .disks[0].encryptionSettings.enabled // "Unknown"' 2>/dev/null || echo "Unknown")
    if [ "$adeStatus" != "Encrypted" ] && [ "$encryptionAtHost" != "true" ]; then
        add_finding "VM Security Posture" "$resource" "Medium" \
            "Neither Azure Disk Encryption nor Encryption at Host is enabled (disks rely on platform-managed encryption only)." \
            "Enable Encryption at Host or ADE for defense-in-depth, especially for VMs handling sensitive data."
    fi

    if [ "$bootDiag" != "true" ]; then
        add_finding "VM Security Posture" "$resource" "Low" "Boot diagnostics is disabled." \
            "Enable boot diagnostics to aid incident response and troubleshooting."
    fi

    extensions=$(az vm extension list -g "$rg" --vm-name "$name" -o json 2>/dev/null || echo '[]')
    secExtCount=$(has_security_extension "$extensions")
    if [ "$secExtCount" -eq 0 ]; then
        add_finding "VM Security Posture" "$resource" "High" \
            "No Microsoft Defender for Endpoint / Azure Monitor Agent extension detected." \
            "Onboard the VM to Microsoft Defender for Cloud / Defender for Endpoint and deploy the Azure Monitor Agent."
    else
        unhealthy=$(echo "$extensions" | jq '[.[] | select(.provisioningState != null and .provisioningState != "Succeeded")] | length')
        if [ "$unhealthy" -gt 0 ]; then
            add_finding "VM Security Posture" "$resource" "Medium" \
                "One or more extensions are not in a 'Succeeded' provisioning state (unhealthy)." \
                "Re-deploy or repair the extension so telemetry/protection is actually functioning."
        fi
    fi

    if [ -z "$vmAgentVersion" ] || [ "$vmAgentReady" != "true" ]; then
        add_finding "VM Security Posture" "$resource" "Medium" \
            "VM Agent is not reporting Ready; extension and patch operations may silently fail." \
            "Investigate and repair the Azure VM Agent installation."
    fi
done <<< "$VM_LIST"

write_report "Azure-VM-Security-Audit-CLI" "$OUTPUT_DIR"
