#!/usr/bin/env bash
# audit-public-ip-exposure.sh
#
# Azure CLI equivalent of ../Azure-Resources/Audit-PublicIPExposure.ps1.
# Inventories public IPs, what they're attached to, and cross-references NSG rules on
# attached VM NICs to flag directly internet-exposed VMs.
#
# Usage:
#   ./audit-public-ip-exposure.sh [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID]

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
log INFO "Scanning subscription $SUB_ID for public IP addresses..."

PIPS_JSON=$(az network public-ip list -o json)
PIP_COUNT=$(echo "$PIPS_JSON" | jq 'length')
log INFO "Found $PIP_COUNT public IP(s). Evaluating attachment and exposure..."

count_risky_inbound_rules() {
    # $1 = NSG JSON. Prints the count of Allow/Inbound rules whose source includes Internet/Any.
    echo "$1" | jq '
        [ ((.securityRules // []) + (.defaultSecurityRules // []))[] |
          select(.access == "Allow" and .direction == "Inbound") |
          ((if ((.sourceAddressPrefixes // []) | length) > 0 then .sourceAddressPrefixes else [.sourceAddressPrefix] end)) as $sources |
          select( ($sources | map(select(. as $s | ["*","0.0.0.0/0","Internet","Any"] | index($s) != null)) | length) > 0 )
        ] | length
    '
}

while IFS= read -r pip; do
    name=$(echo "$pip" | jq -r '.name')
    rg=$(echo "$pip" | jq -r '.resourceGroup')
    resource="$rg/$name"
    ip=$(echo "$pip" | jq -r '.ipAddress // "unassigned"')
    sku=$(echo "$pip" | jq -r '.sku.name // "Basic"')
    ipConfigId=$(echo "$pip" | jq -r '.ipConfiguration.id // empty')

    if [ -z "$ipConfigId" ]; then
        add_finding "Public IP Exposure" "$resource" "Low" "Unattached public IP ($ip) - not currently in use." \
            "Release unused public IPs to reduce cost and attack surface."
        continue
    fi

    attachment="Unknown"
    case "$ipConfigId" in
        */networkInterfaces/*)    attachment="Network Interface (VM)" ;;
        */loadBalancers/*)        attachment="Load Balancer" ;;
        */applicationGateways/*)  attachment="Application Gateway" ;;
        */bastionHosts/*)         attachment="Azure Bastion" ;;
        */azureFirewalls/*)       attachment="Azure Firewall" ;;
    esac

    add_finding "Public IP Exposure" "$resource" "Informational" \
        "Public IP $ip (SKU: $sku) attached to: $attachment." \
        "Confirm this resource is intended to be internet-facing; prefer Azure Firewall/App Gateway/Bastion fronting private resources over direct VM NIC public IPs."

    if [ "$attachment" = "Network Interface (VM)" ]; then
        nicId="${ipConfigId%%/ipConfigurations/*}"
        nic=$(az network nic show --ids "$nicId" -o json 2>/dev/null || echo '{}')
        nsgId=$(echo "$nic" | jq -r '.networkSecurityGroup.id // empty')

        if [ -z "$nsgId" ]; then
            add_finding "Public IP Exposure" "$resource" "High" \
                "VM has a direct public IP and its NIC has no NSG attached (relying solely on subnet-level NSG, if any)." \
                "Attach an NSG directly to the NIC/subnet with least-privilege inbound rules."
        else
            nsg=$(az network nsg show --ids "$nsgId" -o json 2>/dev/null || echo '{}')
            riskyCount=$(count_risky_inbound_rules "$nsg")
            if [ "$riskyCount" -gt 0 ]; then
                add_finding "Public IP Exposure" "$resource" "Critical" \
                    "VM has a direct public IP AND its attached NSG allows inbound traffic from the Internet on $riskyCount rule(s)." \
                    "Remove the public IP and place the VM behind a Load Balancer/Bastion, or tighten the NSG immediately."
            fi
        fi
    fi
done < <(echo "$PIPS_JSON" | jq -c '.[]')

write_report "Azure-Public-IP-Exposure-Audit-CLI" "$OUTPUT_DIR"
