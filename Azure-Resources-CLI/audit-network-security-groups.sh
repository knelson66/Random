#!/usr/bin/env bash
# audit-network-security-groups.sh
#
# Azure CLI equivalent of ../Azure-Resources/Audit-NetworkSecurityGroups.ps1.
# Flags NSG rules that allow inbound traffic from the Internet/Any on sensitive ports
# (RDP/SSH/SMB/SQL/WinRM/RPC), wildcard "allow everything" rules, and orphaned NSGs.
#
# Usage:
#   ./audit-network-security-groups.sh [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID]
#
# Requires: az cli (logged in via `az login`), jq. If pwsh + the ImportExcel/PSWriteOffice
# PowerShell modules are also available, HTML/Excel/PDF reports are generated automatically
# in addition to CSV/JSON - see lib/common.sh and the repo README.

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
log INFO "Scanning subscription $SUB_ID for Network Security Groups..."

NSG_JSON=$(az network nsg list -o json)
NSG_COUNT=$(echo "$NSG_JSON" | jq 'length')
log INFO "Found $NSG_COUNT NSG(s). Evaluating rules..."

TS=$(date '+%Y-%m-%d %H:%M:%S')

echo "$NSG_JSON" | jq --arg ts "$TS" '
def internetSources: ["*","0.0.0.0/0","Internet","Any"];
def sensitivePorts: {"3389":"RDP","22":"SSH","445":"SMB","1433":"SQL Server","3306":"MySQL","5432":"PostgreSQL","5985":"WinRM HTTP","5986":"WinRM HTTPS","135":"RPC"};

[
  .[] as $nsg |
  (
    (if (($nsg.subnets // []) | length) == 0 and (($nsg.networkInterfaces // []) | length) == 0
     then [{Category:"Network Security Groups", Resource:$nsg.name, Severity:"Low",
            Finding:"NSG is not associated with any subnet or network interface.",
            Recommendation:"Remove orphaned NSGs to reduce configuration drift, or confirm it is intentionally reserved.", Reference:""}]
     else [] end)
    +
    (
      (($nsg.securityRules // []) + ($nsg.defaultSecurityRules // [])) as $rules |
      [ $rules[] |
        select(.access == "Allow" and .direction == "Inbound") as $rule |
        ((if (($rule.sourceAddressPrefixes // []) | length) > 0 then $rule.sourceAddressPrefixes else [$rule.sourceAddressPrefix] end)) as $sources |
        select( ($sources | map(select(. as $s | internetSources | index($s) != null)) | length) > 0 ) |
        ((if (($rule.destinationPortRanges // []) | length) > 0 then $rule.destinationPortRanges else [$rule.destinationPortRange] end)) as $ports |
        (
          [ $ports[] | select(. == "*") |
            {Category:"Network Security Groups", Resource:($nsg.name+"/"+$rule.name), Severity:"Critical",
             Finding:"Rule allows ALL inbound ports from the Internet/Any.",
             Recommendation:"Restrict to specific required ports and source IP ranges immediately.", Reference:""}
          ]
          +
          [ $ports[] as $p |
            sensitivePorts | to_entries[] |
            select(
              ($p == .key) or
              ( ($p | test("^[0-9]+-[0-9]+$")) and
                ((.key|tonumber) >= ($p | split("-")[0] | tonumber)) and
                ((.key|tonumber) <= ($p | split("-")[1] | tonumber)) )
            ) |
            {Category:"Network Security Groups", Resource:($nsg.name+"/"+$rule.name), Severity:"Critical",
             Finding:("Rule allows inbound "+.value+" (port "+.key+") from the Internet/Any."),
             Recommendation:("Restrict source to specific IP ranges/VPN, or use Azure Bastion / Just-In-Time VM access instead of exposing "+.value+"."), Reference:""}
          ]
        )
      ] | flatten
    )
  )
] | flatten | map(. + {Timestamp: $ts}) | .[]
' -c >> "$FINDINGS_FILE"

write_report "Azure-NSG-Audit-CLI" "$OUTPUT_DIR"
