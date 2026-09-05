#!/usr/bin/env bash
# audit-rbac-assignments.sh
#
# Azure CLI equivalent of ../Azure-Resources/Audit-RBACAssignments.ps1.
# Flags direct high-privilege user grants at subscription scope, Owner-level service
# principals, orphaned/dangling assignments, lingering classic administrators, and
# custom roles with wildcard (*) Actions.
#
# Usage:
#   ./audit-rbac-assignments.sh [-o OUTPUT_DIR] [-s SUBSCRIPTION_ID]

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
log INFO "Scanning subscription $SUB_ID for RBAC role assignments..."

ASSIGNMENTS_JSON=$(az role assignment list --all -o json)
ASSIGNMENT_COUNT=$(echo "$ASSIGNMENTS_JSON" | jq 'length')
log INFO "Found $ASSIGNMENT_COUNT role assignment(s). Evaluating..."

TS=$(date '+%Y-%m-%d %H:%M:%S')

echo "$ASSIGNMENTS_JSON" | jq --arg ts "$TS" '
def isSubScope($s): ($s | test("^/subscriptions/[0-9a-fA-F-]+$"));
def highPrivRoles: ["Owner","Contributor","User Access Administrator"];
[
  .[] as $a |
  (if ($a.principalType == null or $a.principalType == "Unknown" or $a.principalName == null) then
    [{Category:"Azure RBAC",Resource:($a.roleDefinitionName+" @ "+$a.scope),Severity:"Medium",
      Finding:"Role assignment references a principal that no longer resolves in Entra ID (orphaned).",
      Recommendation:"Remove dangling role assignments left behind by deleted users/groups/service principals.",Reference:""}]
   else
    (if (isSubScope($a.scope)) and (highPrivRoles | index($a.roleDefinitionName) != null) and ($a.principalType == "User") then
      [{Category:"Azure RBAC",Resource:$a.principalName,Severity:"High",
        Finding:("User granted "+$a.roleDefinitionName+" directly at subscription scope."),
        Recommendation:"Assign high-privilege roles to groups (governed by access reviews) or via PIM-eligible, time-bound assignments instead of standing individual grants.",Reference:""}]
     else [] end)
    +
    (if ($a.roleDefinitionName == "Owner") and ($a.principalType == "ServicePrincipal") then
      [{Category:"Azure RBAC",Resource:$a.principalName,Severity:"High",
        Finding:"Service principal / managed identity holds Owner role.",
        Recommendation:"Scope down to the minimum required role (e.g., Contributor on a specific resource group) for automation identities.",Reference:""}]
     else [] end)
   end)
] | flatten | map(. + {Timestamp: $ts}) | .[]
' -c >> "$FINDINGS_FILE"

log INFO "Checking for lingering classic subscription administrators..."
CLASSIC_JSON=$(az role assignment list --include-classic-administrators --all -o json 2>/dev/null | \
    jq '[.[] | select(.roleDefinitionName | test("CoAdministrator|ServiceAdministrator"; "i"))]')
CLASSIC_COUNT=$(echo "$CLASSIC_JSON" | jq 'length')
if [ "$CLASSIC_COUNT" -gt 0 ]; then
    echo "$CLASSIC_JSON" | jq --arg ts "$TS" '
        .[] | {Category:"Azure RBAC", Resource:(.principalName // .signInName // "unknown"), Severity:"High",
               Finding:("Classic subscription administrator role "+.roleDefinitionName+" is still assigned."),
               Recommendation:"Migrate classic administrators to modern Azure RBAC (Owner/Contributor) and remove the classic role.",
               Reference:"", Timestamp:$ts}
    ' -c >> "$FINDINGS_FILE"
fi

log INFO "Checking custom role definitions for wildcard Actions..."
CUSTOM_ROLES_JSON=$(az role definition list --custom-role-only true -o json 2>/dev/null || echo '[]')
echo "$CUSTOM_ROLES_JSON" | jq --arg ts "$TS" '
    [.[] | select((.permissions[]?.actions // []) | index("*") != null) |
     {Category:"Azure RBAC", Resource:.roleName, Severity:"Critical",
      Finding:"Custom role definition grants wildcard (*) Actions, equivalent to Owner-level control-plane access.",
      Recommendation:"Scope custom role Actions to only the operations actually required.",
      Reference:"", Timestamp:$ts}] | .[]
' -c >> "$FINDINGS_FILE"

write_report "Azure-RBAC-Audit-CLI" "$OUTPUT_DIR"
