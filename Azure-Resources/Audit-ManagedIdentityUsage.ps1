<#
.SYNOPSIS
    Inventories user-assigned managed identities and their role assignments to find
    over-privileged or orphaned identities.

.DESCRIPTION
    Checks:
      - User-assigned managed identities not attached to any resource (orphaned, but still
        holding live role assignments/credentials)
      - Managed identities granted Owner or Contributor at subscription scope (should almost
        always be scoped to a specific resource group or resource)
      - Managed identities with more role assignments than distinct resources they're attached
        to (may indicate accumulated, no-longer-needed grants)

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-ManagedIdentityUsage.ps1

.NOTES
    Requires: Az.Accounts, Az.ManagedServiceIdentity, Az.Resources
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.ManagedServiceIdentity

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for user-assigned managed identities..."
    $identities = Get-AzUserAssignedIdentity

    foreach ($identity in $identities) {
        $resource = "$($identity.ResourceGroupName)/$($identity.Name)"

        $usages = Get-AzResource -ODataQuery "identity/type eq 'UserAssigned'" -ErrorAction SilentlyContinue |
            Where-Object { $_.Identity.UserAssignedIdentities.Keys -contains $identity.Id }

        if (-not $usages -or $usages.Count -eq 0) {
            $findings += New-SecurityFinding -Category 'Managed Identity' -Resource $resource -Severity 'Medium' `
                -Finding 'User-assigned managed identity is not attached to any resource.' `
                -Recommendation 'Remove the orphaned identity (and its role assignments) if no longer needed, or attach it to its intended resource.'
        }

        $roleAssignments = Get-AzRoleAssignment -ObjectId $identity.PrincipalId -ErrorAction SilentlyContinue
        foreach ($assignment in $roleAssignments) {
            $isSubScope = $assignment.Scope -match '^/subscriptions/[0-9a-fA-F-]+$'
            if ($isSubScope -and $assignment.RoleDefinitionName -in 'Owner', 'Contributor') {
                $findings += New-SecurityFinding -Category 'Managed Identity' -Resource $resource -Severity 'High' `
                    -Finding "Identity holds '$($assignment.RoleDefinitionName)' at subscription scope." `
                    -Recommendation 'Scope this role assignment down to the specific resource group/resource the identity actually needs to manage.'
            }
        }

        if ($roleAssignments.Count -gt ($usages.Count + 2)) {
            $findings += New-SecurityFinding -Category 'Managed Identity' -Resource $resource -Severity 'Low' `
                -Finding "Identity has $($roleAssignments.Count) role assignment(s) but is only attached to $($usages.Count) resource(s)." `
                -Recommendation 'Review whether all role assignments are still needed; unused grants accumulate over an identity''s lifetime.'
        }
    }
}

Write-SecurityLog "Managed identity audit complete: $($identities.Count) identities checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-ManagedIdentity-Usage-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
