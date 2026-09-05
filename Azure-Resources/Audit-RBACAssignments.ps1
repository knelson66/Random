<#
.SYNOPSIS
    Audits Azure RBAC role assignments at the subscription/resource-group scope for
    over-privileged or stale access.

.DESCRIPTION
    Enumerates all role assignments and flags:
      - Owner/Contributor granted at subscription scope to individual users (should generally go
        through groups or PIM-eligible assignment)
      - Classic administrators (Co-Administrator / Service Administrator) still present
      - Role assignments to accounts that no longer exist in Entra ID (orphaned/dangling)
      - Custom roles with wildcard (*) Actions

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-RBACAssignments.ps1

.NOTES
    Requires: Az.Accounts, Az.Resources
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null

$highPrivRoles = @('Owner', 'Contributor', 'User Access Administrator')
$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for RBAC assignments..."

    $assignments = Get-AzRoleAssignment
    foreach ($a in $assignments) {
        if ($a.ObjectType -eq 'Unknown' -or [string]::IsNullOrWhiteSpace($a.DisplayName)) {
            $findings += New-SecurityFinding -Category 'Azure RBAC' -Resource "$($a.RoleDefinitionName) @ $($a.Scope)" -Severity 'Medium' `
                -Finding "Role assignment references a principal ($($a.ObjectId)) that no longer resolves in Entra ID (orphaned)." `
                -Recommendation 'Remove dangling role assignments left behind by deleted users/groups/service principals.'
            continue
        }

        $isSubscriptionScope = $a.Scope -match '^/subscriptions/[0-9a-fA-F-]+$'
        if ($isSubscriptionScope -and $a.RoleDefinitionName -in $highPrivRoles -and $a.ObjectType -eq 'User') {
            $findings += New-SecurityFinding -Category 'Azure RBAC' -Resource $a.DisplayName -Severity 'High' `
                -Finding "User granted '$($a.RoleDefinitionName)' directly at subscription scope." `
                -Recommendation 'Assign high-privilege roles to groups (governed by access reviews) or via PIM-eligible, time-bound assignments instead of standing individual grants.'
        }

        if ($a.RoleDefinitionName -eq 'Owner' -and $a.ObjectType -eq 'ServicePrincipal') {
            $findings += New-SecurityFinding -Category 'Azure RBAC' -Resource $a.DisplayName -Severity 'High' `
                -Finding 'Service principal / managed identity holds Owner role.' `
                -Recommendation 'Scope down to the minimum required role (e.g., Contributor on a specific resource group) for automation identities.'
        }
    }

    try {
        $classicAdmins = Get-AzRoleAssignment -IncludeClassicAdministrators -ErrorAction SilentlyContinue |
            Where-Object { $_.RoleDefinitionName -match 'CoAdministrator|ServiceAdministrator' }
        foreach ($ca in $classicAdmins) {
            $findings += New-SecurityFinding -Category 'Azure RBAC' -Resource $ca.SignInName -Severity 'High' `
                -Finding "Classic subscription administrator role '$($ca.RoleDefinitionName)' is still assigned." `
                -Recommendation 'Migrate classic administrators to modern Azure RBAC (Owner/Contributor) and remove the classic role.'
        }
    } catch {
        Write-SecurityLog "Could not query classic administrators: $_" -Level WARN
    }

    try {
        $customRoles = Get-AzRoleDefinition -Custom
        foreach ($role in $customRoles) {
            if ($role.Actions -contains '*') {
                $findings += New-SecurityFinding -Category 'Azure RBAC' -Resource $role.Name -Severity 'Critical' `
                    -Finding 'Custom role definition grants wildcard (*) Actions, equivalent to Owner-level control-plane access.' `
                    -Recommendation 'Scope custom role Actions to only the operations actually required.'
            }
        }
    } catch {
        Write-SecurityLog "Could not enumerate custom role definitions: $_" -Level WARN
    }
}

Write-SecurityLog "RBAC audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-RBAC-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
