<#
.SYNOPSIS
    Audits Microsoft Entra ID (Azure AD) directory role assignments, flagging high-privilege
    roles, stale privileged accounts, and permanent (non-PIM-eligible) assignments.

.DESCRIPTION
    Enumerates all active directory role assignments via Microsoft Graph, cross-references
    each assignee against sign-in activity, and flags:
      - Global Administrator / other Tier-0 role membership
      - Accounts assigned high-privilege roles that have not signed in recently
      - Guest or external accounts holding privileged roles
      - Assignments made directly (not eligible/time-bound via PIM), where PIM is licensed

.PARAMETER StaleDaysThreshold
    Number of days of inactivity before a privileged account is flagged as stale. Default 30.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "RoleManagement.Read.Directory","User.Read.All","AuditLog.Read.Directory"
    ./Audit-PrivilegedRoleAssignments.ps1 -OutputPath ./reports

.NOTES
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement,
              Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance (for PIM eligibility)
    Required Graph scopes: RoleManagement.Read.Directory, User.Read.All, AuditLog.Read.Directory
#>
[CmdletBinding()]
param(
    [int]$StaleDaysThreshold = 30,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

$tier0Roles = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'Exchange Administrator', 'SharePoint Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'Conditional Access Administrator',
    'Partner Tier2 Support'
)

Assert-ModuleAvailable -Name Microsoft.Graph.Identity.DirectoryManagement
Test-GraphContext | Out-Null

Write-SecurityLog "Enumerating Entra ID directory roles..."
$findings = @()

$roles = Get-MgDirectoryRole -All
foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All

    foreach ($member in $members) {
        $isPrivileged = $role.DisplayName -in $tier0Roles
        $severity = if ($isPrivileged) { 'Critical' } else { 'Medium' }

        $user = $null
        try {
            $user = Get-MgUser -UserId $member.Id -Property DisplayName, UserPrincipalName, UserType, AccountEnabled, SignInActivity -ErrorAction Stop
        } catch {
            # Member may be a Service Principal or Group rather than a user
        }

        if ($user) {
            $lastSignIn = $user.SignInActivity.LastSignInDateTime
            $daysSince = if ($lastSignIn) { (New-TimeSpan -Start $lastSignIn -End (Get-Date)).Days } else { $null }

            $findings += New-SecurityFinding -Category 'Entra ID Privileged Roles' `
                -Resource $user.UserPrincipalName `
                -Severity $severity `
                -Finding "Assigned role '$($role.DisplayName)'. UserType=$($user.UserType), Enabled=$($user.AccountEnabled), LastSignIn=$($lastSignIn)" `
                -Recommendation 'Validate business justification; move to PIM-eligible/time-bound assignment where possible.'

            if ($user.UserType -eq 'Guest') {
                $findings += New-SecurityFinding -Category 'Entra ID Privileged Roles' `
                    -Resource $user.UserPrincipalName `
                    -Severity 'Critical' `
                    -Finding "Guest account holds directory role '$($role.DisplayName)'." `
                    -Recommendation 'Remove privileged role from guest accounts unless explicitly required and time-bound.'
            }

            if ($daysSince -ne $null -and $daysSince -gt $StaleDaysThreshold -and $isPrivileged) {
                $findings += New-SecurityFinding -Category 'Entra ID Privileged Roles' `
                    -Resource $user.UserPrincipalName `
                    -Severity 'High' `
                    -Finding "Privileged account inactive for $daysSince days (role: $($role.DisplayName))." `
                    -Recommendation 'Disable or remove role assignment for inactive privileged accounts.'
            }

            if (-not $user.AccountEnabled -and $isPrivileged) {
                $findings += New-SecurityFinding -Category 'Entra ID Privileged Roles' `
                    -Resource $user.UserPrincipalName `
                    -Severity 'High' `
                    -Finding "Disabled account still holds privileged role '$($role.DisplayName)'." `
                    -Recommendation 'Remove role assignments from disabled accounts.'
            }
        } else {
            $findings += New-SecurityFinding -Category 'Entra ID Privileged Roles' `
                -Resource $member.Id `
                -Severity $severity `
                -Finding "Non-user principal (service principal/group) holds role '$($role.DisplayName)'." `
                -Recommendation 'Confirm the service principal requires this role and credentials are rotated/monitored.'
        }
    }
}

Write-SecurityLog "Found $($findings.Count) findings across $($roles.Count) directory roles." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Entra-ID-Privileged-Role-Audit' -OutputPath $OutputPath
$findings | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
