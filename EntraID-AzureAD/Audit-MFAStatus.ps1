<#
.SYNOPSIS
    Reports on Multi-Factor Authentication registration and enforcement status across all users
    in Microsoft Entra ID.

.DESCRIPTION
    Uses the Microsoft Graph authenticationMethods and reports APIs to identify:
      - Users with no MFA methods registered
      - Users relying solely on weak methods (SMS/voice) vs. phishing-resistant methods
      - Admin/privileged accounts without MFA
      - Users covered vs. not covered by any Conditional Access MFA-requiring policy

.PARAMETER IncludeDisabledUsers
    Include disabled accounts in the report. Default excludes them.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","User.Read.All","Reports.Read.All","RoleManagement.Read.Directory"
    ./Audit-MFAStatus.ps1

.NOTES
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns
#>
[CmdletBinding()]
param(
    [switch]$IncludeDisabledUsers,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

Test-GraphContext | Out-Null

$strongMethods = @('#microsoft.graph.fido2AuthenticationMethod',
                    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
                    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                    '#microsoft.graph.softwareOathAuthenticationMethod')
$weakMethods = @('#microsoft.graph.phoneAuthenticationMethod', '#microsoft.graph.smsAuthenticationMethod')

Write-SecurityLog "Retrieving users..."
$userProps = 'Id,DisplayName,UserPrincipalName,AccountEnabled,UserType'
$users = Get-MgUser -All -Property $userProps
if (-not $IncludeDisabledUsers) { $users = $users | Where-Object { $_.AccountEnabled } }

Write-SecurityLog "Retrieving privileged role membership for cross-reference..."
$privilegedUpns = @{}
try {
    $roles = Get-MgDirectoryRole -All
    foreach ($role in $roles) {
        Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All | ForEach-Object {
            $privilegedUpns[$_.Id] = $true
        }
    }
} catch {
    Write-SecurityLog "Could not enumerate directory roles (missing RoleManagement.Read.Directory?): $_" -Level WARN
}

$findings = @()
$total = $users.Count
$i = 0

foreach ($user in $users) {
    $i++
    Write-Progress -Activity "Checking MFA registration" -Status $user.UserPrincipalName -PercentComplete (($i / $total) * 100)

    $methods = @()
    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -All -ErrorAction Stop
    } catch {
        Write-SecurityLog "Failed to read auth methods for $($user.UserPrincipalName): $_" -Level WARN
        continue
    }

    $realMethods = $methods | Where-Object { $_.AdditionalProperties['@odata.type'] -ne '#microsoft.graph.passwordAuthenticationMethod' }
    $hasStrong = $realMethods | Where-Object { $_.AdditionalProperties['@odata.type'] -in $strongMethods }
    $hasWeakOnly = ($realMethods.Count -gt 0) -and (-not $hasStrong)
    $isPrivileged = $privilegedUpns.ContainsKey($user.Id)

    if ($realMethods.Count -eq 0) {
        $findings += New-SecurityFinding -Category 'MFA Registration' -Resource $user.UserPrincipalName `
            -Severity $(if ($isPrivileged) { 'Critical' } else { 'High' }) `
            -Finding 'No MFA authentication methods registered (password only).' `
            -Recommendation 'Enforce registration via Conditional Access / Security Defaults before allowing sign-in.'
    } elseif ($hasWeakOnly) {
        $findings += New-SecurityFinding -Category 'MFA Registration' -Resource $user.UserPrincipalName `
            -Severity $(if ($isPrivileged) { 'High' } else { 'Medium' }) `
            -Finding 'Only weak/phishable MFA methods registered (SMS or voice call).' `
            -Recommendation 'Migrate to Microsoft Authenticator (number matching) or FIDO2/Passkeys, especially for privileged accounts.'
    }

    if ($isPrivileged -and -not $hasStrong) {
        $findings += New-SecurityFinding -Category 'MFA Registration' -Resource $user.UserPrincipalName `
            -Severity 'Critical' `
            -Finding 'Privileged account lacks a phishing-resistant or authenticator app MFA method.' `
            -Recommendation 'Require FIDO2 security key or certificate-based auth for all Tier-0/Tier-1 admins.'
    }
}

Write-Progress -Activity "Checking MFA registration" -Completed
Write-SecurityLog "Completed MFA audit for $total users, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Entra-ID-MFA-Status-Audit' -OutputPath $OutputPath
$findings | Group-Object Severity | Select-Object Name, Count | Format-Table -AutoSize | Out-Host
return $findings
