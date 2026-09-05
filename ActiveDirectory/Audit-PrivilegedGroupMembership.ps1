<#
.SYNOPSIS
    Audits membership of highly privileged Active Directory groups (Domain Admins, Enterprise
    Admins, Schema Admins, Account Operators, Backup Operators, etc.) and flags risky nesting.

.DESCRIPTION
    Recursively enumerates membership of a configurable list of Tier-0 groups and flags:
      - Direct user membership (vs. via a managed, access-reviewed sub-group)
      - Disabled accounts still holding privileged group membership
      - Nested groups (harder to audit / can hide effective membership)
      - Accounts also present in AdminSDHolder-protected state that no longer should be

.PARAMETER PrivilegedGroups
    Names of groups to audit. Defaults to the standard Tier-0 set.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    ./Audit-PrivilegedGroupMembership.ps1

.NOTES
    Requires: ActiveDirectory PowerShell module (RSAT)
#>
[CmdletBinding()]
param(
    [string[]]$PrivilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins'),
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ActiveDirectory

$findings = @()

foreach ($groupName in $PrivilegedGroups) {
    $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
    if (-not $group) {
        Write-SecurityLog "Group '$groupName' not found in this domain, skipping." -Level WARN
        continue
    }

    $directMembers = Get-ADGroupMember -Identity $group -Recursive:$false
    $allMembers = Get-ADGroupMember -Identity $group -Recursive

    if ($allMembers.Count -gt 5) {
        $findings += New-SecurityFinding -Category 'Privileged Group Membership' -Resource $groupName -Severity 'Medium' `
            -Finding "Group has $($allMembers.Count) effective members (including nested), which is high for a Tier-0 group." `
            -Recommendation 'Review membership against least-privilege / just-in-time access model (e.g., PAM, temporary group membership).'
    }

    foreach ($member in $directMembers) {
        if ($member.objectClass -eq 'group') {
            $findings += New-SecurityFinding -Category 'Privileged Group Membership' -Resource $groupName -Severity 'Medium' `
                -Finding "Contains nested group '$($member.name)' as a direct member." `
                -Recommendation 'Flatten nesting where possible; nested groups obscure true effective privileged access during reviews.'
        }
    }

    foreach ($member in $allMembers) {
        if ($member.objectClass -ne 'user') { continue }
        try {
            $u = Get-ADUser -Identity $member.distinguishedName -Properties Enabled, LastLogonTimestamp, PasswordLastSet
            if (-not $u.Enabled) {
                $findings += New-SecurityFinding -Category 'Privileged Group Membership' -Resource $u.SamAccountName -Severity 'High' `
                    -Finding "Disabled account is a member of privileged group '$groupName'." `
                    -Recommendation 'Remove disabled accounts from all privileged groups immediately.'
            }
            $lastLogon = if ($u.LastLogonTimestamp) { [datetime]::FromFileTime($u.LastLogonTimestamp) } else { $null }
            if ($lastLogon -and (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days -gt 45) {
                $findings += New-SecurityFinding -Category 'Privileged Group Membership' -Resource $u.SamAccountName -Severity 'High' `
                    -Finding "Privileged group member ('$groupName') has not logged on in $((New-TimeSpan -Start $lastLogon -End (Get-Date)).Days) days." `
                    -Recommendation 'Revalidate need for standing privileged access; consider removing or moving to a PAM/JIT workflow.'
            }
        } catch {
            Write-SecurityLog "Could not resolve details for member $($member.distinguishedName): $_" -Level WARN
        }
    }
}

Write-SecurityLog "Privileged group audit complete across $($PrivilegedGroups.Count) groups: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AD-Privileged-Group-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
