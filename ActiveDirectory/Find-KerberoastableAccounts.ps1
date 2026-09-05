<#
.SYNOPSIS
    Identifies accounts vulnerable to Kerberoasting (service accounts with an SPN set) and
    surfaces those with the weakest defenses first.

.DESCRIPTION
    Kerberoasting requests a service ticket for any account with a Service Principal Name (SPN)
    and attempts to crack the ticket offline. This is a DEFENSIVE audit script only: it enumerates
    at-risk accounts and their hygiene (encryption type, password age, privileged group membership,
    gMSA usage) so you can remediate before an attacker or a red-team exercise finds them.
    It does NOT request or dump any service tickets.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    ./Find-KerberoastableAccounts.ps1

.NOTES
    Requires: ActiveDirectory PowerShell module (RSAT). Read-only / defensive use.
    For authorized penetration testing simulation of the actual ticket-request attack, use a
    dedicated, engagement-scoped tool under your rules of engagement - not this script.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ActiveDirectory

Write-SecurityLog "Enumerating accounts with a Service Principal Name (SPN)..."
$spnAccounts = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName, PasswordLastSet, msDS-SupportedEncryptionTypes, MemberOf, Enabled, PasswordNeverExpires

$privilegedGroupNames = @('Domain Admins', 'Enterprise Admins', 'Administrators')
$findings = @()

foreach ($acct in $spnAccounts) {
    if (-not $acct.Enabled) { continue }

    $encTypes = $acct.'msDS-SupportedEncryptionTypes'
    $usesRC4 = (-not $encTypes) -or ($encTypes -band 0x4) -or ($encTypes -eq 0)
    $passwordAgeDays = if ($acct.PasswordLastSet) { (New-TimeSpan -Start $acct.PasswordLastSet -End (Get-Date)).Days } else { -1 }

    $memberOfNames = $acct.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }
    $isPrivileged = $memberOfNames | Where-Object { $_ -in $privilegedGroupNames }

    if ($usesRC4) {
        $findings += New-SecurityFinding -Category 'Kerberoasting Exposure' -Resource $acct.SamAccountName -Severity $(if ($isPrivileged) { 'Critical' } else { 'High' }) `
            -Finding "SPN account supports RC4 (or encryption type unset), making offline cracking of the service ticket significantly easier." `
            -Recommendation 'Set msDS-SupportedEncryptionTypes to AES only (0x18), or migrate to a Group Managed Service Account (gMSA) with a 120+ character random password.'
    }

    if ($passwordAgeDays -gt 365 -or $passwordAgeDays -lt 0) {
        $findings += New-SecurityFinding -Category 'Kerberoasting Exposure' -Resource $acct.SamAccountName -Severity 'High' `
            -Finding "SPN account password age is $passwordAgeDays days (long-lived password increases the value of a cracked hash)." `
            -Recommendation 'Rotate to a long, random password on a regular cadence, or migrate to a gMSA which rotates automatically.'
    }

    if ($isPrivileged) {
        $findings += New-SecurityFinding -Category 'Kerberoasting Exposure' -Resource $acct.SamAccountName -Severity 'Critical' `
            -Finding "SPN account is also a member of a privileged group ($($isPrivileged -join ', ')). This is the highest-value Kerberoasting target profile." `
            -Recommendation 'Never combine an SPN with privileged group membership. Remove the SPN, remove the privilege, or split responsibilities across separate accounts.'
    }

    if ($acct.PasswordNeverExpires -and -not $isPrivileged) {
        $findings += New-SecurityFinding -Category 'Kerberoasting Exposure' -Resource $acct.SamAccountName -Severity 'Medium' `
            -Finding 'SPN account has PasswordNeverExpires set.' `
            -Recommendation 'Combine with a strong random password and regular manual rotation, or convert to a gMSA.'
    }
}

Write-SecurityLog "Kerberoasting exposure review complete: $($spnAccounts.Count) SPN accounts checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AD-Kerberoasting-Exposure-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
