<#
.SYNOPSIS
    Identifies computer and user accounts configured for unconstrained Kerberos delegation,
    a high-value attack path for domain compromise.

.DESCRIPTION
    An account trusted for unconstrained delegation caches the Kerberos TGT of any user who
    authenticates to it, in memory. Compromising such a host (especially if a Domain Admin
    ever logs into it) can hand an attacker a domain-wide credential. This is a DEFENSIVE,
    read-only audit: it enumerates accounts with this flag set and their risk context. It does
    not perform any coercion or ticket extraction.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    ./Find-UnconstrainedDelegation.ps1

.NOTES
    Requires: ActiveDirectory PowerShell module (RSAT). Read-only / defensive use.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ActiveDirectory

$findings = @()
$privilegedGroupNames = @('Domain Admins', 'Enterprise Admins', 'Administrators')

Write-SecurityLog "Enumerating computer accounts trusted for unconstrained delegation..."
$computers = Get-ADComputer -Filter { TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516 } -Properties TrustedForDelegation, servicePrincipalName, OperatingSystem, Enabled
$dcs = (Get-ADDomainController -Filter *).Name

foreach ($computer in $computers) {
    if (-not $computer.Enabled) { continue }
    if ($computer.Name -in $dcs) {
        # Domain Controllers are trusted for delegation by design; not itself a finding.
        continue
    }

    $findings += New-SecurityFinding -Category 'Unconstrained Delegation' -Resource $computer.Name -Severity 'Critical' `
        -Finding "Non-DC computer account is trusted for unconstrained delegation (OS: $($computer.OperatingSystem))." `
        -Recommendation 'Switch to constrained delegation (or resource-based constrained delegation) scoped to only the specific service/SPN required, or remove delegation entirely if unused.'
}

Write-SecurityLog "Enumerating user accounts trusted for unconstrained delegation..."
$users = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, MemberOf, Enabled

foreach ($user in $users) {
    if (-not $user.Enabled) { continue }

    $memberOfNames = $user.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }
    $isPrivileged = $memberOfNames | Where-Object { $_ -in $privilegedGroupNames }
    $severity = if ($isPrivileged) { 'Critical' } else { 'High' }

    $findings += New-SecurityFinding -Category 'Unconstrained Delegation' -Resource $user.SamAccountName -Severity $severity `
        -Finding "User account is trusted for unconstrained delegation.$(if ($isPrivileged) { ' Account is also privileged (' + ($isPrivileged -join ', ') + ').' })" `
        -Recommendation 'Unconstrained delegation on a user account is almost never required; remove this flag unless there is a documented legacy application dependency.'
}

if ($computers.Count -eq 0 -and $users.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Unconstrained Delegation' -Resource 'Domain' -Severity 'Informational' `
        -Finding 'No non-DC accounts found configured for unconstrained delegation.' -Recommendation 'None.'
}

Write-SecurityLog "Unconstrained delegation review complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AD-Unconstrained-Delegation-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
