<#
.SYNOPSIS
    Identifies accounts vulnerable to AS-REP Roasting (Kerberos pre-authentication disabled).

.DESCRIPTION
    Accounts with "Do not require Kerberos preauthentication" enabled will hand out an
    AS-REP that can be cracked offline without any prior authentication, similar in impact to
    Kerberoasting but requiring zero credentials to attempt. This is a DEFENSIVE, read-only audit:
    it enumerates such accounts and their risk factors. It does not request any tickets.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    ./Find-ASREPRoastableAccounts.ps1

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

Write-SecurityLog "Enumerating accounts with Kerberos pre-authentication disabled..."
$accounts = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth, PasswordLastSet, MemberOf, Enabled, LastLogonTimestamp

$privilegedGroupNames = @('Domain Admins', 'Enterprise Admins', 'Administrators')
$findings = @()

foreach ($acct in $accounts) {
    if (-not $acct.Enabled) { continue }

    $memberOfNames = $acct.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }
    $isPrivileged = $memberOfNames | Where-Object { $_ -in $privilegedGroupNames }
    $severity = if ($isPrivileged) { 'Critical' } else { 'High' }

    $findings += New-SecurityFinding -Category 'AS-REP Roasting Exposure' -Resource $acct.SamAccountName -Severity $severity `
        -Finding "Account has 'Do not require Kerberos preauthentication' enabled, allowing an unauthenticated AS-REP hash extraction attempt.$(if ($isPrivileged) { ' Account is also privileged (' + ($isPrivileged -join ', ') + ').' })" `
        -Recommendation 'Disable "Do not require Kerberos preauthentication" unless there is a specific legacy application requirement; if required, ensure a very strong, unique password.'
}

if ($accounts.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'AS-REP Roasting Exposure' -Resource 'Domain' -Severity 'Informational' `
        -Finding 'No accounts found with Kerberos pre-authentication disabled.' -Recommendation 'None.'
}

Write-SecurityLog "AS-REP roasting exposure review complete: $($accounts.Count) accounts found, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AD-ASREPRoasting-Exposure-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
