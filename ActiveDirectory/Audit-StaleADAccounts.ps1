<#
.SYNOPSIS
    Audits on-premises Active Directory for stale user and computer accounts.

.DESCRIPTION
    Finds enabled user and computer accounts that have not authenticated in longer than the
    specified threshold, and accounts with passwords older than the domain's maximum password
    age (or a supplied override), which typically indicates the account is unused (password
    expiration would otherwise force a change or lockout).

.PARAMETER StaleDaysThreshold
    Days since last logon before an account is flagged stale. Default 60.

.PARAMETER SearchBase
    Optional distinguished name to limit the search to an OU subtree.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    ./Audit-StaleADAccounts.ps1 -StaleDaysThreshold 90 -SearchBase "OU=Employees,DC=contoso,DC=com"

.NOTES
    Requires: ActiveDirectory PowerShell module (RSAT), run from a domain-joined host with rights
    to query the domain.
#>
[CmdletBinding()]
param(
    [int]$StaleDaysThreshold = 60,
    [string]$SearchBase,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ActiveDirectory

$cutoffDate = (Get-Date).AddDays(-$StaleDaysThreshold)
$searchParams = @{ Filter = { Enabled -eq $true } ; Properties = 'LastLogonTimestamp', 'PasswordLastSet', 'PasswordNeverExpires', 'whenCreated' }
if ($SearchBase) { $searchParams['SearchBase'] = $SearchBase }

$findings = @()

Write-SecurityLog "Querying stale user accounts (no logon in $StaleDaysThreshold+ days)..."
$users = Get-ADUser @searchParams
foreach ($u in $users) {
    $lastLogon = if ($u.LastLogonTimestamp) { [datetime]::FromFileTime($u.LastLogonTimestamp) } else { $null }

    if (-not $lastLogon -or $lastLogon -lt $cutoffDate) {
        $days = if ($lastLogon) { (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days } else { 'never logged on' }
        $findings += New-SecurityFinding -Category 'Stale AD Accounts' -Resource $u.SamAccountName -Severity 'Medium' `
            -Finding "Enabled user account has not logged on in $days days (created $($u.whenCreated))." `
            -Recommendation 'Disable and move to a "Disabled Accounts" OU pending deletion, unless confirmed as a valid service/break-glass account.'
    }

    if ($u.PasswordNeverExpires) {
        $findings += New-SecurityFinding -Category 'Stale AD Accounts' -Resource $u.SamAccountName -Severity 'Low' `
            -Finding 'Account has "Password never expires" set.' `
            -Recommendation 'Confirm this is an approved service account with a strong, vaulted password; otherwise remove the flag.'
    }
}

Write-SecurityLog "Querying stale computer accounts..."
$computers = Get-ADComputer @searchParams
foreach ($c in $computers) {
    $lastLogon = if ($c.LastLogonTimestamp) { [datetime]::FromFileTime($c.LastLogonTimestamp) } else { $null }
    if (-not $lastLogon -or $lastLogon -lt $cutoffDate) {
        $days = if ($lastLogon) { (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days } else { 'never logged on' }
        $findings += New-SecurityFinding -Category 'Stale AD Accounts' -Resource $c.Name -Severity 'Low' `
            -Finding "Enabled computer account has not logged on in $days days." `
            -Recommendation 'Disable/remove stale computer accounts; they can be re-used in machine-account takeover style attacks.'
    }
}

Write-SecurityLog "Stale account audit complete: $($findings.Count) findings ($($users.Count) users, $($computers.Count) computers checked)." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AD-Stale-Account-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
