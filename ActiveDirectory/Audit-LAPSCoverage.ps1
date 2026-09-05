<#
.SYNOPSIS
    Audits Windows LAPS (Local Administrator Password Solution) deployment coverage across
    domain-joined computers.

.DESCRIPTION
    Checks:
      - Computers with no LAPS password ever set (ms-Mcs-AdmPwd / msLAPS-Password empty)
      - Computers where the LAPS password has not rotated in longer than the configured policy
        interval would suggest (password aging, possible broken LAPS client/GPO application)
      - Whether the domain schema has been extended for Windows LAPS (native) vs. still only
        supporting the legacy Microsoft LAPS attribute

.PARAMETER StalePasswordDays
    Flag LAPS passwords not rotated within this many days. Default 45.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    ./Audit-LAPSCoverage.ps1

.NOTES
    Requires: ActiveDirectory PowerShell module (RSAT). Reading ms-Mcs-AdmPwd/msLAPS-Password
    requires the caller to have been delegated read access to that attribute (which is itself
    worth auditing separately - see Audit-GPOPermissionsDelegation.ps1 for delegation review).
#>
[CmdletBinding()]
param(
    [int]$StalePasswordDays = 45,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ActiveDirectory

$findings = @()

Write-SecurityLog "Checking whether the Windows LAPS schema extension is present..."
$schemaNC = (Get-ADRootDSE).schemaNamingContext
$windowsLapsAttr = Get-ADObject -SearchBase $schemaNC -Filter "lDAPDisplayName -eq 'msLAPS-Password'" -ErrorAction SilentlyContinue
$legacyLapsAttr = Get-ADObject -SearchBase $schemaNC -Filter "lDAPDisplayName -eq 'ms-Mcs-AdmPwd'" -ErrorAction SilentlyContinue

if (-not $windowsLapsAttr -and -not $legacyLapsAttr) {
    $findings += New-SecurityFinding -Category 'LAPS Coverage' -Resource 'Domain' -Severity 'Critical' `
        -Finding 'Neither the Windows LAPS nor legacy Microsoft LAPS schema attributes are present.' `
        -Recommendation 'Deploy LAPS (native Windows LAPS is built into Windows 11/Server 2022+ and recent updates; otherwise extend the schema and deploy the legacy LAPS CSE/GPO).'
    $findings | Export-SecurityReport -Title 'AD-LAPS-Coverage-Audit' -OutputPath $OutputPath
    return $findings
}

$passwordAttr = if ($windowsLapsAttr) { 'msLAPS-PasswordExpirationTime' } else { 'ms-Mcs-AdmPwdExpirationTime' }
Write-SecurityLog "Using attribute '$passwordAttr' for LAPS coverage checks (Windows LAPS: $([bool]$windowsLapsAttr), Legacy LAPS: $([bool]$legacyLapsAttr))."

Write-SecurityLog "Enumerating enabled, non-DC computer accounts..."
$dcs = (Get-ADDomainController -Filter *).Name
$computers = Get-ADComputer -Filter { Enabled -eq $true } -Properties $passwordAttr, OperatingSystem | Where-Object { $_.Name -notin $dcs }

$noLaps = 0
$stale = 0
foreach ($computer in $computers) {
    $expiration = $computer.$passwordAttr
    if (-not $expiration) {
        $noLaps++
        continue
    }
    try {
        $expirationDate = [datetime]::FromFileTime($expiration)
        $daysUntilExpiry = (New-TimeSpan -Start (Get-Date) -End $expirationDate).Days
        if ($daysUntilExpiry -lt -$StalePasswordDays) {
            $stale++
        }
    } catch { }
}

if ($noLaps -gt 0) {
    $findings += New-SecurityFinding -Category 'LAPS Coverage' -Resource 'Domain' -Severity 'High' `
        -Finding "$noLaps of $($computers.Count) enabled non-DC computer(s) have never had a LAPS password set." `
        -Recommendation 'Verify the LAPS GPO/CSP is applied to all relevant OUs, and that the LAPS client is installed on these machines.'
}

if ($stale -gt 0) {
    $findings += New-SecurityFinding -Category 'LAPS Coverage' -Resource 'Domain' -Severity 'Medium' `
        -Finding "$stale computer(s) have a LAPS password expiration date more than $StalePasswordDays days in the past (rotation appears stalled)." `
        -Recommendation 'Investigate whether these machines are offline/decommissioned, or whether the LAPS scheduled task/policy is failing to run on them.'
}

if ($noLaps -eq 0 -and $stale -eq 0) {
    $findings += New-SecurityFinding -Category 'LAPS Coverage' -Resource 'Domain' -Severity 'Informational' `
        -Finding "All $($computers.Count) checked computers have an active, rotating LAPS password." -Recommendation 'None.'
}

Write-SecurityLog "LAPS coverage audit complete: $($computers.Count) computers checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AD-LAPS-Coverage-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
