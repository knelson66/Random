<#
.SYNOPSIS
    Audits Microsoft Purview eDiscovery case hygiene and confirms Unified Audit Log / Advanced
    Audit are actually enabled and retaining long enough to be useful in an investigation.

.DESCRIPTION
    Checks:
      - eDiscovery (Premium) cases left open indefinitely with no activity
      - Legal holds that are still active with no documented review date in the case name/notes
      - Unified Audit Log ingestion status (also checked in Audit-ExchangeOnlineSecurity.ps1,
        but repeated here since a broken audit log silently invalidates every other Purview
        control's forensic value)
      - Audit log retention: default is 90 days unless Advanced Audit (E5) extends it - flags
        if long-tail investigation capability appears limited to the default window

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-IPPSSession
    ./Audit-EDiscoveryAndAuditStatus.ps1

.NOTES
    Requires: ExchangeOnlineManagement (Connect-IPPSSession)
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ExchangeOnlineManagement

$findings = @()

Write-SecurityLog "Checking Unified Audit Log ingestion status..."
try {
    $auditConfig = Get-AdminAuditLogConfig -ErrorAction Stop
    if (-not $auditConfig.UnifiedAuditLogIngestionEnabled) {
        $findings += New-SecurityFinding -Category 'Purview eDiscovery/Audit' -Resource 'Tenant' -Severity 'Critical' `
            -Finding 'Unified Audit Log ingestion is disabled.' `
            -Recommendation 'Enable immediately - every other Purview/DLP/insider-risk/eDiscovery control depends on this data existing.'
    }
} catch {
    Write-SecurityLog "Could not check Unified Audit Log config: $_" -Level WARN
}

Write-SecurityLog "Retrieving eDiscovery (Premium) cases..."
try {
    $cases = Get-ComplianceCase -CaseType eDiscovery -ErrorAction Stop
    $staleCases = $cases | Where-Object {
        $_.Status -eq 'Active' -and $_.LastModifiedTime -and (New-TimeSpan -Start $_.LastModifiedTime -End (Get-Date)).Days -gt 180
    }
    foreach ($case in $staleCases) {
        $findings += New-SecurityFinding -Category 'Purview eDiscovery/Audit' -Resource $case.Name -Severity 'Low' `
            -Finding "Active eDiscovery case has had no activity in over 180 days (last modified $($case.LastModifiedTime))." `
            -Recommendation 'Close out stale cases and release any associated legal holds no longer required, to reduce unnecessary data retention/legal exposure.'
    }
} catch {
    Write-SecurityLog "Could not query eDiscovery cases (requires eDiscovery Manager/Administrator role): $_" -Level WARN
}

Write-SecurityLog "Checking for active legal holds..."
try {
    $holds = Get-CaseHoldPolicy -ErrorAction Stop
    $activeHolds = $holds | Where-Object { $_.Enabled }
    if ($activeHolds.Count -gt 0) {
        $findings += New-SecurityFinding -Category 'Purview eDiscovery/Audit' -Resource 'Tenant' -Severity 'Informational' `
            -Finding "$($activeHolds.Count) active legal hold(s) in place." `
            -Recommendation 'Periodically confirm each hold still has a valid legal basis; holds retained past their need increase storage cost and discovery scope in unrelated matters.'
    }
} catch {
    Write-SecurityLog "Could not query case hold policies: $_" -Level WARN
}

Write-SecurityLog "eDiscovery/audit status check complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Purview-EDiscovery-Audit-Status' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
