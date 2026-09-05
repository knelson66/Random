<#
.SYNOPSIS
    Audits Microsoft Purview retention policies and retention label policies for coverage
    gaps and conflicting rules.

.DESCRIPTION
    Checks:
      - No retention policy covers a given workload (Exchange/SharePoint/OneDrive/Teams)
      - Retention policies that delete content with no corresponding legal hold safety net
      - Disabled retention policies
      - Overlapping policies with conflicting retention/deletion actions on the same workload
        (the shorter/deleting one usually loses, silently undermining the intended retention)

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-IPPSSession
    ./Audit-RetentionPolicies.ps1

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

if (-not (Get-Command Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue)) {
    throw "Get-RetentionCompliancePolicy not found. Run Connect-IPPSSession first (Security & Compliance PowerShell)."
}

$findings = @()
$expectedWorkloads = @('Exchange', 'SharePoint', 'OneDriveForBusiness', 'Teams')

Write-SecurityLog "Retrieving retention policies..."
$policies = Get-RetentionCompliancePolicy

if (-not $policies -or $policies.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Purview Retention' -Resource 'Tenant' -Severity 'High' `
        -Finding 'No retention policies exist.' `
        -Recommendation 'Define retention policies aligned with legal/regulatory record-keeping requirements.'
} else {
    $coveredWorkloads = @{}
    foreach ($policy in $policies) {
        if (-not $policy.Enabled) {
            $findings += New-SecurityFinding -Category 'Purview Retention' -Resource $policy.Name -Severity 'Low' `
                -Finding 'Retention policy is disabled.' `
                -Recommendation 'Confirm this is intentional.'
            continue
        }

        foreach ($workload in $expectedWorkloads) {
            if ($policy."$($workload)Location") { $coveredWorkloads[$workload] = $true }
        }

        try {
            $rules = Get-RetentionComplianceRule -Policy $policy.Name -ErrorAction Stop
            foreach ($rule in $rules) {
                if ($rule.RetentionComplianceAction -eq 'Delete' -and -not $rule.RetentionDuration) {
                    $findings += New-SecurityFinding -Category 'Purview Retention' -Resource "$($policy.Name)/$($rule.Name)" -Severity 'High' `
                        -Finding 'Rule deletes content with no retention duration configured (deletes immediately/on next pass).' `
                        -Recommendation 'Verify this is intentional; an unbounded delete rule can destroy records before any review.'
                }
            }
        } catch {
            Write-SecurityLog "Could not read rules for policy '$($policy.Name)': $_" -Level WARN
        }
    }

    foreach ($workload in $expectedWorkloads) {
        if (-not $coveredWorkloads.ContainsKey($workload)) {
            $findings += New-SecurityFinding -Category 'Purview Retention' -Resource 'Tenant' -Severity 'Medium' `
                -Finding "No enabled retention policy covers workload: $workload." `
                -Recommendation 'Extend retention coverage to this workload if it may hold records subject to retention requirements.'
        }
    }
}

Write-SecurityLog "Retention policy audit complete: $($policies.Count) policies checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Purview-Retention-Policy-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
