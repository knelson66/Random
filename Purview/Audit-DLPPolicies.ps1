<#
.SYNOPSIS
    Audits Microsoft Purview Data Loss Prevention (DLP) policy coverage and enforcement mode
    across Exchange, SharePoint, OneDrive, and Teams.

.DESCRIPTION
    Enumerates all DLP policies and their rules, flagging:
      - Policies in "Test mode" (not actually blocking/warning) left that way long-term
      - No DLP policy covering a workload at all (Exchange/SharePoint/OneDrive/Teams/Endpoint)
      - Rules with no user notification or admin alert configured (silent failures)
      - Disabled policies that appear to cover sensitive information types

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-IPPSSession
    ./Audit-DLPPolicies.ps1

.NOTES
    Requires: ExchangeOnlineManagement (Connect-IPPSSession connects to Security & Compliance PowerShell)
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ExchangeOnlineManagement

if (-not (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)) {
    throw "Get-DlpCompliancePolicy not found. Run Connect-IPPSSession first (Security & Compliance PowerShell)."
}

$findings = @()
$expectedWorkloads = @('Exchange', 'SharePoint', 'OneDriveForBusiness', 'Teams', 'EndpointDevices')

Write-SecurityLog "Retrieving DLP policies..."
$policies = Get-DlpCompliancePolicy

if (-not $policies -or $policies.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Purview DLP' -Resource 'Tenant' -Severity 'Critical' `
        -Finding 'No DLP policies exist in the tenant.' `
        -Recommendation 'Create DLP policies for sensitive information types relevant to your business (PII, PCI, PHI, credentials, etc.).'
} else {
    $coveredWorkloads = @{}

    foreach ($policy in $policies) {
        if ($policy.Mode -eq 'TestWithNotifications' -or $policy.Mode -eq 'TestWithoutNotifications') {
            $findings += New-SecurityFinding -Category 'Purview DLP' -Resource $policy.Name -Severity 'Medium' `
                -Finding "Policy is running in test mode ('$($policy.Mode)') and is not actually enforcing/blocking." `
                -Recommendation 'Review test-mode detection results, then promote to Enable (enforce) if false-positive rate is acceptable.'
        }

        if ($policy.Enabled -eq $false) {
            $findings += New-SecurityFinding -Category 'Purview DLP' -Resource $policy.Name -Severity 'Low' `
                -Finding 'Policy is disabled.' `
                -Recommendation 'Confirm this is intentional; a disabled DLP policy provides no protection.'
        }

        foreach ($workload in $expectedWorkloads) {
            if ($policy."$($workload)Location" -or $policy.Workload -contains $workload) {
                $coveredWorkloads[$workload] = $true
            }
        }

        try {
            $rules = Get-DlpComplianceRule -Policy $policy.Name -ErrorAction Stop
            foreach ($rule in $rules) {
                $hasAction = $rule.BlockAccess -or $rule.NotifyUser -or $rule.GenerateAlert -or $rule.NotifyAllowOverride
                if (-not $hasAction) {
                    $findings += New-SecurityFinding -Category 'Purview DLP' -Resource "$($policy.Name)/$($rule.Name)" -Severity 'Medium' `
                        -Finding 'Rule has no block/notify/alert action configured (detects but takes no visible action).' `
                        -Recommendation 'Add at least a user notification or admin alert action so matches are actionable.'
                }
            }
        } catch {
            Write-SecurityLog "Could not read rules for policy '$($policy.Name)': $_" -Level WARN
        }
    }

    foreach ($workload in $expectedWorkloads) {
        if (-not $coveredWorkloads.ContainsKey($workload)) {
            $findings += New-SecurityFinding -Category 'Purview DLP' -Resource 'Tenant' -Severity 'Medium' `
                -Finding "No DLP policy appears to cover workload: $workload." `
                -Recommendation 'Extend DLP coverage to this workload if sensitive data can flow through it.'
        }
    }
}

Write-SecurityLog "DLP policy audit complete: $($policies.Count) policies checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Purview-DLP-Policy-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
