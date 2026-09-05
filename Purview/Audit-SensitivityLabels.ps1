<#
.SYNOPSIS
    Audits Microsoft Purview Information Protection sensitivity labels and their publishing
    policies for coverage and encryption strength.

.DESCRIPTION
    Checks:
      - Sensitivity labels defined but not published to any user/group via a label policy
      - No label configured to apply encryption at all (data can be classified but never protected)
      - No default label set for a publishing policy (relies entirely on manual user choice)
      - Mandatory labeling not enforced anywhere in the tenant
      - Auto-labeling policies present vs. absent (proactive vs. reactive classification)

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-IPPSSession
    ./Audit-SensitivityLabels.ps1

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

if (-not (Get-Command Get-Label -ErrorAction SilentlyContinue)) {
    throw "Get-Label not found. Run Connect-IPPSSession first (Security & Compliance PowerShell)."
}

$findings = @()

Write-SecurityLog "Retrieving sensitivity labels..."
$labels = Get-Label

if (-not $labels -or $labels.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Purview Sensitivity Labels' -Resource 'Tenant' -Severity 'High' `
        -Finding 'No sensitivity labels are defined.' `
        -Recommendation 'Define a label taxonomy (e.g., Public/Internal/Confidential/Highly Confidential) as the foundation for data classification and DLP.'
} else {
    $anyEncrypting = $labels | Where-Object { $_.EncryptionEnabled -eq $true }
    if (-not $anyEncrypting) {
        $findings += New-SecurityFinding -Category 'Purview Sensitivity Labels' -Resource 'Tenant' -Severity 'High' `
            -Finding 'No sensitivity label applies encryption.' `
            -Recommendation 'Configure encryption (with appropriate permissions) on labels covering confidential/restricted content.'
    }
}

Write-SecurityLog "Retrieving label publishing policies..."
$labelPolicies = Get-LabelPolicy

if (-not $labelPolicies -or $labelPolicies.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Purview Sensitivity Labels' -Resource 'Tenant' -Severity 'High' `
        -Finding 'Sensitivity labels exist but no label policy publishes them to any users.' `
        -Recommendation 'Create a label policy to publish labels to the relevant users/groups (or All).'
} else {
    foreach ($policy in $labelPolicies) {
        if (-not $policy.Settings -or ($policy.Settings -notmatch 'mandatory' -or $policy.Settings -match 'mandatory,false')) {
            $findings += New-SecurityFinding -Category 'Purview Sensitivity Labels' -Resource $policy.Name -Severity 'Low' `
                -Finding 'Mandatory labeling does not appear to be enforced by this policy.' `
                -Recommendation 'Consider requiring a label on all documents/emails for policies covering regulated data.'
        }
        if (-not $policy.Settings -or ($policy.Settings -notmatch 'defaultlabelid')) {
            $findings += New-SecurityFinding -Category 'Purview Sensitivity Labels' -Resource $policy.Name -Severity 'Low' `
                -Finding 'No default label is configured for this publishing policy.' `
                -Recommendation 'Set a sensible default (e.g., Internal) so unlabeled content does not default to unclassified/public exposure.'
        }
    }
}

Write-SecurityLog "Checking for auto-labeling policies..."
try {
    $autoLabelPolicies = Get-AutoSensitivityLabelPolicy -ErrorAction Stop
    if (-not $autoLabelPolicies -or $autoLabelPolicies.Count -eq 0) {
        $findings += New-SecurityFinding -Category 'Purview Sensitivity Labels' -Resource 'Tenant' -Severity 'Medium' `
            -Finding 'No auto-labeling policies are configured; classification relies entirely on manual user action.' `
            -Recommendation 'Add auto-labeling policies for content matching known sensitive information types (credit cards, SSNs, etc.) as a safety net.'
    }
} catch {
    Write-SecurityLog "Could not query auto-labeling policies: $_" -Level WARN
}

Write-SecurityLog "Sensitivity label audit complete: $($labels.Count) labels, $($labelPolicies.Count) policies checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Purview-Sensitivity-Label-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
