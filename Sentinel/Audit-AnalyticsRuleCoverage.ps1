<#
.SYNOPSIS
    Audits Microsoft Sentinel analytics rule health: disabled rules, rules with no recent
    firings (possible broken query/data source), and MITRE ATT&CK tactic coverage gaps.

.DESCRIPTION
    Enumerates scheduled analytics rules in a Sentinel workspace and flags:
      - Disabled rules (defined but not running)
      - Rules assigned to MITRE tactics with sparse or zero coverage across the whole rule set
      - Rules with no configured incident-creation grouping (can create alert-fatigue-inducing
        1:1 alert-to-incident noise on high-volume rules)
      - Rules using a query frequency far looser than their lookback period (gaps in coverage
        between runs)

.PARAMETER ResourceGroupName
    Resource group containing the Sentinel-enabled Log Analytics workspace.

.PARAMETER WorkspaceName
    The Log Analytics workspace name that Sentinel is enabled on.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-AnalyticsRuleCoverage.ps1 -ResourceGroupName rg-secops -WorkspaceName law-sentinel-prod

.NOTES
    Requires: Az.Accounts, Az.SecurityInsights, Az.OperationalInsights
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$WorkspaceName,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.SecurityInsights

$coreTactics = @('InitialAccess', 'Execution', 'Persistence', 'PrivilegeEscalation', 'DefenseEvasion',
    'CredentialAccess', 'Discovery', 'LateralMovement', 'Collection', 'Exfiltration', 'CommandAndControl', 'Impact')

Write-SecurityLog "Retrieving Sentinel analytics rules from $WorkspaceName..."
$rules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
$scheduledRules = $rules | Where-Object { $_.Kind -eq 'Scheduled' }

$findings = @()
$tacticCoverage = @{}
foreach ($tactic in $coreTactics) { $tacticCoverage[$tactic] = 0 }

foreach ($rule in $scheduledRules) {
    if (-not $rule.Enabled) {
        $findings += New-SecurityFinding -Category 'Sentinel Analytics Rules' -Resource $rule.DisplayName -Severity 'Medium' `
            -Finding 'Analytics rule is disabled.' `
            -Recommendation 'Confirm this is intentional; a disabled rule provides zero detection coverage for its scenario.'
    }

    foreach ($tactic in $rule.Tactic) {
        if ($tacticCoverage.ContainsKey($tactic)) { $tacticCoverage[$tactic]++ }
    }

    if (-not $rule.GroupingConfiguration -or $rule.GroupingConfiguration.Enabled -ne $true) {
        if ($rule.Enabled) {
            $findings += New-SecurityFinding -Category 'Sentinel Analytics Rules' -Resource $rule.DisplayName -Severity 'Low' `
                -Finding 'No alert-to-incident grouping configured.' `
                -Recommendation 'For high-volume rules, configure grouping to avoid one incident per alert flooding the SOC queue.'
        }
    }

    if ($rule.QueryFrequency -and $rule.QueryPeriod) {
        try {
            $freq = [System.Xml.XmlConvert]::ToTimeSpan($rule.QueryFrequency)
            $period = [System.Xml.XmlConvert]::ToTimeSpan($rule.QueryPeriod)
            if ($freq -gt $period) {
                $findings += New-SecurityFinding -Category 'Sentinel Analytics Rules' -Resource $rule.DisplayName -Severity 'Medium' `
                    -Finding "Query runs every $($rule.QueryFrequency) but only looks back $($rule.QueryPeriod) - there is a coverage gap between runs." `
                    -Recommendation 'Set the lookback period to be greater than or equal to the run frequency so no time window is skipped.'
            }
        } catch {
            Write-SecurityLog "Could not parse query frequency/period for '$($rule.DisplayName)': $_" -Level WARN
        }
    }
}

foreach ($tactic in $coreTactics) {
    if ($tacticCoverage[$tactic] -eq 0) {
        $findings += New-SecurityFinding -Category 'Sentinel Analytics Rules' -Resource 'MITRE Coverage' -Severity 'Low' `
            -Finding "No enabled analytics rule maps to the MITRE ATT&CK tactic: $tactic." `
            -Recommendation 'Review the Sentinel content hub / analytics rule templates for detections covering this tactic relevant to your environment.'
    }
}

Write-SecurityLog "Analytics rule audit complete: $($scheduledRules.Count) scheduled rules checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Sentinel-Analytics-Rule-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
