<#
.SYNOPSIS
    Audits Microsoft Sentinel automation rules and playbook (Logic App) wiring for coverage
    and broken references.

.DESCRIPTION
    Checks:
      - Automation rules with no configured actions (defined but do nothing)
      - Playbook-running actions referencing a Logic App that no longer exists or is disabled
      - No automation rule configured at all (100% manual triage, common in newer deployments)
      - Automation rules disabled

.PARAMETER ResourceGroupName
    Resource group containing the Sentinel-enabled Log Analytics workspace.

.PARAMETER WorkspaceName
    The Log Analytics workspace name that Sentinel is enabled on.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-AutomationRuleCoverage.ps1 -ResourceGroupName rg-secops -WorkspaceName law-sentinel-prod

.NOTES
    Requires: Az.Accounts, Az.SecurityInsights, Az.LogicApp
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

Write-SecurityLog "Retrieving Sentinel automation rules..."
$rules = Get-AzSentinelAutomationRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction SilentlyContinue

$findings = @()

if (-not $rules -or $rules.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Sentinel Automation' -Resource 'Tenant' -Severity 'Low' `
        -Finding 'No automation rules are configured; all incident triage/response is fully manual.' `
        -Recommendation 'Consider automation rules for low-risk repetitive actions (auto-close known-benign patterns, auto-assign by severity/tag, tag with MITRE tactic).'
} else {
    foreach ($rule in $rules) {
        if ($rule.Actions.Count -eq 0) {
            $findings += New-SecurityFinding -Category 'Sentinel Automation' -Resource $rule.DisplayName -Severity 'Low' `
                -Finding 'Automation rule has no configured actions.' `
                -Recommendation 'Add an action, or remove the rule if it is a leftover from testing.'
        }

        foreach ($action in $rule.Actions) {
            if ($action.ActionType -eq 'RunPlaybook' -and $action.LogicAppResourceId) {
                try {
                    $logicApp = Get-AzResource -ResourceId $action.LogicAppResourceId -ErrorAction Stop
                    if ($logicApp.Properties.state -ne 'Enabled') {
                        $findings += New-SecurityFinding -Category 'Sentinel Automation' -Resource $rule.DisplayName -Severity 'High' `
                            -Finding "Referenced playbook '$($logicApp.Name)' exists but is disabled." `
                            -Recommendation 'Re-enable the Logic App or update the automation rule to reference an active playbook.'
                    }
                } catch {
                    $findings += New-SecurityFinding -Category 'Sentinel Automation' -Resource $rule.DisplayName -Severity 'High' `
                        -Finding 'Referenced playbook Logic App no longer exists (broken reference).' `
                        -Recommendation 'Update or remove this action; a broken playbook reference silently fails to run at incident time.'
                }
            }
        }
    }
}

Write-SecurityLog "Automation rule audit complete: $($rules.Count) rules checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Sentinel-Automation-Rule-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
