<#
.SYNOPSIS
    Reports Azure Policy compliance state across a subscription, highlighting non-compliant
    resources for security-relevant initiatives (e.g. CIS, NIST, ISO 27001, or a custom
    security baseline initiative).

.DESCRIPTION
    Queries policy states for all assignments (or a specific initiative if -PolicyAssignmentName
    is supplied) and summarizes non-compliant resources by policy definition, so findings can be
    triaged and assigned for remediation.

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER PolicyAssignmentName
    Optional. Limit the report to a specific policy/initiative assignment name.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-AzurePolicyCompliance.ps1 -PolicyAssignmentName "CIS-Microsoft-Azure-Foundations-Benchmark"

.NOTES
    Requires: Az.Accounts, Az.PolicyInsights, Az.Resources
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$PolicyAssignmentName,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.PolicyInsights

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Retrieving policy compliance state for subscription $sub..."

    $states = Get-AzPolicyState -SubscriptionId $sub -Filter "ComplianceState eq 'NonCompliant'"
    if ($PolicyAssignmentName) {
        $states = $states | Where-Object { $_.PolicyAssignmentName -eq $PolicyAssignmentName }
    }

    $grouped = $states | Group-Object PolicyDefinitionName

    foreach ($group in $grouped) {
        $sample = $group.Group | Select-Object -First 1
        $severity = if ($sample.PolicyDefinitionCategory -match 'Security') { 'High' } else { 'Medium' }

        $findings += New-SecurityFinding -Category 'Azure Policy Compliance' -Resource $sample.PolicyAssignmentName -Severity $severity `
            -Finding "$($group.Count) resource(s) non-compliant with policy '$($sample.PolicyDefinitionName)'." `
            -Recommendation 'Review affected resources and remediate via portal "Remediate" action, a remediation task, or manual fix.' `
            -Reference $sample.PolicyDefinitionId
    }

    Write-SecurityLog "$($states.Count) non-compliant resource states across $($grouped.Count) policy definitions in $sub." -Level $(if ($states.Count -gt 0) { 'WARN' } else { 'SUCCESS' })
}

$findings | Export-SecurityReport -Title 'Azure-Policy-Compliance-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
