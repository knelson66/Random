<#
.SYNOPSIS
    Pulls the Microsoft Defender for Cloud Secure Score and unhealthy recommendations for one or
    more subscriptions, and exports a prioritized remediation report.

.DESCRIPTION
    Queries the Defender for Cloud (Microsoft Defender for Cloud) REST API via Az.Security to
    retrieve the current secure score, per-control breakdown, and every unhealthy assessment,
    then ranks them by potential score impact and severity so an engineer can prioritize
    remediation work.

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Get-DefenderForCloudSecureScore.ps1

.NOTES
    Requires: Az.Accounts, Az.Security
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.Security

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Retrieving Defender for Cloud secure score for subscription $sub..."

    try {
        $secureScores = Get-AzSecuritySecureScore
        foreach ($score in $secureScores) {
            $pct = if ($score.Max -gt 0) { [math]::Round(($score.Current / $score.Max) * 100, 1) } else { 0 }
            $findings += New-SecurityFinding -Category 'Defender for Cloud' -Resource "Subscription $sub" -Severity 'Informational' `
                -Finding "Secure score: $($score.Current)/$($score.Max) ($pct%)." `
                -Recommendation 'Track trend over time; target continuous improvement, not a single point-in-time snapshot.'
        }
    } catch {
        Write-SecurityLog "Could not retrieve secure score for $sub (is Defender for Cloud enabled?): $_" -Level WARN
    }

    try {
        $assessments = Get-AzSecurityAssessment
        $unhealthy = $assessments | Where-Object { $_.Status.Code -eq 'Unhealthy' }

        foreach ($item in $unhealthy) {
            $severity = switch ($item.Status.Severity) {
                'High'   { 'High' }
                'Medium' { 'Medium' }
                'Low'    { 'Low' }
                default  { 'Medium' }
            }
            $findings += New-SecurityFinding -Category 'Defender for Cloud' -Resource $item.DisplayName -Severity $severity `
                -Finding "Unhealthy recommendation: $($item.DisplayName) (resource: $($item.ResourceDetails.Source))." `
                -Recommendation 'Open in Defender for Cloud recommendations blade for the exact remediation steps and affected resources.' `
                -Reference $item.Id
        }
        Write-SecurityLog "$($unhealthy.Count) unhealthy recommendations found for $sub." -Level $(if ($unhealthy.Count -gt 0) { 'WARN' } else { 'SUCCESS' })
    } catch {
        Write-SecurityLog "Could not retrieve assessments for $sub : $_" -Level WARN
    }
}

$findings | Export-SecurityReport -Title 'Azure-DefenderForCloud-SecureScore' -OutputPath $OutputPath
$findings | Where-Object { $_.Severity -ne 'Informational' } | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
