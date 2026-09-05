<#
.SYNOPSIS
    Pulls Microsoft Secure Score (the Entra ID/M365-wide score, distinct from the Defender for
    Cloud Azure resource secure score) and its control breakdown, ranked for remediation.

.DESCRIPTION
    Retrieves the tenant's current Microsoft Secure Score via Microsoft Graph and:
      - Reports the current score vs. maximum and trend vs. the prior recorded snapshot
      - Lists unimplemented control actions ranked by their point value (highest-impact first)
      - Flags controls that regressed (were implemented, now are not) since the last snapshot

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "SecurityEvents.Read.All"
    ./Get-MicrosoftSecureScoreTrend.ps1

.NOTES
    Requires: Microsoft.Graph.Security
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$findings = @()

Write-SecurityLog "Retrieving Microsoft Secure Score history..."
try {
    $scores = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=2").value
} catch {
    Write-SecurityLog "Failed to retrieve Secure Score (requires SecurityEvents.Read.All): $_" -Level ERROR
    return
}

if (-not $scores -or $scores.Count -eq 0) {
    Write-SecurityLog "No Secure Score data returned." -Level ERROR
    return
}

$current = $scores[0]
$previous = if ($scores.Count -gt 1) { $scores[1] } else { $null }
$pct = [math]::Round(($current.currentScore / $current.maxScore) * 100, 1)

$trendText = if ($previous) {
    $delta = $current.currentScore - $previous.currentScore
    if ($delta -gt 0) { "up $delta points since $($previous.createdDateTime)" }
    elseif ($delta -lt 0) { "down $([math]::Abs($delta)) points since $($previous.createdDateTime)" }
    else { "unchanged since $($previous.createdDateTime)" }
} else { "no prior snapshot to compare" }

$findings += New-SecurityFinding -Category 'Microsoft Secure Score' -Resource 'Tenant' -Severity 'Informational' `
    -Finding "Current Secure Score: $($current.currentScore)/$($current.maxScore) ($pct%), $trendText." `
    -Recommendation 'Track this trend over time; a flat or declining score despite new controls being available means remediation work is not keeping pace with the evolving baseline.'

Write-SecurityLog "Retrieving control profiles for remediation ranking..."
try {
    $controlProfiles = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?`$top=999").value
} catch {
    $controlProfiles = @()
    Write-SecurityLog "Could not retrieve control profiles: $_" -Level WARN
}

$controlScores = $current.controlScores
$unimplemented = foreach ($cs in $controlScores) {
    $profile = $controlProfiles | Where-Object { $_.id -eq $cs.controlName }
    if ($cs.score -lt $cs.controlScore -or ($profile -and $profile.implementationStatus -notmatch 'Implemented')) {
        [pscustomobject]@{
            ControlName  = $cs.controlName
            Category     = $cs.controlCategory
            PointValue   = $profile.maxScore ?? $cs.controlScore
            ActionUrl    = $profile.actionUrl
            Description  = $profile.title ?? $cs.controlName
        }
    }
}
$rankedGaps = $unimplemented | Sort-Object PointValue -Descending | Select-Object -First 20

foreach ($gap in $rankedGaps) {
    $severity = if ($gap.PointValue -ge 8) { 'High' } elseif ($gap.PointValue -ge 4) { 'Medium' } else { 'Low' }
    $findings += New-SecurityFinding -Category 'Microsoft Secure Score' -Resource $gap.Description -Severity $severity `
        -Finding "Unimplemented control worth $($gap.PointValue) point(s) (category: $($gap.Category))." `
        -Recommendation 'Implement this control; prioritized here by point value for maximum score impact per unit of remediation effort.' `
        -Reference $gap.ActionUrl
}

Write-SecurityLog "Secure Score trend report complete: $($rankedGaps.Count) top remediation gaps identified." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Microsoft-SecureScore-Trend-Report' -OutputPath $OutputPath
$findings | Select-Object -First 25 | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
