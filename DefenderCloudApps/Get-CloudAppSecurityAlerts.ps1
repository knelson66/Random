<#
.SYNOPSIS
    Pulls open Microsoft Defender for Cloud Apps alerts and reports on triage backlog and
    severity distribution.

.DESCRIPTION
    Calls the Defender for Cloud Apps alerts API for open alerts and flags:
      - High-severity alerts open longer than a threshold (SLA breach risk)
      - A large volume of open alerts overall (signal is being generated but not triaged)
      - Alerts clustered on a small number of users (possible ongoing compromise worth
        prioritizing over one-off alerts spread across many users)

.PARAMETER TenantUrl
    Your Defender for Cloud Apps tenant URL, e.g. "contoso.us.portal.cloudappsecurity.com".

.PARAMETER ApiToken
    An MDA API token (Settings > System > API tokens).

.PARAMETER StaleHighSeverityHours
    Flag open High-severity alerts older than this many hours. Default 24.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    ./Get-CloudAppSecurityAlerts.ps1 -TenantUrl "contoso.us.portal.cloudappsecurity.com" -ApiToken $env:MDA_API_TOKEN

.NOTES
    Requires: an MDA API token. See https://learn.microsoft.com/defender-cloud-apps/api-authentication
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantUrl,
    [Parameter(Mandatory)][string]$ApiToken,
    [int]$StaleHighSeverityHours = 24,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

$headers = @{ Authorization = "Token $ApiToken" }
$base = "https://$TenantUrl/api/v1"
$findings = @()

Write-SecurityLog "Retrieving open Defender for Cloud Apps alerts..."
$body = @{ filters = @{ resolutionStatus = @{ eq = 0 } } } | ConvertTo-Json -Depth 5
try {
    $response = Invoke-RestMethod -Uri "$base/alerts/" -Headers $headers -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop
} catch {
    Write-SecurityLog "Failed to retrieve alerts: $_" -Level ERROR
    return
}

$alerts = $response.data
if (-not $alerts -or $alerts.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Defender for Cloud Apps Alerts' -Resource 'Tenant' -Severity 'Informational' `
        -Finding 'No open alerts.' -Recommendation 'None.'
} else {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $highSeverity = $alerts | Where-Object { $_.severity_value -eq 3 -or $_.title -match 'High' }

    foreach ($alert in $highSeverity) {
        $ageHours = if ($alert.timestamp) { ($now - ($alert.timestamp / 1000)) / 3600 } else { 0 }
        if ($ageHours -gt $StaleHighSeverityHours) {
            $alertResource = if ($alert.entity.user.email) { $alert.entity.user.email } else { $alert.title }
            $findings += New-SecurityFinding -Category 'Defender for Cloud Apps Alerts' -Resource $alertResource -Severity 'High' `
                -Finding "High-severity alert '$($alert.title)' has been open for $([math]::Round($ageHours,1)) hours." `
                -Recommendation 'Triage immediately; high-severity MDA alerts typically indicate active exfiltration, impossible travel, or malware OAuth activity.'
        }
    }

    if ($alerts.Count -gt 50) {
        $findings += New-SecurityFinding -Category 'Defender for Cloud Apps Alerts' -Resource 'Tenant' -Severity 'Medium' `
            -Finding "$($alerts.Count) open alerts in total." `
            -Recommendation 'Review policy tuning (thresholds, scopes) to reduce noise, or add analyst capacity to keep pace with alert volume.'
    }

    $byUser = $alerts | Where-Object { $_.entity.user.email } | Group-Object { $_.entity.user.email } | Sort-Object Count -Descending | Select-Object -First 5
    foreach ($u in $byUser) {
        if ($u.Count -ge 3) {
            $findings += New-SecurityFinding -Category 'Defender for Cloud Apps Alerts' -Resource $u.Name -Severity 'High' `
                -Finding "$($u.Count) open alerts are associated with this single user." `
                -Recommendation 'Prioritize this user for investigation - a cluster of alerts on one identity is a stronger compromise signal than isolated alerts.'
        }
    }
}

Write-SecurityLog "Alert triage summary complete: $($alerts.Count) open alerts, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'DefenderCloudApps-Alert-Triage' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
