<#
.SYNOPSIS
    Pulls open Microsoft 365 Defender (XDR) incidents via Microsoft Graph and summarizes
    triage backlog, similar in spirit to the Sentinel incident summary script but for
    tenants using Defender XDR's native incident queue instead of (or alongside) Sentinel.

.DESCRIPTION
    Retrieves incidents from the unified Microsoft Graph security/incidents endpoint and flags:
      - High/Critical severity incidents still in "active"/"inProgress" status past an SLA
      - Incidents with no assigned owner
      - Incidents impacting a large number of assets (broad blast radius, prioritize triage)

.PARAMETER HighSeveritySlaHours
    SLA threshold in hours for High/Critical severity incidents. Default 4.

.PARAMETER LookbackDays
    How many days of incidents to retrieve. Default 30.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "SecurityIncident.Read.All"
    ./Get-DefenderIncidents.ps1

.NOTES
    Requires: Microsoft.Graph.Security
#>
[CmdletBinding()]
param(
    [int]$HighSeveritySlaHours = 4,
    [int]$LookbackDays = 30,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$sinceDate = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-SecurityLog "Retrieving Microsoft 365 Defender incidents since $sinceDate..."

try {
    $incidents = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/incidents?`$filter=createdDateTime ge $sinceDate&`$top=999").value
} catch {
    Write-SecurityLog "Failed to retrieve incidents (requires SecurityIncident.Read.All): $_" -Level ERROR
    return
}

$findings = @()
$openIncidents = $incidents | Where-Object { $_.status -in 'active', 'inProgress' }

foreach ($incident in $openIncidents) {
    $ageHours = if ($incident.createdDateTime) { (New-TimeSpan -Start ([datetime]$incident.createdDateTime) -End (Get-Date).ToUniversalTime()).TotalHours } else { 0 }

    if ($incident.severity -in 'high', 'critical' -and $ageHours -gt $HighSeveritySlaHours) {
        $findings += New-SecurityFinding -Category 'Defender XDR Incidents' -Resource $incident.displayName -Severity 'High' `
            -Finding "$($incident.severity) severity incident has been open for $([math]::Round($ageHours,1)) hours, past the $HighSeveritySlaHours-hour SLA." `
            -Recommendation 'Escalate for immediate triage in the Microsoft Defender portal.' `
            -Reference "https://security.microsoft.com/incidents/$($incident.id)"
    }

    if (-not $incident.assignedTo) {
        $findings += New-SecurityFinding -Category 'Defender XDR Incidents' -Resource $incident.displayName -Severity 'Medium' `
            -Finding "Incident (severity: $($incident.severity)) has no assigned owner." `
            -Recommendation 'Assign an analyst so accountability for triage is clear.' `
            -Reference "https://security.microsoft.com/incidents/$($incident.id)"
    }

    $assetCount = ($incident.alerts | Select-Object -ExpandProperty deviceId -Unique -ErrorAction SilentlyContinue).Count
    if ($assetCount -gt 10) {
        $findings += New-SecurityFinding -Category 'Defender XDR Incidents' -Resource $incident.displayName -Severity 'High' `
            -Finding "Incident spans $assetCount distinct device(s) - broad blast radius." `
            -Recommendation 'Prioritize this incident; wide device impact often indicates lateral movement, a worming threat, or a compromised shared credential.' `
            -Reference "https://security.microsoft.com/incidents/$($incident.id)"
    }
}

Write-SecurityLog "Defender XDR incident summary complete: $($openIncidents.Count) open incidents, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'DefenderXDR-Open-Incidents-Summary' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
