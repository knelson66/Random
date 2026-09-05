<#
.SYNOPSIS
    Summarizes open Microsoft Sentinel incidents by severity, age, and assignment status to
    surface SOC triage backlog and SLA risk.

.DESCRIPTION
    Retrieves all incidents not in a Closed state and flags:
      - High/Critical severity incidents open longer than an SLA threshold
      - Unassigned incidents (nobody owns triage)
      - A large volume of open New-status incidents (queue is not being worked)

.PARAMETER ResourceGroupName
    Resource group containing the Sentinel-enabled Log Analytics workspace.

.PARAMETER WorkspaceName
    The Log Analytics workspace name that Sentinel is enabled on.

.PARAMETER HighSeveritySlaHours
    SLA threshold in hours for High/Critical severity incidents. Default 4.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Get-OpenIncidentsSummary.ps1 -ResourceGroupName rg-secops -WorkspaceName law-sentinel-prod

.NOTES
    Requires: Az.Accounts, Az.SecurityInsights
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$WorkspaceName,
    [int]$HighSeveritySlaHours = 4,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.SecurityInsights

Write-SecurityLog "Retrieving Sentinel incidents from $WorkspaceName..."
$incidents = Get-AzSentinelIncident -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
$openIncidents = $incidents | Where-Object { $_.Status -ne 'Closed' }

$findings = @()

foreach ($incident in $openIncidents) {
    $ageHours = if ($incident.CreatedTimeUtc) { (New-TimeSpan -Start $incident.CreatedTimeUtc -End (Get-Date).ToUniversalTime()).TotalHours } else { 0 }

    if ($incident.Severity -in 'High', 'Critical' -and $ageHours -gt $HighSeveritySlaHours) {
        $findings += New-SecurityFinding -Category 'Sentinel Incidents' -Resource $incident.Title -Severity 'High' `
            -Finding "$($incident.Severity) severity incident has been open for $([math]::Round($ageHours,1)) hours, past the $HighSeveritySlaHours-hour SLA." `
            -Recommendation 'Escalate for immediate triage; document the delay reason if a valid investigation is already in progress.'
    }

    if (-not $incident.Owner -or -not $incident.Owner.AssignedTo) {
        $findings += New-SecurityFinding -Category 'Sentinel Incidents' -Resource $incident.Title -Severity 'Medium' `
            -Finding "Incident (severity: $($incident.Severity)) has no assigned owner." `
            -Recommendation 'Assign an analyst so accountability for triage is clear.'
    }
}

$newStatusCount = ($openIncidents | Where-Object { $_.Status -eq 'New' }).Count
if ($newStatusCount -gt 20) {
    $findings += New-SecurityFinding -Category 'Sentinel Incidents' -Resource 'Tenant' -Severity 'Medium' `
        -Finding "$newStatusCount incidents are still in 'New' status (untouched)." `
        -Recommendation 'Review SOC staffing/automation rules; a growing New-status queue means alerts are not being triaged in a timely manner.'
}

Write-SecurityLog "Incident summary complete: $($openIncidents.Count) open incidents, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Sentinel-Open-Incidents-Summary' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
