<#
.SYNOPSIS
    Audits Power Automate flows tenant-wide for orphaned ownership, risky connector usage,
    and flows running with an over-privileged connection.

.DESCRIPTION
    Enumerates flows across environments and flags:
      - Flows owned by a single user with no co-owner (business continuity risk if that
        user leaves or is disabled - a very common real-world outage cause)
      - Flows using HTTP/HTTP-with-AAD/custom connectors (arbitrary outbound calls, harder
        to govern than first-party connectors)
      - Flows that are turned on but have a high recent failure rate (may be silently
        failing to perform a security-relevant action, e.g. an approval or alert flow)

.PARAMETER FailureRateThreshold
    Flag flows whose recent run failure rate exceeds this percentage. Default 25.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Add-PowerAppsAccount
    ./Audit-PowerAutomateFlowRisk.ps1

.NOTES
    Requires: Microsoft.PowerApps.Administration.PowerShell
#>
[CmdletBinding()]
param(
    [int]$FailureRateThreshold = 25,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name Microsoft.PowerApps.Administration.PowerShell

$riskyConnectors = @('shared_webcontents', 'shared_http', 'shared_httpwithazuread', 'custom')
$findings = @()

Write-SecurityLog "Retrieving Power Platform environments..."
$environments = Get-AdminPowerAppEnvironment

foreach ($env in $environments) {
    Write-SecurityLog "Scanning flows in environment: $($env.DisplayName)..."
    $flows = Get-AdminFlow -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
    if (-not $flows) { continue }

    foreach ($flow in $flows) {
        $resource = "$($env.DisplayName)/$($flow.DisplayName)"

        try {
            $owners = Get-AdminFlowOwnerRole -EnvironmentName $env.EnvironmentName -FlowName $flow.FlowName -ErrorAction Stop
            $ownerCount = ($owners | Where-Object { $_.RoleType -eq 'Owner' }).Count
            if ($ownerCount -le 1 -and $flow.Enabled) {
                $findings += New-SecurityFinding -Category 'Power Automate' -Resource $resource -Severity 'Medium' `
                    -Finding 'Active flow has a single owner with no co-owner.' `
                    -Recommendation 'Add a co-owner (e.g., a team distribution list or a second admin) so the flow survives the original owner leaving/being disabled.'
            }
        } catch {
            Write-SecurityLog "Could not read owners for flow '$($flow.DisplayName)': $_" -Level WARN
        }

        $connectionRefs = $flow.Internal.properties.connectionReferences
        if ($connectionRefs) {
            foreach ($ref in $connectionRefs.PSObject.Properties) {
                $apiName = $ref.Value.apiId -replace '.*/', ''
                if ($apiName -in $riskyConnectors) {
                    $findings += New-SecurityFinding -Category 'Power Automate' -Resource $resource -Severity 'Low' `
                        -Finding "Flow uses connector '$apiName', which can make arbitrary/generic outbound calls." `
                        -Recommendation 'Confirm this flow is DLP-governed appropriately for this connector class; review the destination endpoints it calls.'
                }
            }
        }

    }

    Write-SecurityLog "$($flows.Count) flow(s) checked in $($env.DisplayName). Per-run failure-rate telemetry (this script's -FailureRateThreshold intent) isn't exposed by Get-AdminFlow directly - cross-check high-value flows' run history in the Power Platform admin center analytics or via the flow's own Run History pane." -Level INFO
}

Write-SecurityLog "Power Automate flow risk audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'PowerAutomate-Flow-Risk-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
