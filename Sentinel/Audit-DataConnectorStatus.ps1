<#
.SYNOPSIS
    Audits Microsoft Sentinel data connector connection status against the set of connectors
    that matter most for a Microsoft-centric environment.

.DESCRIPTION
    Checks that key data connectors (Entra ID, Microsoft 365, Defender for Endpoint, Defender
    for Cloud Apps, Defender for Identity, Azure Activity) are actually connected, since a
    disconnected connector silently blinds every analytics rule and hunting query relying on
    that data - one of the most common and hardest-to-notice Sentinel misconfigurations.

.PARAMETER ResourceGroupName
    Resource group containing the Sentinel-enabled Log Analytics workspace.

.PARAMETER WorkspaceName
    The Log Analytics workspace name that Sentinel is enabled on.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-DataConnectorStatus.ps1 -ResourceGroupName rg-secops -WorkspaceName law-sentinel-prod

.NOTES
    Requires: Az.Accounts, Az.SecurityInsights
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

$expectedConnectors = @(
    'AzureActiveDirectory', 'Office365', 'MicrosoftThreatProtection', 'MicrosoftDefenderAdvancedThreatProtection',
    'MicrosoftCloudAppSecurity', 'AzureActivity', 'AzureSecurityCenter'
)

Write-SecurityLog "Retrieving Sentinel data connectors for $WorkspaceName..."
$connectors = Get-AzSentinelDataConnector -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName

$findings = @()
$connectorKinds = $connectors | ForEach-Object { $_.Kind }

foreach ($expected in $expectedConnectors) {
    if ($expected -notin $connectorKinds) {
        $findings += New-SecurityFinding -Category 'Sentinel Data Connectors' -Resource $expected -Severity 'High' `
            -Finding "Connector '$expected' is not configured in this workspace." `
            -Recommendation 'Connect this data source if it is part of your environment - detections and hunting queries relying on it will otherwise silently return no results.'
    }
}

foreach ($connector in $connectors) {
    if ($connector.AdditionalProperties.ContainsKey('dataTypes')) {
        $dataTypes = $connector.AdditionalProperties['dataTypes']
        $disconnectedTypes = $dataTypes.PSObject.Properties | Where-Object { $_.Value.state -eq 'Disabled' }
        foreach ($dt in $disconnectedTypes) {
            $findings += New-SecurityFinding -Category 'Sentinel Data Connectors' -Resource $connector.Kind -Severity 'Medium' `
                -Finding "Data type '$($dt.Name)' under this connector is disabled." `
                -Recommendation 'Enable this log/data type if it is expected to be ingested for detection coverage.'
        }
    }
}

Write-SecurityLog "Data connector audit complete: $($connectors.Count) connectors present, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Sentinel-Data-Connector-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
