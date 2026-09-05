<#
.SYNOPSIS
    Isolates or un-isolates a device onboarded to Microsoft Defender for Endpoint via the
    Microsoft Graph Security API, for use during active incident response.

.DESCRIPTION
    Wraps the Defender for Endpoint "isolate machine" and "unisolate machine" actions exposed
    through Microsoft Graph. Full isolation cuts the device off from the network except for its
    continued communication with Defender for Endpoint, containing lateral movement while
    investigation continues. Requires explicit confirmation before acting because it is disruptive
    to the end user / workload on that device.

.PARAMETER DeviceId
    The Defender for Endpoint machine ID (not the Entra ID device ID) to act on.

.PARAMETER Action
    'Isolate' or 'Unisolate'.

.PARAMETER Comment
    Justification comment recorded against the action (required by the API).

.PARAMETER SelectiveIsolation
    If set, performs selective isolation (keeps Outlook/Teams/Skype connectivity) instead of full isolation.

.EXAMPLE
    Connect-MgGraph -Scopes "Machine.Isolate"
    ./Invoke-DefenderDeviceIsolation.ps1 -DeviceId "abcd1234..." -Action Isolate -Comment "IR-2026-014: suspected ransomware precursor"

.NOTES
    Requires: Microsoft.Graph.Authentication. Required Graph scope: Machine.Isolate.
    THIS IS A DISRUPTIVE ACTION. It will prompt for confirmation unless -Confirm:$false / -Force is used.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$DeviceId,
    [Parameter(Mandatory)][ValidateSet('Isolate', 'Unisolate')][string]$Action,
    [Parameter(Mandatory)][string]$Comment,
    [switch]$SelectiveIsolation,
    [switch]$Force
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$isolationType = if ($SelectiveIsolation) { 'Selective' } else { 'Full' }
$target = "device $DeviceId"
$description = "$Action ($isolationType isolation) on $target"

if (-not $Force -and -not $PSCmdlet.ShouldProcess($target, $description)) {
    Write-SecurityLog "Action cancelled by user." -Level WARN
    return
}

# Defender for Endpoint machine actions are exposed under the /machines endpoint
$actionUri = switch ($Action) {
    'Isolate'   { "https://graph.microsoft.com/v1.0/machines/$DeviceId/isolate" }
    'Unisolate' { "https://graph.microsoft.com/v1.0/machines/$DeviceId/unisolate" }
}

$body = @{ Comment = $Comment }
if ($Action -eq 'Isolate') { $body['IsolationType'] = $isolationType }

Write-SecurityLog "Submitting $Action request for $target..."
try {
    $response = Invoke-MgGraphRequest -Method POST -Uri $actionUri -Body ($body | ConvertTo-Json)
    Write-SecurityLog "$Action request submitted. Action Id: $($response.id). Status: $($response.status)" -Level SUCCESS
    Write-SecurityLog "Poll status with: Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/machineactions/$($response.id)'" -Level INFO
} catch {
    Write-SecurityLog "Failed to submit $Action request: $_" -Level ERROR
    throw
}
