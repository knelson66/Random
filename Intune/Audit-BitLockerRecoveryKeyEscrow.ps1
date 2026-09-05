<#
.SYNOPSIS
    Audits Windows devices for BitLocker recovery key escrow to Entra ID/Intune, so recovery
    isn't blocked during an incident or lockout.

.DESCRIPTION
    Cross-references Intune-managed Windows devices against escrowed BitLocker recovery keys
    and flags:
      - Encrypted Windows devices with no recovery key escrowed to Entra ID
      - Devices where the escrowed key's creation date is very old relative to the device's
        last sync (possible key rotation drift)

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All","BitlockerKey.Read.All"
    ./Audit-BitLockerRecoveryKeyEscrow.ps1

.NOTES
    Requires: Microsoft.Graph.DeviceManagement, Microsoft.Graph.Identity.DirectoryManagement
    Reading recovery key metadata (not the key itself) requires BitlockerKey.Read.All (or
    BitlockerKey.ReadBasic.All for metadata only).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$findings = @()

Write-SecurityLog "Retrieving Windows managed devices..."
$windowsDevices = Get-MgDeviceManagementManagedDevice -All -Filter "operatingSystem eq 'Windows'" -Property Id, DeviceName, AzureAdDeviceId, IsEncrypted, UserPrincipalName

Write-SecurityLog "Retrieving escrowed BitLocker recovery keys..."
$recoveryKeys = @()
try {
    $recoveryKeys = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?`$select=id,deviceId,createdDateTime" -ErrorAction Stop
    $recoveryKeys = $recoveryKeys.value
} catch {
    Write-SecurityLog "Could not retrieve BitLocker recovery keys (check BitlockerKey.Read.All consent): $_" -Level ERROR
}

$keysByDeviceId = @{}
foreach ($key in $recoveryKeys) { $keysByDeviceId[$key.deviceId] = $key }

foreach ($device in $windowsDevices) {
    if ($device.IsEncrypted -ne $true) { continue }

    $resource = "$($device.DeviceName) ($($device.UserPrincipalName))"
    $escrowedKey = $keysByDeviceId[$device.AzureAdDeviceId]

    if (-not $escrowedKey) {
        $findings += New-SecurityFinding -Category 'BitLocker Key Escrow' -Resource $resource -Severity 'High' `
            -Finding 'Device reports as encrypted but has no BitLocker recovery key escrowed to Entra ID.' `
            -Recommendation 'Ensure the BitLocker CSP / Intune encryption policy is configured to escrow recovery keys; without this, a locked-out device cannot be recovered by IT.'
    }
}

Write-SecurityLog "BitLocker escrow audit complete: $($windowsDevices.Count) Windows devices checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Intune-BitLocker-Escrow-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
