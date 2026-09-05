<#
.SYNOPSIS
    Produces a detailed, per-setting breakdown of why each non-compliant Intune-managed device
    is failing compliance, rather than just the pass/fail summary.

.DESCRIPTION
    For every device in a Not Compliant state, retrieves the individual compliance policy
    setting states so an admin can see exactly which control is failing (e.g., encryption
    disabled, jailbroken/rooted, password policy not met) instead of re-deriving it manually
    per device in the console.

.PARAMETER StaleSyncDaysThreshold
    Also flag devices whose last check-in is older than this many days. Default 14.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All"
    ./Get-NonCompliantDevices.ps1

.NOTES
    Requires: Microsoft.Graph.DeviceManagement
#>
[CmdletBinding()]
param(
    [int]$StaleSyncDaysThreshold = 14,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$findings = @()

Write-SecurityLog "Retrieving non-compliant and stale managed devices..."
$devices = Get-MgDeviceManagementManagedDevice -All -Property Id, DeviceName, ComplianceState, OperatingSystem, LastSyncDateTime, UserPrincipalName, JailBroken, IsEncrypted, ManagementAgent

foreach ($device in $devices) {
    $resource = "$($device.DeviceName) ($($device.UserPrincipalName))"
    $daysSinceSync = if ($device.LastSyncDateTime) { (New-TimeSpan -Start $device.LastSyncDateTime -End (Get-Date)).Days } else { $null }

    if ($device.ComplianceState -eq 'noncompliant') {
        try {
            $settingStates = Get-MgDeviceManagementManagedDeviceDeviceCompliancePolicyState -ManagedDeviceId $device.Id -ErrorAction Stop
            $failing = $settingStates | Where-Object { $_.State -eq 'nonCompliant' }
            foreach ($fail in $failing) {
                $findings += New-SecurityFinding -Category 'Intune Non-Compliant Device' -Resource $resource -Severity 'High' `
                    -Finding "Failing compliance policy: $($fail.DisplayName)." `
                    -Recommendation 'Remediate the specific failing setting on the device, or via the assigned configuration/compliance profile.'
            }
            if ($failing.Count -eq 0) {
                $findings += New-SecurityFinding -Category 'Intune Non-Compliant Device' -Resource $resource -Severity 'High' `
                    -Finding 'Device is marked Not Compliant but no specific failing policy state was returned (may be a stale evaluation).' `
                    -Recommendation 'Trigger a device sync and re-check compliance state.'
            }
        } catch {
            Write-SecurityLog "Could not read compliance policy states for $resource : $_" -Level WARN
        }
    }

    if ($device.JailBroken -eq 'True') {
        $findings += New-SecurityFinding -Category 'Intune Non-Compliant Device' -Resource $resource -Severity 'Critical' `
            -Finding 'Device is reported as jailbroken/rooted.' `
            -Recommendation 'Block access immediately via Conditional Access and consider a selective/full wipe per policy.'
    }

    if ($device.IsEncrypted -eq $false) {
        $findings += New-SecurityFinding -Category 'Intune Non-Compliant Device' -Resource $resource -Severity 'High' `
            -Finding 'Device storage is not encrypted.' `
            -Recommendation 'Enforce disk encryption (BitLocker/FileVault/device encryption) via compliance policy.'
    }

    if ($daysSinceSync -ne $null -and $daysSinceSync -gt $StaleSyncDaysThreshold) {
        $findings += New-SecurityFinding -Category 'Intune Non-Compliant Device' -Resource $resource -Severity 'Medium' `
            -Finding "Device has not checked in for $daysSinceSync days." `
            -Recommendation 'Investigate unresponsive devices; retire/wipe if no longer in use.'
    }
}

Write-SecurityLog "Non-compliant device deep-dive complete: $($devices.Count) devices checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Intune-NonCompliant-Device-Detail' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
