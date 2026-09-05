<#
.SYNOPSIS
    Audits Microsoft Intune device compliance policy coverage and flags devices/platforms
    that fall outside of it.

.DESCRIPTION
    Enumerates all device compliance policies and their assignments, then cross-references
    managed devices to flag:
      - Platforms (Windows/iOS/Android/macOS) with no compliance policy assigned at all
      - Compliance policies not assigned to any group (defined but inert)
      - Devices in a "Not Compliant" or "In Grace Period" state
      - Devices with compliance state "Unknown" (haven't checked in / policy not evaluated)

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All","DeviceManagementManagedDevices.Read.All"
    ./Audit-DeviceCompliancePolicies.ps1

.NOTES
    Requires: Microsoft.Graph.DeviceManagement
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

Write-SecurityLog "Retrieving device compliance policies..."
$policies = Get-MgDeviceManagementDeviceCompliancePolicy -All
$findings = @()

if (-not $policies -or $policies.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Intune Compliance' -Resource 'Tenant' -Severity 'Critical' `
        -Finding 'No device compliance policies exist in the tenant.' `
        -Recommendation 'Create at least one compliance policy per managed platform (Windows, iOS, Android, macOS).'
} else {
    $platformsCovered = @{}
    foreach ($policy in $policies) {
        $odataType = $policy.AdditionalProperties['@odata.type']
        $platformsCovered[$odataType] = $true

        $assignments = Get-MgDeviceManagementDeviceCompliancePolicyAssignment -DeviceCompliancePolicyId $policy.Id -ErrorAction SilentlyContinue
        if (-not $assignments -or $assignments.Count -eq 0) {
            $findings += New-SecurityFinding -Category 'Intune Compliance' -Resource $policy.DisplayName -Severity 'Medium' `
                -Finding 'Compliance policy exists but is not assigned to any group.' `
                -Recommendation 'Assign the policy to the intended device/user groups, or remove it if obsolete.'
        }
    }

    $expectedPlatforms = @(
        '#microsoft.graph.windows10CompliancePolicy',
        '#microsoft.graph.iosCompliancePolicy',
        '#microsoft.graph.androidWorkProfileCompliancePolicy',
        '#microsoft.graph.macOSCompliancePolicy'
    )
    foreach ($platform in $expectedPlatforms) {
        if (-not $platformsCovered.ContainsKey($platform)) {
            $friendly = $platform -replace '#microsoft.graph.', '' -replace 'CompliancePolicy', ''
            $findings += New-SecurityFinding -Category 'Intune Compliance' -Resource 'Tenant' -Severity 'Low' `
                -Finding "No compliance policy defined for platform: $friendly (only relevant if this platform is enrolled)." `
                -Recommendation 'Create a compliance policy for every platform actually enrolled in Intune.'
        }
    }
}

Write-SecurityLog "Retrieving managed device compliance states..."
$devices = Get-MgDeviceManagementManagedDevice -All -Property Id, DeviceName, ComplianceState, OperatingSystem, LastSyncDateTime, UserPrincipalName

$notCompliant = $devices | Where-Object { $_.ComplianceState -eq 'noncompliant' }
foreach ($d in $notCompliant) {
    $findings += New-SecurityFinding -Category 'Intune Compliance' -Resource "$($d.DeviceName) ($($d.UserPrincipalName))" -Severity 'High' `
        -Finding "Device is Not Compliant (OS: $($d.OperatingSystem), last sync $($d.LastSyncDateTime))." `
        -Recommendation 'Investigate and remediate the failing compliance settings, or block access via Conditional Access until resolved.'
}

$grace = $devices | Where-Object { $_.ComplianceState -eq 'inGracePeriod' }
foreach ($d in $grace) {
    $findings += New-SecurityFinding -Category 'Intune Compliance' -Resource "$($d.DeviceName) ($($d.UserPrincipalName))" -Severity 'Medium' `
        -Finding "Device is in a compliance grace period (OS: $($d.OperatingSystem))." `
        -Recommendation 'Grace period will expire and block access; follow up before it does.'
}

$unknown = $devices | Where-Object { $_.ComplianceState -eq 'unknown' }
if ($unknown.Count -gt 0) {
    $findings += New-SecurityFinding -Category 'Intune Compliance' -Resource 'Tenant' -Severity 'Medium' `
        -Finding "$($unknown.Count) device(s) report compliance state 'Unknown' (not evaluated / not checked in)." `
        -Recommendation 'Investigate stale/unresponsive devices; consider retiring devices that never check in.'
}

Write-SecurityLog "Compliance policy audit complete: $($devices.Count) devices checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Intune-Device-Compliance-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
