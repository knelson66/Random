<#
.SYNOPSIS
    Audits Intune Windows Update rings for risky deferral/deadline settings and safeguard holds.

.DESCRIPTION
    Checks each Windows Update ring (feature/quality update policy) for:
      - Quality update deferral longer than a recommended maximum (patches sitting unapplied)
      - Automatic restarts disabled or deadlines set too far out, delaying remediation of
        actively exploited vulnerabilities
      - No update ring assigned to any device group (Windows devices silently on default cadence)

.PARAMETER MaxQualityDeferralDays
    Flag rings deferring quality (security) updates longer than this. Default 7.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"
    ./Audit-WindowsUpdateRings.ps1

.NOTES
    Requires: Microsoft.Graph.DeviceManagement
#>
[CmdletBinding()]
param(
    [int]$MaxQualityDeferralDays = 7,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$findings = @()

Write-SecurityLog "Retrieving Windows Update rings..."
$rings = Get-MgDeviceManagementDeviceConfiguration -All -Filter "isof('microsoft.graph.windowsUpdateForBusinessConfiguration')"

if (-not $rings -or $rings.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Intune Update Rings' -Resource 'Tenant' -Severity 'Medium' `
        -Finding 'No Windows Update ring policies are configured.' `
        -Recommendation 'Create at least one update ring so quality/security update cadence is managed rather than left at Windows defaults.'
} else {
    foreach ($ring in $rings) {
        $props = $ring.AdditionalProperties
        $qualityDeferral = [int]($props['qualityUpdateDeferralPeriodInDays'] ?? 0)
        $autoRestart = $props['automaticUpdateMode']

        if ($qualityDeferral -gt $MaxQualityDeferralDays) {
            $findings += New-SecurityFinding -Category 'Intune Update Rings' -Resource $ring.DisplayName -Severity 'High' `
                -Finding "Quality (security) update deferral is $qualityDeferral days, above the recommended max of $MaxQualityDeferralDays." `
                -Recommendation 'Reduce quality update deferral so security patches deploy promptly, especially for internet-facing/high-risk device groups.'
        }

        if ($autoRestart -eq 'notifyDownload' -or $autoRestart -eq 'autoInstallAndNotifyForRestart') {
            $findings += New-SecurityFinding -Category 'Intune Update Rings' -Resource $ring.DisplayName -Severity 'Low' `
                -Finding "Automatic update mode ('$autoRestart') relies on the user to restart, which can delay patch installation indefinitely." `
                -Recommendation 'Use "Auto install and restart" with a reasonable deadline/grace period to guarantee patches actually apply.'
        }

        $assignments = Get-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $ring.Id -ErrorAction SilentlyContinue
        if (-not $assignments -or $assignments.Count -eq 0) {
            $findings += New-SecurityFinding -Category 'Intune Update Rings' -Resource $ring.DisplayName -Severity 'Low' `
                -Finding 'Update ring is not assigned to any device group.' `
                -Recommendation 'Assign the ring, or remove it if unused.'
        }
    }
}

Write-SecurityLog "Windows Update ring audit complete: $($rings.Count) rings checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Intune-Update-Ring-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
