<#
.SYNOPSIS
    Audits Intune device configuration profiles and security baselines for assignment
    coverage and deployment health.

.DESCRIPTION
    Enumerates configuration profiles, security baselines (endpoint security templates), and
    their assignment status, flagging:
      - Profiles/baselines not assigned to any group
      - Profiles with a high error/conflict count on assigned devices
      - No security baseline deployed at all (Windows 10/11 baseline, Defender baseline, etc.)

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"
    ./Audit-ConfigurationProfileCoverage.ps1

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

$findings = @()

Write-SecurityLog "Retrieving device configuration profiles..."
$profiles = Get-MgDeviceManagementDeviceConfiguration -All
foreach ($profile in $profiles) {
    $assignments = Get-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $profile.Id -ErrorAction SilentlyContinue
    if (-not $assignments -or $assignments.Count -eq 0) {
        $findings += New-SecurityFinding -Category 'Intune Configuration' -Resource $profile.DisplayName -Severity 'Low' `
            -Finding 'Configuration profile exists but is not assigned to any group.' `
            -Recommendation 'Assign the profile to its intended scope, or remove it if obsolete.'
    }

    try {
        $status = Get-MgDeviceManagementDeviceConfigurationDeviceStatusOverview -DeviceConfigurationId $profile.Id -ErrorAction Stop
        if ($status.ErrorDeviceCount -gt 0 -or $status.ConflictDeviceCount -gt 0) {
            $findings += New-SecurityFinding -Category 'Intune Configuration' -Resource $profile.DisplayName -Severity 'Medium' `
                -Finding "Profile has $($status.ErrorDeviceCount) device(s) in error and $($status.ConflictDeviceCount) in conflict." `
                -Recommendation 'Review the per-device deployment status and resolve conflicting/erroring settings.'
        }
    } catch {
        Write-SecurityLog "Could not read deployment status for '$($profile.DisplayName)': $_" -Level WARN
    }
}

Write-SecurityLog "Retrieving security baseline (Settings Catalog / templates) coverage..."
try {
    $baselineTemplates = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/templates?`$filter=templateType eq 'securityBaseline'"
    $deployedBaselines = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/intents"
    if (-not $deployedBaselines.value -or $deployedBaselines.value.Count -eq 0) {
        $findings += New-SecurityFinding -Category 'Intune Configuration' -Resource 'Tenant' -Severity 'High' `
            -Finding 'No Intune security baselines (or endpoint security policies) are deployed.' `
            -Recommendation 'Deploy at minimum the Windows security baseline and Microsoft Defender Antivirus policy to enrolled Windows devices.'
    } else {
        Write-SecurityLog "$($deployedBaselines.value.Count) security baseline/endpoint security instance(s) found." -Level INFO
    }
} catch {
    Write-SecurityLog "Could not query security baseline templates (beta endpoint, permissions may vary): $_" -Level WARN
}

Write-SecurityLog "Configuration profile audit complete: $($profiles.Count) profiles checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Intune-Configuration-Profile-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
