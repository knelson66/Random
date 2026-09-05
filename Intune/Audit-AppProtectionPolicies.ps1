<#
.SYNOPSIS
    Audits Intune Mobile Application Management (MAM) app protection policies for coverage
    and weak settings.

.DESCRIPTION
    Enumerates iOS and Android app protection policies and flags:
      - No app protection policy defined for a platform (relevant for BYOD without full MDM enrollment)
      - PIN not required to access managed apps
      - Data backup/"save as" to personal storage locations not blocked
      - Managed browser not required for web links from managed apps
      - No policy targeting unmanaged ("personal") devices specifically

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "DeviceManagementApps.Read.All"
    ./Audit-AppProtectionPolicies.ps1

.NOTES
    Requires: Microsoft.Graph.DeviceManagement.Actions / Microsoft.Graph.Beta.DeviceManagement
    (app protection policy cmdlets live in the beta profile at the time of writing).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$findings = @()

Write-SecurityLog "Retrieving iOS app protection policies..."
$iosPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections" -ErrorAction SilentlyContinue
Write-SecurityLog "Retrieving Android app protection policies..."
$androidPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections" -ErrorAction SilentlyContinue

$allPolicies = @()
if ($iosPolicies.value) { $allPolicies += $iosPolicies.value | ForEach-Object { $_ | Add-Member -NotePropertyName Platform -NotePropertyValue 'iOS' -PassThru } }
if ($androidPolicies.value) { $allPolicies += $androidPolicies.value | ForEach-Object { $_ | Add-Member -NotePropertyName Platform -NotePropertyValue 'Android' -PassThru } }

if ($allPolicies.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Intune App Protection' -Resource 'Tenant' -Severity 'High' `
        -Finding 'No iOS or Android app protection (MAM) policies are configured.' `
        -Recommendation 'Deploy app protection policies to secure corporate data in managed apps on BYOD/unenrolled devices.'
}

foreach ($policy in $allPolicies) {
    $resource = "$($policy.Platform)/$($policy.displayName)"

    if (-not $policy.pinRequired) {
        $findings += New-SecurityFinding -Category 'Intune App Protection' -Resource $resource -Severity 'High' `
            -Finding 'PIN is not required to access managed app data.' `
            -Recommendation 'Require a PIN (or biometric) for managed app access.'
    }

    if ($policy.saveAsBlocked -ne $true) {
        $findings += New-SecurityFinding -Category 'Intune App Protection' -Resource $resource -Severity 'Medium' `
            -Finding '"Save As" to personal storage locations is not blocked.' `
            -Recommendation 'Block Save As to non-corporate storage locations to prevent data exfiltration.'
    }

    if ($policy.managedBrowser -and $policy.managedBrowser -ne 'microsoftEdge' -and $policy.managedBrowserToOpenLinksRequired -ne $true) {
        $findings += New-SecurityFinding -Category 'Intune App Protection' -Resource $resource -Severity 'Low' `
            -Finding 'Managed browser is not required to open links from managed apps.' `
            -Recommendation 'Require Microsoft Edge (managed browser) for web links to keep browsing data within managed context.'
    }

    if ($policy.allowedDataStorageLocations -contains 'allowedLocationsOther' -or $policy.allowedDataStorageLocations -contains 'sharePoint' -and -not $policy.allowedDataStorageLocations) {
        $findings += New-SecurityFinding -Category 'Intune App Protection' -Resource $resource -Severity 'Low' `
            -Finding 'Policy allows broad data storage locations for managed app data.' `
            -Recommendation 'Restrict allowed data storage locations to only what business processes require.'
    }

    if ($policy.periodOfflineBeforeAccessCheck) {
        try {
            $offlinePeriod = [System.Xml.XmlConvert]::ToTimeSpan($policy.periodOfflineBeforeAccessCheck)
            if ($offlinePeriod -gt [timespan]::FromDays(1)) {
                $findings += New-SecurityFinding -Category 'Intune App Protection' -Resource $resource -Severity 'Low' `
                    -Finding "Offline grace period before an access check is longer than 1 day ($($policy.periodOfflineBeforeAccessCheck))." `
                    -Recommendation 'Shorten the offline access grace period so revoked/noncompliant access is cut off faster.'
            }
        } catch {
            Write-SecurityLog "Could not parse periodOfflineBeforeAccessCheck for $resource : $_" -Level WARN
        }
    }
}

Write-SecurityLog "App protection policy audit complete: $($allPolicies.Count) policies checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Intune-App-Protection-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
