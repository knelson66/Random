<#
.SYNOPSIS
    Audits Windows 365 Cloud PC provisioning policies and device status for security gaps.

.DESCRIPTION
    Checks:
      - Provisioning policies using Microsoft-hosted network (no ability to enforce
        organization-specific network controls/egress inspection) where an Azure network
        connection would be more appropriate for regulated data
      - Cloud PCs stuck in a "provisioningFailed"/"inGracePeriod"/"notProvisioned" state
      - Cloud PCs not enrolled in Intune (would miss compliance/configuration policy coverage)
      - Single sign-on not enabled on provisioning policies (relies on legacy auth prompts)

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "CloudPC.Read.All"
    ./Audit-Windows365CloudPCSecurity.ps1

.NOTES
    Requires: Microsoft.Graph.Beta.DeviceManagement.Actions (Cloud PC cmdlets are in the beta
    profile at the time of writing) or direct Invoke-MgGraphRequest calls (used here for
    broad compatibility).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$findings = @()

Write-SecurityLog "Retrieving Windows 365 provisioning policies..."
try {
    $policies = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies").value
} catch {
    Write-SecurityLog "Could not retrieve provisioning policies (requires CloudPC.Read.All and a Windows 365 license): $_" -Level ERROR
    return
}

foreach ($policy in $policies) {
    if ($policy.microsoftManagedDesktop.managedType -eq 'notManaged' -and $policy.domainJoinConfiguration.domainJoinType -eq 'azureADJoin' -and -not $policy.domainJoinConfiguration.onPremisesConnectionId) {
        $findings += New-SecurityFinding -Category 'Windows 365' -Resource $policy.displayName -Severity 'Low' `
            -Finding 'Provisioning policy uses the Microsoft-hosted network with no Azure network connection.' `
            -Recommendation 'For regulated/sensitive workloads, consider an Azure network connection to apply org-specific network controls, egress inspection, and private connectivity to on-prem resources.'
    }

    if (-not $policy.enableSingleSignOn) {
        $findings += New-SecurityFinding -Category 'Windows 365' -Resource $policy.displayName -Severity 'Low' `
            -Finding 'Single sign-on is not enabled on this provisioning policy.' `
            -Recommendation 'Enable Windows 365 SSO so users authenticate via modern auth/Windows Hello rather than a legacy credential prompt.'
    }
}

Write-SecurityLog "Retrieving Cloud PC device status..."
try {
    $cloudPCs = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs").value
} catch {
    Write-SecurityLog "Could not retrieve Cloud PCs: $_" -Level ERROR
    $cloudPCs = @()
}

$unhealthyStates = @('provisioningFailed', 'inGracePeriod', 'notProvisioned', 'failed')
foreach ($pc in $cloudPCs) {
    if ($pc.status -in $unhealthyStates) {
        $findings += New-SecurityFinding -Category 'Windows 365' -Resource "$($pc.managedDeviceName) ($($pc.userPrincipalName))" -Severity 'Medium' `
            -Finding "Cloud PC status is '$($pc.status)'." `
            -Recommendation 'Investigate provisioning/licensing issues; a Cloud PC stuck in grace period will be deprovisioned (and its data lost) if not resolved.'
    }
    if (-not $pc.managedDeviceId) {
        $findings += New-SecurityFinding -Category 'Windows 365' -Resource "$($pc.userPrincipalName)" -Severity 'Medium' `
            -Finding 'Cloud PC does not appear to be enrolled in Intune (no managed device ID).' `
            -Recommendation 'Investigate why this Cloud PC has no Intune enrollment; it will miss compliance and configuration policy coverage.'
    }
}

Write-SecurityLog "Windows 365 audit complete: $($policies.Count) policies, $($cloudPCs.Count) Cloud PCs checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Windows365-CloudPC-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
