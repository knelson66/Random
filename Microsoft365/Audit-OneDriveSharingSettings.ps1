<#
.SYNOPSIS
    Audits OneDrive for Business per-user sharing exposure: anonymous links currently active
    and external sharing on individual OneDrive sites.

.DESCRIPTION
    Enumerates OneDrive personal sites and flags:
      - Sites where sharing capability is more permissive than the tenant default (an
        individual user's OneDrive is more exposed than the org-wide policy intends)
      - Large OneDrive accounts (a heuristic for "likely holds a lot of content") that also
        allow anonymous/guest sharing, worth a targeted manual review of what's actually shared

    Note: per-site counts of active anonymous ("Anyone") links are not exposed by the
    Microsoft.Online.SharePoint.PowerShell module at scale - for that level of detail, use
    PnP PowerShell's Get-PnPSharingLinks against specific high-priority sites this script flags.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-SPOService -Url https://contoso-admin.sharepoint.com
    ./Audit-OneDriveSharingSettings.ps1

.NOTES
    Requires: Microsoft.Online.SharePoint.PowerShell
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name Microsoft.Online.SharePoint.PowerShell

$findings = @()

Write-SecurityLog "Reading tenant sharing default..."
$tenant = Get-SPOTenant
$tenantDefault = $tenant.SharingCapability

Write-SecurityLog "Enumerating OneDrive personal sites (this can take a while in large tenants)..."
$oneDriveSites = Get-SPOSite -IncludePersonalSite $true -Filter "Url -like '-my.sharepoint.com/personal/'" -Limit All

$permissivenessOrder = @{ Disabled = 0; ExistingExternalUserSharingOnly = 1; ExternalUserSharingOnly = 2; ExternalUserAndGuestSharing = 3 }

foreach ($site in $oneDriveSites) {
    if ($permissivenessOrder.ContainsKey($site.SharingCapability) -and $permissivenessOrder.ContainsKey($tenantDefault)) {
        if ($permissivenessOrder[$site.SharingCapability] -gt $permissivenessOrder[$tenantDefault]) {
            $findings += New-SecurityFinding -Category 'OneDrive Sharing' -Resource $site.Owner -Severity 'Medium' `
                -Finding "This user's OneDrive sharing setting ('$($site.SharingCapability)') is more permissive than the tenant default ('$tenantDefault')." `
                -Recommendation 'Investigate why this site has an overridden sharing policy; align to tenant default unless there is a documented business exception.'
        }
    }

    if ($site.StorageUsageCurrent -gt 100000 -and $site.SharingCapability -eq 'ExternalUserAndGuestSharing') {
        $findings += New-SecurityFinding -Category 'OneDrive Sharing' -Resource $site.Owner -Severity 'Low' `
            -Finding "Large OneDrive ($([math]::Round($site.StorageUsageCurrent/1024,1)) GB) allows anonymous/guest sharing." `
            -Recommendation 'Given the volume of content, consider a targeted review of what has actually been shared externally from this account.'
    }
}

Write-SecurityLog "OneDrive sharing audit complete: $($oneDriveSites.Count) sites checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'OneDrive-Sharing-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
