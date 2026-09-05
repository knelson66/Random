<#
.SYNOPSIS
    Audits SharePoint Online and OneDrive external sharing configuration and flags overly
    permissive site collections.

.DESCRIPTION
    Checks the tenant-wide sharing capability setting, then enumerates site collections whose
    sharing setting is more permissive than the tenant default or than an "Anyone" link policy
    would suggest is appropriate, and reports sites with anonymous "Anyone" links currently active.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-SPOService -Url https://contoso-admin.sharepoint.com
    ./Audit-SharePointExternalSharing.ps1

.NOTES
    Requires: Microsoft.Online.SharePoint.PowerShell module
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name Microsoft.Online.SharePoint.PowerShell

$findings = @()

Write-SecurityLog "Reading tenant-wide sharing configuration..."
try {
    $tenant = Get-SPOTenant
    if ($tenant.SharingCapability -eq 'ExternalUserAndGuestSharing') {
        $findings += New-SecurityFinding -Category 'SharePoint/OneDrive Sharing' -Resource 'Tenant' -Severity 'High' `
            -Finding "Tenant sharing capability is 'ExternalUserAndGuestSharing' (Anyone links allowed tenant-wide)." `
            -Recommendation 'Restrict to "New and existing guests" or "Existing guests only" unless anonymous links are a deliberate business requirement, and pair with link expiration.'
    }
    if (-not $tenant.RequireAnonymousLinksExpireInDays -or $tenant.RequireAnonymousLinksExpireInDays -le 0) {
        $findings += New-SecurityFinding -Category 'SharePoint/OneDrive Sharing' -Resource 'Tenant' -Severity 'Medium' `
            -Finding 'Anonymous ("Anyone") links do not have an expiration policy set.' `
            -Recommendation 'Set RequireAnonymousLinksExpireInDays (e.g., 30) so external links do not remain valid indefinitely.'
    }
    if ($tenant.DefaultSharingLinkType -eq 'AnonymousAccess') {
        $findings += New-SecurityFinding -Category 'SharePoint/OneDrive Sharing' -Resource 'Tenant' -Severity 'Medium' `
            -Finding 'Default sharing link type is set to Anonymous Access.' `
            -Recommendation 'Change the default to "Specific people" so users must deliberately choose to widen sharing scope.'
    }
    if (-not $tenant.EnableDeviceCompliancePolicy -and -not $tenant.ConditionalAccessPolicy) {
        $findings += New-SecurityFinding -Category 'SharePoint/OneDrive Sharing' -Resource 'Tenant' -Severity 'Low' `
            -Finding 'No SharePoint-level Conditional Access / device compliance restriction is configured.' `
            -Recommendation 'Consider restricting unmanaged device access to SharePoint/OneDrive to browser-only, no-download sessions.'
    }
} catch {
    Write-SecurityLog "Could not read SPO tenant settings: $_" -Level WARN
}

Write-SecurityLog "Enumerating site collections for permissive sharing settings..."
try {
    $sites = Get-SPOSite -Limit All -IncludePersonalSite $false
    foreach ($site in $sites) {
        if ($site.SharingCapability -eq 'ExternalUserAndGuestSharing') {
            $findings += New-SecurityFinding -Category 'SharePoint/OneDrive Sharing' -Resource $site.Url -Severity 'Medium' `
                -Finding 'Site collection allows Anyone (anonymous) links.' `
                -Recommendation 'Review whether this site genuinely needs anonymous external sharing; tighten to guest-only if not.'
        }
    }
    Write-SecurityLog "$($sites.Count) site collections reviewed." -Level SUCCESS
} catch {
    Write-SecurityLog "Could not enumerate site collections: $_" -Level WARN
}

$findings | Export-SecurityReport -Title 'SharePoint-External-Sharing-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
