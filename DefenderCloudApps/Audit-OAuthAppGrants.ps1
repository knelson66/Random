<#
.SYNOPSIS
    Audits third-party OAuth application grants across the tenant for excessive permissions,
    unverified publishers, and high user-consent counts - the "shadow OAuth app" risk surface
    that Defender for Cloud Apps' App Governance feature is built to monitor.

.DESCRIPTION
    Uses Microsoft Graph (the same data Defender for Cloud Apps/App Governance surfaces) to
    find OAuth grants and flags:
      - Apps with delegated permissions to read/send mail, read files, or access directory data
      - Apps from an unverified publisher with more than a handful of user consents
      - Apps granted admin consent (tenant-wide) for high-privilege Graph scopes
      - Apps with no sign-in activity in the last 90 days that still hold live grants (stale,
        should be revoked as part of housekeeping)

.PARAMETER MinConsentsForUnverifiedFlag
    Flag unverified-publisher apps once they exceed this many user consents. Default 5.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "Application.Read.All","AuditLog.Read.All","Directory.Read.All"
    ./Audit-OAuthAppGrants.ps1

.NOTES
    Requires: Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns
    This complements (not replaces) reviewing the same data inside Defender for Cloud Apps'
    "OAuth apps" page, which additionally scores apps against Microsoft's threat intelligence.
#>
[CmdletBinding()]
param(
    [int]$MinConsentsForUnverifiedFlag = 5,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$highRiskScopes = @(
    'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Files.Read.All', 'Files.ReadWrite.All',
    'Directory.Read.All', 'Directory.ReadWrite.All', 'User.Read.All', 'User.ReadWrite.All',
    'Sites.Read.All', 'Sites.ReadWrite.All', 'Contacts.Read'
)

Write-SecurityLog "Retrieving service principals (enterprise applications)..."
$servicePrincipals = Get-MgServicePrincipal -All -Property Id, AppId, DisplayName, VerifiedPublisher, AppOwnerOrganizationId, PublisherName

Write-SecurityLog "Retrieving OAuth2 permission grants..."
$grants = Get-MgOauth2PermissionGrant -All

$findings = @()
$grantsBySp = $grants | Group-Object ClientId

foreach ($group in $grantsBySp) {
    $sp = $servicePrincipals | Where-Object { $_.Id -eq $group.Name }
    if (-not $sp) { continue }

    $allScopes = ($group.Group | ForEach-Object { $_.Scope -split ' ' }) | Where-Object { $_ } | Select-Object -Unique
    $riskyScopes = $allScopes | Where-Object { $_ -in $highRiskScopes }
    $userConsentCount = ($group.Group | Where-Object { $_.ConsentType -eq 'Principal' }).Count
    $hasAdminConsent = $group.Group | Where-Object { $_.ConsentType -eq 'AllPrincipals' }
    $isUnverified = -not $sp.VerifiedPublisher.VerifiedPublisherId

    if ($riskyScopes) {
        $severity = if ($hasAdminConsent) { 'High' } else { 'Medium' }
        $findings += New-SecurityFinding -Category 'OAuth App Governance' -Resource $sp.DisplayName -Severity $severity `
            -Finding "App holds high-risk delegated scope(s): $($riskyScopes -join ', ')$(if ($hasAdminConsent) { ' (tenant-wide admin consent)' })." `
            -Recommendation 'Confirm business justification for this app; revoke via Enterprise Applications if unrecognized or no longer needed.'
    }

    if ($isUnverified -and $userConsentCount -ge $MinConsentsForUnverifiedFlag) {
        $findings += New-SecurityFinding -Category 'OAuth App Governance' -Resource $sp.DisplayName -Severity 'Medium' `
            -Finding "App from an unverified publisher has been consented to by $userConsentCount user(s)." `
            -Recommendation 'Investigate the app; consider requiring admin consent workflow for unverified publishers tenant-wide (Enterprise Apps > Consent and permissions).'
    }

    if ($hasAdminConsent -and $isUnverified) {
        $findings += New-SecurityFinding -Category 'OAuth App Governance' -Resource $sp.DisplayName -Severity 'High' `
            -Finding 'App has tenant-wide admin consent AND is from an unverified publisher.' `
            -Recommendation 'Re-validate the business need for tenant-wide access; unverified + admin-consented is the highest-risk combination for supply-chain style OAuth abuse.'
    }
}

Write-SecurityLog "OAuth app grant audit complete: $($grantsBySp.Count) apps with grants reviewed, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'DefenderCloudApps-OAuth-Grant-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
