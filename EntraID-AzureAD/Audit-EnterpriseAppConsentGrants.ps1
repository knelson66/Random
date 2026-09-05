<#
.SYNOPSIS
    Audits tenant-wide user consent settings and existing enterprise application consent
    grants for risky self-service OAuth consent exposure.

.DESCRIPTION
    Checks:
      - Tenant-wide user consent policy allows users to consent to apps from any publisher
        (as opposed to verified publishers with low-risk permissions, or admin-consent-only)
      - Admin consent workflow is not enabled (users blocked from consenting have no path to
        request access, so they resort to workarounds, or legitimate requests get lost)
      - Existing service principals with delegated permissions that include mail/file read
        access, granted via user (not admin) consent

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All"
    ./Audit-EnterpriseAppConsentGrants.ps1

.NOTES
    Requires: Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Applications
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$findings = @()
$sensitiveScopes = @('Mail.Read', 'Mail.ReadWrite', 'Files.Read.All', 'Files.ReadWrite.All', 'Contacts.Read', 'Notes.Read.All')

Write-SecurityLog "Checking tenant-wide user consent policy..."
try {
    $consentPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $userConsentSetting = $consentPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned

    if ($userConsentSetting -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {
        $findings += New-SecurityFinding -Category 'Enterprise App Consent' -Resource 'Tenant' -Severity 'High' `
            -Finding 'Users can consent to apps requesting any permissions (legacy "allow all" consent policy).' `
            -Recommendation 'Restrict user consent to verified publishers with low-risk permissions, or require admin consent for all apps.'
    }
} catch {
    Write-SecurityLog "Could not read authorization policy: $_" -Level WARN
}

Write-SecurityLog "Checking admin consent workflow status..."
try {
    $adminConsentPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"
    if (-not $adminConsentPolicy.isEnabled) {
        $findings += New-SecurityFinding -Category 'Enterprise App Consent' -Resource 'Tenant' -Severity 'Medium' `
            -Finding 'Admin consent workflow is not enabled.' `
            -Recommendation 'Enable the admin consent workflow so users blocked from self-service consent have a legitimate path to request access, reviewed by an admin.'
    }
} catch {
    Write-SecurityLog "Could not read admin consent request policy: $_" -Level WARN
}

Write-SecurityLog "Reviewing existing user-consented grants for sensitive scopes..."
$grants = Get-MgOauth2PermissionGrant -All | Where-Object { $_.ConsentType -eq 'Principal' }
$grantsBySp = $grants | Group-Object ClientId

foreach ($group in $grantsBySp) {
    $allScopes = ($group.Group | ForEach-Object { $_.Scope -split ' ' }) | Where-Object { $_ } | Select-Object -Unique
    $risky = $allScopes | Where-Object { $_ -in $sensitiveScopes }
    if ($risky) {
        $sp = Get-MgServicePrincipal -ServicePrincipalId $group.Name -ErrorAction SilentlyContinue
        $userCount = $group.Group.Count
        $findings += New-SecurityFinding -Category 'Enterprise App Consent' -Resource ($sp.DisplayName ?? $group.Name) -Severity 'Medium' `
            -Finding "App holds sensitive scope(s) ($($risky -join ', ')) via individual USER consent from $userCount user(s), not admin consent." `
            -Recommendation 'Review whether this app should require admin consent instead, and confirm each consenting user still needs it.'
    }
}

Write-SecurityLog "Enterprise app consent audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Entra-ID-Enterprise-App-Consent-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
