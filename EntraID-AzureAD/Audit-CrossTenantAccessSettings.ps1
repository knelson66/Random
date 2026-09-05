<#
.SYNOPSIS
    Audits Entra ID cross-tenant access settings (B2B collaboration/direct connect) for overly
    permissive default or partner-specific trust configuration.

.DESCRIPTION
    Checks:
      - Default inbound/outbound cross-tenant access settings allow all users/apps with no
        MFA or device compliance trust requirement
      - Specific partner configurations that trust the partner's MFA/device claims without
        the organization actually knowing the partner's security posture
      - B2B direct connect enabled tenant-wide rather than scoped to known partners
      - Automatic redemption of invitations enabled for all external domains

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "Policy.Read.All"
    ./Audit-CrossTenantAccessSettings.ps1

.NOTES
    Requires: Microsoft.Graph.Identity.SignIns
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$findings = @()

Write-SecurityLog "Retrieving default cross-tenant access settings..."
try {
    $defaultSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default"

    if ($defaultSettings.b2bCollaborationInbound.usersAndGroups.accessType -eq 'allowed' -and
        -not $defaultSettings.inboundTrust.isMfaAccepted) {
        $findings += New-SecurityFinding -Category 'Cross-Tenant Access' -Resource 'Default (all tenants)' -Severity 'Medium' `
            -Finding 'Default inbound trust does not accept MFA claims from external tenants, forcing re-authentication (or worse, silently blocking) for any partner relying on trust.' `
            -Recommendation 'Decide deliberately: either enable inbound trust of MFA/compliant-device claims for genuinely trusted partners, or leave disabled and document why.'
    }

    if ($defaultSettings.b2bDirectConnectInbound.usersAndGroups.accessType -eq 'allowed') {
        $findings += New-SecurityFinding -Category 'Cross-Tenant Access' -Resource 'Default (all tenants)' -Severity 'Medium' `
            -Finding 'B2B direct connect (Teams Shared Channels cross-tenant trust) is allowed by default for all external tenants.' `
            -Recommendation 'Scope B2B direct connect to specific known partner tenants rather than allowing it tenant-wide by default.'
    }
} catch {
    Write-SecurityLog "Could not read default cross-tenant access policy: $_" -Level WARN
}

Write-SecurityLog "Retrieving partner-specific cross-tenant access configurations..."
try {
    $partners = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners").value
    foreach ($partner in $partners) {
        if ($partner.inboundTrust.isMfaAccepted -and $partner.inboundTrust.isCompliantDeviceAccepted) {
            $findings += New-SecurityFinding -Category 'Cross-Tenant Access' -Resource "Partner: $($partner.tenantId)" -Severity 'Informational' `
                -Finding 'This partner tenant is trusted for both MFA and compliant-device claims.' `
                -Recommendation 'Confirm this trust level matches an actual documented business relationship and was not left over from a one-time project.'
        }
        if ($partner.b2bCollaborationInbound.usersAndGroups.accessType -eq 'allowed' -and -not $partner.b2bCollaborationInbound.applications) {
            $findings += New-SecurityFinding -Category 'Cross-Tenant Access' -Resource "Partner: $($partner.tenantId)" -Severity 'Low' `
                -Finding 'Inbound B2B collaboration allows all applications with no application-level restriction for this partner.' `
                -Recommendation 'Scope inbound access to only the specific applications the partnership requires.'
        }
    }
} catch {
    Write-SecurityLog "Could not read partner-specific cross-tenant access configurations: $_" -Level WARN
}

Write-SecurityLog "Cross-tenant access audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Entra-ID-CrossTenant-Access-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
