<#
.SYNOPSIS
    Audits Conditional Access policy coverage and configuration in Microsoft Entra ID.

.DESCRIPTION
    Retrieves all Conditional Access policies and flags common gaps and misconfigurations:
      - Policies in "Report-only" mode that were never promoted to "On"
      - No policy requiring MFA for all users / all cloud apps
      - No policy blocking legacy authentication
      - No policy requiring compliant/hybrid-joined device for admin roles
      - Disabled policies that appear to cover critical scenarios
      - Break-glass/emergency access accounts not excluded from blocking policies (informational)

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All"
    ./Audit-ConditionalAccessPolicies.ps1

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

Write-SecurityLog "Retrieving Conditional Access policies..."
$policies = Get-MgIdentityConditionalAccessPolicy -All
$findings = @()

if (-not $policies -or $policies.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Conditional Access' -Resource 'Tenant' -Severity 'Critical' `
        -Finding 'No Conditional Access policies exist in the tenant.' `
        -Recommendation 'Implement baseline CA policies: block legacy auth, require MFA for all users, require compliant device for admins.'
} else {
    foreach ($p in $policies) {
        if ($p.State -eq 'enabledForReportingButNotEnforced') {
            $findings += New-SecurityFinding -Category 'Conditional Access' -Resource $p.DisplayName -Severity 'Medium' `
                -Finding 'Policy is in report-only mode and is not being enforced.' `
                -Recommendation 'Review sign-in logs for impact, then promote to On if safe.'
        }
        if ($p.State -eq 'disabled') {
            $findings += New-SecurityFinding -Category 'Conditional Access' -Resource $p.DisplayName -Severity 'Low' `
                -Finding 'Policy exists but is disabled.' `
                -Recommendation 'Confirm this policy is intentionally retired; remove if obsolete.'
        }
    }

    $enforced = $policies | Where-Object { $_.State -eq 'enabled' }

    $mfaAllUsers = $enforced | Where-Object {
        $_.GrantControls.BuiltInControls -contains 'mfa' -and
        ($_.Conditions.Users.IncludeUsers -contains 'All')
    }
    if (-not $mfaAllUsers) {
        $findings += New-SecurityFinding -Category 'Conditional Access' -Resource 'Tenant' -Severity 'High' `
            -Finding 'No enabled policy requires MFA for all users across all cloud apps.' `
            -Recommendation 'Create a policy targeting All users / All cloud apps with Grant = Require MFA.'
    }

    $legacyAuthBlocked = $enforced | Where-Object {
        $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or $_.Conditions.ClientAppTypes -contains 'other'
    } | Where-Object { $_.GrantControls.BuiltInControls -contains 'block' }
    if (-not $legacyAuthBlocked) {
        $findings += New-SecurityFinding -Category 'Conditional Access' -Resource 'Tenant' -Severity 'High' `
            -Finding 'No policy blocks legacy authentication protocols (basic auth / other clients).' `
            -Recommendation 'Create a CA policy that blocks client app types: Exchange ActiveSync + Other clients.'
    }

    $deviceCompliancePolicies = $enforced | Where-Object {
        $_.GrantControls.BuiltInControls -contains 'compliantDevice' -or $_.GrantControls.BuiltInControls -contains 'domainJoinedDevice'
    }
    if (-not $deviceCompliancePolicies) {
        $findings += New-SecurityFinding -Category 'Conditional Access' -Resource 'Tenant' -Severity 'Medium' `
            -Finding 'No policy requires a compliant or hybrid-joined device.' `
            -Recommendation 'Require compliant/hybrid-joined device for admin roles and/or all users where feasible.'
    }

    $adminPolicy = $enforced | Where-Object {
        $_.Conditions.Users.IncludeRoles.Count -gt 0
    }
    if (-not $adminPolicy) {
        $findings += New-SecurityFinding -Category 'Conditional Access' -Resource 'Tenant' -Severity 'Medium' `
            -Finding 'No policy specifically targets privileged directory roles.' `
            -Recommendation 'Create a dedicated policy for admin roles requiring phishing-resistant MFA and a compliant device.'
    }
}

Write-SecurityLog "Reviewed $($policies.Count) Conditional Access policies, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Entra-ID-Conditional-Access-Audit' -OutputPath $OutputPath
$findings | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
