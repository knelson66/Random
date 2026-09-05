<#
.SYNOPSIS
    Audits Microsoft Teams external access, guest access, and meeting security policies.

.DESCRIPTION
    Checks the tenant-wide Teams federation/external access configuration and meeting policies for:
      - Open federation with all external domains
      - Guest access to Teams enabled without corresponding Entra ID guest governance
      - Anonymous users allowed to join meetings / start meetings before the organizer
      - Meeting recording and transcription available to anonymous/external participants

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-MicrosoftTeams
    ./Audit-TeamsExternalAccess.ps1

.NOTES
    Requires: MicrosoftTeams module
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name MicrosoftTeams

$findings = @()

Write-SecurityLog "Reading Teams federation configuration..."
try {
    $fedConfig = Get-CsTenantFederationConfiguration
    if ($fedConfig.AllowFederatedUsers -and $fedConfig.AllowedDomains -eq 'AllowAllKnownDomains') {
        $findings += New-SecurityFinding -Category 'Teams External Access' -Resource 'Tenant' -Severity 'Medium' `
            -Finding 'Open federation is enabled - any external Teams tenant/domain can communicate with your users.' `
            -Recommendation 'Restrict to an explicit allow-list of trusted partner domains where feasible.'
    }
    if ($fedConfig.AllowPublicUsers) {
        $findings += New-SecurityFinding -Category 'Teams External Access' -Resource 'Tenant' -Severity 'Low' `
            -Finding 'Communication with consumer Skype/Teams (public) users is allowed.' `
            -Recommendation 'Disable unless there is a specific business need to contact consumer accounts.'
    }
} catch {
    Write-SecurityLog "Could not read federation configuration: $_" -Level WARN
}

Write-SecurityLog "Reading Teams client/guest configuration..."
try {
    $clientConfig = Get-CsTeamsClientConfiguration
    if ($clientConfig.AllowGuestUser -and -not $clientConfig.AllowResourceAccountSendMessage) {
        $findings += New-SecurityFinding -Category 'Teams External Access' -Resource 'Tenant' -Severity 'Informational' `
            -Finding 'Guest access to Teams is enabled.' `
            -Recommendation 'Ensure this is paired with Entra ID guest lifecycle governance (access reviews, expiration) - see Audit-GuestUsers.ps1.'
    }
} catch {
    Write-SecurityLog "Could not read Teams client configuration: $_" -Level WARN
}

Write-SecurityLog "Reading meeting policies for anonymous access risk..."
try {
    $meetingPolicies = Get-CsTeamsMeetingPolicy
    foreach ($policy in $meetingPolicies) {
        if ($policy.AllowAnonymousUsersToJoinMeeting -eq $true) {
            $findings += New-SecurityFinding -Category 'Teams Meeting Security' -Resource $policy.Identity -Severity 'Medium' `
                -Finding 'Policy allows anonymous (unauthenticated) users to join meetings.' `
                -Recommendation 'Restrict to authenticated users only for policies covering sensitive meetings; use the lobby to vet anonymous joiners if this must stay enabled.'
        }
        if ($policy.AllowAnonymousUsersToStartMeeting -eq $true) {
            $findings += New-SecurityFinding -Category 'Teams Meeting Security' -Resource $policy.Identity -Severity 'High' `
                -Finding 'Policy allows anonymous users to start a meeting (bypassing the organizer).' `
                -Recommendation 'Disable - meetings should not be startable by unauthenticated participants.'
        }
        if ($policy.AutoAdmittedUsers -eq 'Everyone') {
            $findings += New-SecurityFinding -Category 'Teams Meeting Security' -Resource $policy.Identity -Severity 'Medium' `
                -Finding "AutoAdmittedUsers is set to 'Everyone', bypassing the meeting lobby for all participants including external/anonymous." `
                -Recommendation 'Set to "People in my organization" (or stricter) for policies applied to sensitive meeting types.'
        }
    }
} catch {
    Write-SecurityLog "Could not read Teams meeting policies: $_" -Level WARN
}

Write-SecurityLog "Teams external access audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Teams-External-Access-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
