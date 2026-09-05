<#
.SYNOPSIS
    Audits B2B guest accounts in Microsoft Entra ID for staleness, excessive access, and
    domains outside an approved allow-list.

.DESCRIPTION
    Enumerates all guest users, checks last sign-in activity, group/role membership, and
    the source domain of each guest to flag accounts that should be reviewed or removed.

.PARAMETER StaleDaysThreshold
    Days since last sign-in (or invitation, if never signed in) before a guest is flagged stale.

.PARAMETER ApprovedDomains
    Array of domains considered trusted partners. Guests from other domains are flagged Medium.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.Directory","Directory.Read.All"
    ./Audit-GuestUsers.ps1 -StaleDaysThreshold 90 -ApprovedDomains "contoso-partner.com","fabrikam.com"

.NOTES
    Requires: Microsoft.Graph.Users, Microsoft.Graph.Groups
#>
[CmdletBinding()]
param(
    [int]$StaleDaysThreshold = 90,
    [string[]]$ApprovedDomains = @(),
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

Write-SecurityLog "Retrieving guest users..."
$guests = Get-MgUser -All -Filter "userType eq 'Guest'" -Property Id, DisplayName, UserPrincipalName, Mail, CreatedDateTime, SignInActivity, AccountEnabled, ExternalUserState

$findings = @()

foreach ($guest in $guests) {
    $domain = ($guest.Mail ?? $guest.UserPrincipalName) -replace '.*#EXT#@', '' -replace '.*@', ''
    $lastSignIn = $guest.SignInActivity.LastSignInDateTime
    $reference = $lastSignIn ?? $guest.CreatedDateTime
    $daysSince = if ($reference) { (New-TimeSpan -Start $reference -End (Get-Date)).Days } else { $null }

    if (-not $lastSignIn) {
        $findings += New-SecurityFinding -Category 'Guest Access' -Resource $guest.UserPrincipalName `
            -Severity 'Medium' `
            -Finding "Guest has never signed in. Invitation state: $($guest.ExternalUserState). Created $($guest.CreatedDateTime)." `
            -Recommendation 'Remove pending invitations older than 30 days if unused.'
    } elseif ($daysSince -gt $StaleDaysThreshold) {
        $findings += New-SecurityFinding -Category 'Guest Access' -Resource $guest.UserPrincipalName `
            -Severity 'High' `
            -Finding "Guest inactive for $daysSince days (last sign-in $lastSignIn)." `
            -Recommendation 'Remove stale guest accounts as part of periodic access recertification.'
    }

    if ($ApprovedDomains.Count -gt 0 -and $domain -and ($ApprovedDomains -notcontains $domain)) {
        $findings += New-SecurityFinding -Category 'Guest Access' -Resource $guest.UserPrincipalName `
            -Severity 'Medium' `
            -Finding "Guest domain '$domain' is not on the approved partner domain list." `
            -Recommendation 'Confirm business relationship or remove access; consider restricting via cross-tenant access settings.'
    }

    try {
        $memberships = Get-MgUserMemberOf -UserId $guest.Id -All
        $groupCount = ($memberships | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' }).Count
        if ($groupCount -gt 5) {
            $findings += New-SecurityFinding -Category 'Guest Access' -Resource $guest.UserPrincipalName `
                -Severity 'Medium' `
                -Finding "Guest is a member of $groupCount groups, which may grant broader access than intended." `
                -Recommendation 'Review group memberships and apply least-privilege / dedicated guest access groups.'
        }
    } catch {
        Write-SecurityLog "Could not enumerate memberships for $($guest.UserPrincipalName): $_" -Level WARN
    }
}

Write-SecurityLog "Audited $($guests.Count) guest accounts, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Entra-ID-Guest-User-Audit' -OutputPath $OutputPath
$findings | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
