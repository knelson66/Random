<#
.SYNOPSIS
    Correlates Microsoft Entra ID sign-in logs to surface suspicious authentication patterns for
    incident response and threat hunting.

.DESCRIPTION
    Pulls sign-in logs via Microsoft Graph over a lookback window and flags:
      - Impossible travel (same account, two sign-ins from geographically distant locations within
        an implausible time window)
      - A single account failing authentication many times in a short window (password spray/brute force)
      - Successful sign-ins flagged with Entra ID Identity Protection risk level Medium/High
      - Sign-ins from countries not on an allow-list, if supplied

.PARAMETER LookbackHours
    How many hours of sign-in history to analyze. Default 24.

.PARAMETER AllowedCountries
    Optional ISO country codes considered normal (e.g. "US","CA"). Sign-ins from other countries
    are flagged Medium.

.PARAMETER FailedAttemptThreshold
    Number of failed sign-ins for one account within the window to flag as possible brute force. Default 10.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All","IdentityRiskEvent.Read.All"
    ./Get-SuspiciousSignInActivity.ps1 -LookbackHours 24 -AllowedCountries "US","CA"

.NOTES
    Requires: Microsoft.Graph.Reports, Microsoft.Graph.Identity.SignIns
    Impossible-travel detection here uses a simple heuristic (great-circle distance / elapsed time
    vs. a maximum plausible speed) intended for triage - it is not a replacement for Identity
    Protection's native risk detections, which should always be reviewed as well.
#>
[CmdletBinding()]
param(
    [int]$LookbackHours = 24,
    [string[]]$AllowedCountries = @(),
    [int]$FailedAttemptThreshold = 10,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

function Get-HaversineDistanceKm {
    param([double]$Lat1, [double]$Lon1, [double]$Lat2, [double]$Lon2)
    $R = 6371.0
    $dLat = ($Lat2 - $Lat1) * [math]::PI / 180
    $dLon = ($Lon2 - $Lon1) * [math]::PI / 180
    $a = [math]::Sin($dLat / 2) * [math]::Sin($dLat / 2) +
         [math]::Cos($Lat1 * [math]::PI / 180) * [math]::Cos($Lat2 * [math]::PI / 180) *
         [math]::Sin($dLon / 2) * [math]::Sin($dLon / 2)
    $c = 2 * [math]::Atan2([math]::Sqrt($a), [math]::Sqrt(1 - $a))
    return $R * $c
}

$startTime = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-SecurityLog "Retrieving sign-in logs since $startTime..."

$filter = "createdDateTime ge $startTime"
$signIns = Get-MgAuditLogSignIn -Filter $filter -All

$findings = @()

# Failed sign-in bursts (brute force / password spray on a single account)
$failedGroups = $signIns | Where-Object { $_.Status.ErrorCode -ne 0 } | Group-Object UserPrincipalName
foreach ($group in $failedGroups) {
    if ($group.Count -ge $FailedAttemptThreshold) {
        $ips = ($group.Group | Select-Object -ExpandProperty IPAddress -Unique) -join ', '
        $findings += New-SecurityFinding -Category 'Suspicious Sign-In Activity' -Resource $group.Name -Severity 'High' `
            -Finding "$($group.Count) failed sign-in attempts in the last $LookbackHours hours from IP(s): $ips." `
            -Recommendation 'Investigate for brute force/password spray; consider forcing a password reset and reviewing Conditional Access lockout controls.'
    }
}

# Risky sign-ins per Identity Protection
$risky = $signIns | Where-Object { $_.RiskLevelDuringSignIn -in 'medium', 'high' -or $_.RiskLevelAggregated -in 'medium', 'high' }
foreach ($event in $risky) {
    $severity = if ($event.RiskLevelDuringSignIn -eq 'high' -or $event.RiskLevelAggregated -eq 'high') { 'Critical' } else { 'High' }
    $findings += New-SecurityFinding -Category 'Suspicious Sign-In Activity' -Resource $event.UserPrincipalName -Severity $severity `
        -Finding "Identity Protection flagged sign-in risk '$($event.RiskLevelDuringSignIn)' from $($event.Location.City), $($event.Location.CountryOrRegion) (IP $($event.IPAddress)) at $($event.CreatedDateTime)." `
        -Recommendation 'Review the risk detection details in Identity Protection; confirm/dismiss and remediate (force password reset, revoke sessions) if confirmed compromised.'
}

# Country allow-list check
if ($AllowedCountries.Count -gt 0) {
    $successful = $signIns | Where-Object { $_.Status.ErrorCode -eq 0 -and $_.Location.CountryOrRegion -and ($AllowedCountries -notcontains $_.Location.CountryOrRegion) }
    foreach ($event in $successful) {
        $findings += New-SecurityFinding -Category 'Suspicious Sign-In Activity' -Resource $event.UserPrincipalName -Severity 'Medium' `
            -Finding "Successful sign-in from unexpected country '$($event.Location.CountryOrRegion)' (IP $($event.IPAddress)) at $($event.CreatedDateTime)." `
            -Recommendation 'Confirm travel/VPN usage with the user; investigate further if unexplained.'
    }
}

# Impossible travel heuristic
Write-SecurityLog "Evaluating impossible-travel heuristic..."
$byUser = $signIns | Where-Object { $_.Status.ErrorCode -eq 0 -and $_.Location.GeoCoordinates } | Group-Object UserPrincipalName
foreach ($group in $byUser) {
    $sorted = $group.Group | Sort-Object CreatedDateTime
    for ($j = 1; $j -lt $sorted.Count; $j++) {
        $prev = $sorted[$j - 1]
        $curr = $sorted[$j]
        if (-not $prev.Location.GeoCoordinates -or -not $curr.Location.GeoCoordinates) { continue }

        $hours = (New-TimeSpan -Start $prev.CreatedDateTime -End $curr.CreatedDateTime).TotalHours
        if ($hours -le 0 -or $hours -gt 12) { continue }

        $distanceKm = Get-HaversineDistanceKm -Lat1 $prev.Location.GeoCoordinates.Latitude -Lon1 $prev.Location.GeoCoordinates.Longitude `
            -Lat2 $curr.Location.GeoCoordinates.Latitude -Lon2 $curr.Location.GeoCoordinates.Longitude
        $impliedSpeedKmh = $distanceKm / $hours

        if ($impliedSpeedKmh -gt 900 -and $distanceKm -gt 300) {
            $findings += New-SecurityFinding -Category 'Suspicious Sign-In Activity' -Resource $group.Name -Severity 'Critical' `
                -Finding "Impossible travel: sign-ins from $($prev.Location.City) and $($curr.Location.City) ($([math]::Round($distanceKm))km apart) within $([math]::Round($hours,1))h (implied speed $([math]::Round($impliedSpeedKmh))km/h)." `
                -Recommendation 'High-confidence account compromise indicator. Revoke sessions, force password reset, require MFA re-registration, and review recent mailbox/OAuth grant activity.'
        }
    }
}

Write-SecurityLog "Sign-in analysis complete: $($signIns.Count) sign-ins analyzed, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Suspicious-SignIn-Activity-Report' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
