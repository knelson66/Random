<#
.SYNOPSIS
    Pulls discovered SaaS applications and risky OAuth grants from Nudge Security and converts
    them into this toolkit's standard findings format.

.DESCRIPTION
    Calls the Nudge Security REST API (https://api.nudgesecurity.io/api/1.0) to retrieve
    discovered apps and flags:
      - Unsanctioned/unmanaged apps with active recent usage (classic shadow IT)
      - Apps flagged by Nudge as having risky OAuth scopes or a poor security posture
      - Apps with no assigned business owner (nobody accountable for the relationship)

.PARAMETER ApiToken
    A Nudge Security API token (created under Settings > API Tokens in the Nudge console).
    Prefer an environment variable over passing it on the command line.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    ./Get-NudgeSecurityShadowIT.ps1 -ApiToken $env:NUDGE_API_TOKEN

.NOTES
    Requires: a Nudge Security API token. Base URL, auth scheme, and field names below reflect
    Nudge's published API surface (apps/search, accounts/search, events) as of this writing -
    VERIFY current endpoint paths, the exact bearer/header format, and response field names
    against https://help.nudgesecurity.com before relying on this in production, since the
    author could not fetch live API documentation when writing this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ApiToken,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

$baseUrl = "https://api.nudgesecurity.io/api/1.0"
$headers = @{
    Authorization = "Bearer $ApiToken"
    'Content-Type' = 'application/json'
}
$findings = @()

function Invoke-NudgeApi {
    param([string]$Path, [hashtable]$Body = @{})
    try {
        return Invoke-RestMethod -Uri "$baseUrl/$Path" -Headers $headers -Method POST -Body ($Body | ConvertTo-Json -Depth 5) -ErrorAction Stop
    } catch {
        Write-SecurityLog "Nudge Security API call to '$Path' failed: $_" -Level ERROR
        return $null
    }
}

Write-SecurityLog "Retrieving discovered apps from Nudge Security..."
$appsResponse = Invoke-NudgeApi -Path 'apps/search' -Body @{ limit = 500 }

if (-not $appsResponse) {
    Write-SecurityLog "No data returned - verify the API token and confirm the endpoint path against current Nudge docs." -Level ERROR
    return
}

$apps = $appsResponse.data ?? $appsResponse.results ?? $appsResponse

foreach ($app in $apps) {
    $name = $app.name ?? $app.app_name ?? 'Unknown app'
    $isSanctioned = $app.sanctioned ?? $app.is_sanctioned ?? $null
    $riskLevel = $app.risk_level ?? $app.security_risk ?? $null
    $owner = $app.owner ?? $app.business_owner ?? $null
    $userCount = $app.user_count ?? $app.account_count ?? 0

    if ($isSanctioned -eq $false -and [int]$userCount -gt 0) {
        $findings += New-SecurityFinding -Category 'Shadow IT (Nudge Security)' -Resource $name -Severity 'Medium' `
            -Finding "Unsanctioned app in active use by $userCount account(s)." `
            -Recommendation 'Review the app with its users; sanction with an owner, or block/offboard if not approved for business use.'
    }

    if ($riskLevel -match 'high|critical') {
        $findings += New-SecurityFinding -Category 'Shadow IT (Nudge Security)' -Resource $name -Severity 'High' `
            -Finding "Nudge Security flags this app's risk level as '$riskLevel'." `
            -Recommendation 'Review the specific risk factors in the Nudge console (OAuth scopes, breach history, compliance posture) and act accordingly.'
    }

    if (-not $owner -and [int]$userCount -gt 0) {
        $findings += New-SecurityFinding -Category 'Shadow IT (Nudge Security)' -Resource $name -Severity 'Low' `
            -Finding 'App has no assigned business owner.' `
            -Recommendation 'Assign an accountable owner so lifecycle decisions (renewal, offboarding, security review) have a clear driver.'
    }
}

Write-SecurityLog "Nudge Security shadow IT review complete: $($apps.Count) apps checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'NudgeSecurity-ShadowIT-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
