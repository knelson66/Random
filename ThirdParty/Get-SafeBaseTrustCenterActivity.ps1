<#
.SYNOPSIS
    Pulls recent Trust Center access/questionnaire activity from SafeBase for review, and
    flags access requests pending approval past an SLA.

.DESCRIPTION
    Calls the SafeBase REST API to retrieve Trust Center visitor/access accounts and flags:
      - Access requests pending approval longer than a threshold (prospects/customers waiting
        on your security team to unblock a deal)
      - NDA-gated document access granted to a domain not matching any known customer/prospect
        pattern you supply (possible competitor or unrelated party fishing for your security posture)

.PARAMETER ApiKey
    A SafeBase API key (Settings > API in the SafeBase admin console). Prefer an environment
    variable over passing it on the command line.

.PARAMETER PendingApprovalSlaHours
    Flag pending access requests older than this many hours. Default 48.

.PARAMETER KnownDomainPatterns
    Optional array of wildcard patterns for expected visitor email domains (e.g. "*.com" is too
    broad to be useful - supply actual customer/prospect domains if you want this check to fire).

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    ./Get-SafeBaseTrustCenterActivity.ps1 -ApiKey $env:SAFEBASE_API_KEY -PendingApprovalSlaHours 24

.NOTES
    Requires: a SafeBase API key. The base URL, auth header, and field names below reflect
    SafeBase's published REST reference (docs.safebase.io, e.g. GET /api/ext/v1/rest/accounts)
    as of this writing - VERIFY current endpoint paths, auth header format, and response field
    names against https://docs.safebase.io before relying on this in production, since the
    author could not fetch live API documentation when writing this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ApiKey,
    [int]$PendingApprovalSlaHours = 48,
    [string[]]$KnownDomainPatterns = @(),
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

$baseUrl = "https://app.safebase.io/api/ext/v1/rest"
$headers = @{ Authorization = "Bearer $ApiKey" }
$findings = @()

function Invoke-SafeBaseApi {
    param([string]$Path)
    try {
        return Invoke-RestMethod -Uri "$baseUrl/$Path" -Headers $headers -Method GET -ErrorAction Stop
    } catch {
        Write-SecurityLog "SafeBase API call to '$Path' failed: $_" -Level ERROR
        return $null
    }
}

Write-SecurityLog "Retrieving Trust Center accounts/access requests from SafeBase..."
$accountsResponse = Invoke-SafeBaseApi -Path 'accounts'

if (-not $accountsResponse) {
    Write-SecurityLog "No data returned - verify the API key and confirm the endpoint path against current SafeBase docs." -Level ERROR
    return
}

$accounts = $accountsResponse.data ?? $accountsResponse.accounts ?? $accountsResponse
$now = Get-Date

foreach ($account in $accounts) {
    $email = $account.email ?? $account.contactEmail ?? 'unknown'
    $status = $account.status ?? $account.approvalStatus ?? $null
    $requestedAt = $account.createdAt ?? $account.requestedAt ?? $null
    $domain = if ($email -match '@(.+)$') { $Matches[1] } else { $null }

    if ($status -match 'pending' -and $requestedAt) {
        try {
            $ageHours = (New-TimeSpan -Start ([datetime]$requestedAt) -End $now).TotalHours
            if ($ageHours -gt $PendingApprovalSlaHours) {
                $findings += New-SecurityFinding -Category 'Trust Center Access (SafeBase)' -Resource $email -Severity 'Medium' `
                    -Finding "Trust Center access request has been pending approval for $([math]::Round($ageHours,1)) hours." `
                    -Recommendation 'Review and approve/deny the request; a slow security-review turnaround is a common friction point in sales cycles.'
            }
        } catch {
            Write-SecurityLog "Could not parse request timestamp for $email : $_" -Level WARN
        }
    }

    if ($KnownDomainPatterns.Count -gt 0 -and $domain) {
        $matchesKnown = $KnownDomainPatterns | Where-Object { $domain -like $_ }
        if (-not $matchesKnown) {
            $findings += New-SecurityFinding -Category 'Trust Center Access (SafeBase)' -Resource $email -Severity 'Low' `
                -Finding "Access granted/requested from domain '$domain', which does not match any known customer/prospect pattern." `
                -Recommendation 'Confirm this is a legitimate prospect/customer before approving access to NDA-gated security documentation.'
        }
    }
}

Write-SecurityLog "SafeBase Trust Center activity review complete: $($accounts.Count) accounts checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'SafeBase-TrustCenter-Activity-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
