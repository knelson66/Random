<#
.SYNOPSIS
    Audits Microsoft Defender for Cloud Apps (MDA) policy coverage via its REST API - file
    policies, activity policies, anomaly detection, and Cloud Discovery risk.

.DESCRIPTION
    Calls the Defender for Cloud Apps management API to check:
      - No file policy configured (sensitive file sharing/exposure goes undetected)
      - No activity policy configured for impossible travel / mass download / mass deletion
      - Built-in anomaly detection policies present but disabled
      - Cloud Discovery: count of "high risk" discovered apps (shadow IT) with active usage

.PARAMETER TenantUrl
    Your Defender for Cloud Apps tenant URL, e.g. "contoso.us.portal.cloudappsecurity.com".

.PARAMETER ApiToken
    An MDA API token (Settings > System > API tokens). Prefer pulling this from a secret
    store/environment variable rather than passing it on the command line.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    ./Audit-CloudAppSecurityPolicies.ps1 -TenantUrl "contoso.us.portal.cloudappsecurity.com" -ApiToken $env:MDA_API_TOKEN

.NOTES
    Requires: an MDA API token with at least read-only scope. See
    https://learn.microsoft.com/defender-cloud-apps/api-authentication for token setup.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantUrl,
    [Parameter(Mandatory)][string]$ApiToken,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

$headers = @{ Authorization = "Token $ApiToken" }
$base = "https://$TenantUrl/api/v1"
$findings = @()

function Invoke-MdaApi {
    param([string]$Path, [hashtable]$Body = $null)
    $uri = "$base/$Path"
    try {
        if ($Body) {
            return Invoke-RestMethod -Uri $uri -Headers $headers -Method POST -Body ($Body | ConvertTo-Json) -ContentType 'application/json' -ErrorAction Stop
        }
        return Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction Stop
    } catch {
        Write-SecurityLog "MDA API call to $Path failed: $_" -Level ERROR
        return $null
    }
}

Write-SecurityLog "Retrieving Defender for Cloud Apps policies..."
$policies = Invoke-MdaApi -Path 'policies/'

if ($policies -and $policies.data) {
    $filePolicies = $policies.data | Where-Object { $_.type -match 'file' }
    $activityPolicies = $policies.data | Where-Object { $_.type -match 'activity' }
    $anomalyPolicies = $policies.data | Where-Object { $_.type -match 'anomaly' }

    if (-not $filePolicies) {
        $findings += New-SecurityFinding -Category 'Defender for Cloud Apps' -Resource 'Tenant' -Severity 'Medium' `
            -Finding 'No file policies are configured.' `
            -Recommendation 'Create file policies to detect sensitive files shared externally/publicly across connected cloud apps.'
    }
    if (-not $activityPolicies) {
        $findings += New-SecurityFinding -Category 'Defender for Cloud Apps' -Resource 'Tenant' -Severity 'Medium' `
            -Finding 'No activity policies are configured.' `
            -Recommendation 'Create activity policies for scenarios like mass download, mass deletion, or impossible travel.'
    }

    $disabledAnomaly = $anomalyPolicies | Where-Object { $_.disabled -eq $true }
    foreach ($p in $disabledAnomaly) {
        $findings += New-SecurityFinding -Category 'Defender for Cloud Apps' -Resource $p.name -Severity 'Medium' `
            -Finding 'Built-in anomaly detection policy is disabled.' `
            -Recommendation 'Re-enable unless there is a specific, documented reason (e.g., excessive false positives being tuned).'
    }
} else {
    Write-SecurityLog "No policy data returned - verify the API token has the required scope." -Level WARN
}

Write-SecurityLog "Retrieving Cloud Discovery risk summary..."
$discoveredApps = Invoke-MdaApi -Path 'discovery/discovered_apps/'
if ($discoveredApps -and $discoveredApps.data) {
    $highRisk = $discoveredApps.data | Where-Object { $_.risk_score -and $_.risk_score -le 3 }
    if ($highRisk.Count -gt 0) {
        $findings += New-SecurityFinding -Category 'Defender for Cloud Apps' -Resource 'Cloud Discovery' -Severity 'Medium' `
            -Finding "$($highRisk.Count) discovered app(s) have a low risk score (<=3/10) and active usage in the environment." `
            -Recommendation 'Review the highest-usage low-score apps; sanction, block, or ask the business owner to justify continued use (classic shadow IT triage).'
    }
}

Write-SecurityLog "Defender for Cloud Apps policy audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'DefenderCloudApps-Policy-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
