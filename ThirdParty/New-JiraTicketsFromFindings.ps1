<#
.SYNOPSIS
    Creates Jira issues from a security findings CSV/JSON report (as produced by any script in
    this toolkit), so remediation work lands directly in the team's existing ticket queue.

.DESCRIPTION
    Reads a findings file (CSV or JSON, matching the New-SecurityFinding schema: Category,
    Resource, Severity, Finding, Recommendation, Reference) and creates one Jira issue per
    finding via the REST API, mapping Severity to a Jira priority. Supports a minimum-severity
    filter so you don't flood the backlog with Low/Informational noise.

.PARAMETER FindingsPath
    Path to a .csv or .json findings file produced by Export-SecurityReport.

.PARAMETER JiraBaseUrl
    Your Jira Cloud site, e.g. "https://contoso.atlassian.net".

.PARAMETER ProjectKey
    The Jira project key to create issues in, e.g. "SEC".

.PARAMETER Email
    The Atlassian account email used for API authentication.

.PARAMETER ApiToken
    A Jira API token (id.atlassian.com/manage-profile/security/api-tokens). Prefer pulling
    this from a secret store/environment variable rather than passing it on the command line.

.PARAMETER MinimumSeverity
    Only create issues for findings at or above this severity. Default High.

.PARAMETER IssueType
    Jira issue type to create. Default "Task".

.EXAMPLE
    ./New-JiraTicketsFromFindings.ps1 -FindingsPath ./reports/Azure-KeyVault-Audit_20260101.json `
        -JiraBaseUrl "https://contoso.atlassian.net" -ProjectKey SEC -Email me@contoso.com -ApiToken $env:JIRA_TOKEN

.NOTES
    Requires: a Jira Cloud API token. Uses Jira REST API v3 (https://developer.atlassian.com/cloud/jira/platform/rest/v3/).
    This creates real tickets - review -WhatIf output (via -DryRun) before running against a live project.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FindingsPath,
    [Parameter(Mandatory)][string]$JiraBaseUrl,
    [Parameter(Mandatory)][string]$ProjectKey,
    [Parameter(Mandatory)][string]$Email,
    [Parameter(Mandatory)][string]$ApiToken,
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
    [string]$MinimumSeverity = 'High',
    [string]$IssueType = 'Task',
    [switch]$DryRun
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

if (-not (Test-Path $FindingsPath)) { throw "Findings file not found: $FindingsPath" }

$severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
$severityToPriority = @{ Critical = 'Highest'; High = 'High'; Medium = 'Medium'; Low = 'Low'; Informational = 'Lowest' }

$findings = if ($FindingsPath -like '*.json') {
    Get-Content -Raw $FindingsPath | ConvertFrom-Json
} else {
    Import-Csv $FindingsPath
}

$toCreate = $findings | Where-Object { $severityOrder[[string]$_.Severity] -le $severityOrder[$MinimumSeverity] }
Write-SecurityLog "$($toCreate.Count) of $($findings.Count) finding(s) meet the minimum severity ($MinimumSeverity) and will become Jira issues."

if ($toCreate.Count -eq 0) { return }

$authHeader = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$Email`:$ApiToken")) }
$createdIssues = @()

foreach ($finding in $toCreate) {
    $summary = "[$($finding.Severity)] $($finding.Category): $($finding.Resource)"
    if ($summary.Length -gt 255) { $summary = $summary.Substring(0, 252) + '...' }

    $bodyObject = @{
        fields = @{
            project   = @{ key = $ProjectKey }
            summary   = $summary
            issuetype = @{ name = $IssueType }
            priority  = @{ name = $severityToPriority[[string]$finding.Severity] }
            description = @{
                type    = 'doc'
                version = 1
                content = @(
                    @{ type = 'paragraph'; content = @(@{ type = 'text'; text = "Finding: $($finding.Finding)" }) },
                    @{ type = 'paragraph'; content = @(@{ type = 'text'; text = "Recommendation: $($finding.Recommendation)" }) },
                    @{ type = 'paragraph'; content = @(@{ type = 'text'; text = "Resource: $($finding.Resource) | Category: $($finding.Category) | Reference: $($finding.Reference)" }) }
                )
            }
        }
    }
    $body = $bodyObject | ConvertTo-Json -Depth 10

    if ($DryRun) {
        Write-SecurityLog "[DryRun] Would create issue: $summary" -Level INFO
        continue
    }

    try {
        $response = Invoke-RestMethod -Uri "$JiraBaseUrl/rest/api/3/issue" -Headers $authHeader -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop
        Write-SecurityLog "Created $($response.key): $summary" -Level SUCCESS
        $createdIssues += $response.key
    } catch {
        Write-SecurityLog "Failed to create issue for '$summary': $_" -Level ERROR
    }
}

Write-SecurityLog "Jira ticket creation complete: $($createdIssues.Count) issue(s) created." -Level SUCCESS
return $createdIssues
