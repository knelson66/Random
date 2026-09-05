<#
.SYNOPSIS
    Audits GitHub organization security settings: 2FA enforcement, branch protection,
    secret scanning, and outside collaborator exposure.

.DESCRIPTION
    Calls the GitHub REST API to check:
      - Two-factor authentication not required at the organization level
      - Repositories with no branch protection on their default branch
      - Secret scanning / push protection not enabled on non-archived repositories
      - Outside collaborators with admin/write access to private repositories
      - Members holding organization Owner role beyond a reasonable count (should be a small,
        well-known set)

.PARAMETER Organization
    GitHub organization login (e.g., "contoso").

.PARAMETER Token
    A GitHub PAT (classic) or fine-grained token with org:read, repo, and admin:org read scopes.
    Prefer an environment variable over passing it on the command line.

.PARAMETER MaxOwners
    Flag if the organization has more than this many Owners. Default 5.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    ./Audit-GitHubOrgSecurity.ps1 -Organization "contoso" -Token $env:GITHUB_TOKEN

.NOTES
    Requires: a GitHub personal access token with appropriate org read scopes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Organization,
    [Parameter(Mandatory)][string]$Token,
    [int]$MaxOwners = 5,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

$headers = @{
    Authorization          = "Bearer $Token"
    Accept                 = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
}
$findings = @()

function Invoke-GitHubApi {
    param([string]$Uri)
    try {
        return Invoke-RestMethod -Uri $Uri -Headers $headers -Method GET -ErrorAction Stop
    } catch {
        Write-SecurityLog "GitHub API call failed ($Uri): $_" -Level ERROR
        return $null
    }
}

Write-SecurityLog "Checking organization security settings for '$Organization'..."
$org = Invoke-GitHubApi "https://api.github.com/orgs/$Organization"

if ($org -and $org.two_factor_requirement_enabled -ne $true) {
    $findings += New-SecurityFinding -Category 'GitHub' -Resource $Organization -Severity 'Critical' `
        -Finding 'Two-factor authentication is not required for organization members.' `
        -Recommendation 'Enable "Require two-factor authentication" in organization security settings.'
}

Write-SecurityLog "Checking organization owners..."
$owners = Invoke-GitHubApi "https://api.github.com/orgs/$Organization/members?role=admin&per_page=100"
if ($owners -and $owners.Count -gt $MaxOwners) {
    $findings += New-SecurityFinding -Category 'GitHub' -Resource $Organization -Severity 'Medium' `
        -Finding "Organization has $($owners.Count) Owners, above the recommended max of $MaxOwners." `
        -Recommendation 'Reduce standing Owner membership to a small, well-audited set; use team-level admin permissions for broader delegation.'
}

Write-SecurityLog "Checking outside collaborators..."
$outsideCollabs = Invoke-GitHubApi "https://api.github.com/orgs/$Organization/outside_collaborators?per_page=100"
foreach ($collab in $outsideCollabs) {
    $findings += New-SecurityFinding -Category 'GitHub' -Resource $collab.login -Severity 'Low' `
        -Finding 'Outside collaborator has repository access without organization membership.' `
        -Recommendation 'Periodically review outside collaborators; convert to a member with appropriate team access or remove if no longer needed.'
}

Write-SecurityLog "Checking repositories for branch protection and secret scanning..."
$page = 1
do {
    $repos = Invoke-GitHubApi "https://api.github.com/orgs/$Organization/repos?per_page=100&page=$page&type=all"
    foreach ($repo in $repos) {
        if ($repo.archived) { continue }

        $branchProtection = $null
        try {
            $branchProtection = Invoke-RestMethod -Uri "https://api.github.com/repos/$Organization/$($repo.name)/branches/$($repo.default_branch)/protection" -Headers $headers -Method GET -ErrorAction Stop
        } catch {
            # A 404 here means no protection is configured, which is itself the finding.
        }
        if (-not $branchProtection) {
            $findings += New-SecurityFinding -Category 'GitHub' -Resource $repo.full_name -Severity 'Medium' `
                -Finding "Default branch ('$($repo.default_branch)') has no branch protection rule." `
                -Recommendation 'Require pull request reviews and passing status checks before merging to the default branch.'
        }

        if ($repo.security_and_analysis) {
            if ($repo.security_and_analysis.secret_scanning.status -ne 'enabled') {
                $findings += New-SecurityFinding -Category 'GitHub' -Resource $repo.full_name -Severity 'High' `
                    -Finding 'Secret scanning is not enabled.' `
                    -Recommendation 'Enable secret scanning (and push protection) to catch committed credentials before/after they land in history.'
            } elseif ($repo.security_and_analysis.secret_scanning_push_protection.status -ne 'enabled') {
                $findings += New-SecurityFinding -Category 'GitHub' -Resource $repo.full_name -Severity 'Medium' `
                    -Finding 'Secret scanning is enabled but push protection is not.' `
                    -Recommendation 'Enable push protection to block commits containing detectable secrets before they are ever pushed.'
            }
        }
    }
    $page++
} while ($repos -and $repos.Count -eq 100)

Write-SecurityLog "GitHub organization security audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'GitHub-Org-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
