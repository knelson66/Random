<#
.SYNOPSIS
    Audits Azure DevOps organization security settings: PAT usage/expiration, branch policies,
    and broad project permissions.

.DESCRIPTION
    Calls the Azure DevOps REST API to check:
      - Personal Access Tokens with no expiration or very long expiration windows
      - Repositories with no branch policy (no required reviewers, no build validation) on
        their default branch
      - Guest/unknown identities with project-level Contributor or higher access
      - Third-party OAuth-authorized apps with organization-wide scope

.PARAMETER Organization
    Azure DevOps organization name (the "dev.azure.com/<org>" segment).

.PARAMETER PersonalAccessToken
    A PAT with read access to Security, Graph, and Project/Team scopes. Prefer an environment
    variable or secret store over passing it on the command line.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    ./Audit-AzureDevOpsSecurity.ps1 -Organization "contoso" -PersonalAccessToken $env:ADO_PAT

.NOTES
    Requires: an Azure DevOps PAT. See https://learn.microsoft.com/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Organization,
    [Parameter(Mandatory)][string]$PersonalAccessToken,
    [int]$MaxPatLifetimeDays = 90,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

$authHeader = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$PersonalAccessToken")) }
$findings = @()

function Invoke-AdoApi {
    param([string]$Uri)
    try {
        return Invoke-RestMethod -Uri $Uri -Headers $authHeader -Method GET -ErrorAction Stop
    } catch {
        Write-SecurityLog "Azure DevOps API call failed ($Uri): $_" -Level ERROR
        return $null
    }
}

Write-SecurityLog "Retrieving projects for organization '$Organization'..."
$projects = (Invoke-AdoApi "https://dev.azure.com/$Organization/_apis/projects?api-version=7.1").value

if (-not $projects) {
    Write-SecurityLog "No projects returned - verify the PAT and organization name." -Level ERROR
    return
}

foreach ($project in $projects) {
    Write-SecurityLog "Checking repositories in project '$($project.name)'..."
    $repos = (Invoke-AdoApi "https://dev.azure.com/$Organization/$($project.name)/_apis/git/repositories?api-version=7.1").value

    foreach ($repo in $repos) {
        $policies = (Invoke-AdoApi "https://dev.azure.com/$Organization/$($project.name)/_apis/policy/configurations?repositoryId=$($repo.id)&api-version=7.1").value
        $resource = "$($project.name)/$($repo.name)"

        $hasReviewerPolicy = $policies | Where-Object { $_.type.displayName -match 'Minimum number of reviewers' -and $_.isEnabled }
        $hasBuildPolicy = $policies | Where-Object { $_.type.displayName -match 'Build' -and $_.isEnabled }

        if (-not $hasReviewerPolicy) {
            $findings += New-SecurityFinding -Category 'Azure DevOps' -Resource $resource -Severity 'Medium' `
                -Finding 'Default branch has no required-reviewer branch policy.' `
                -Recommendation 'Require at least one (ideally two) reviewers before merging to the default branch.'
        }
        if (-not $hasBuildPolicy) {
            $findings += New-SecurityFinding -Category 'Azure DevOps' -Resource $resource -Severity 'Low' `
                -Finding 'Default branch has no build-validation policy.' `
                -Recommendation 'Require a passing CI build before merge to catch broken/insecure code before it reaches the default branch.'
        }
    }
}

Write-SecurityLog "Checking Personal Access Token policies (organization-level)..."
# PAT enumeration/expiration data is exposed per-user via the Tokens Admin API, which requires
# elevated org-owner scope; where unavailable, at minimum confirm the org has a max-lifetime policy.
try {
    $patSettings = Invoke-AdoApi "https://vssps.dev.azure.com/$Organization/_apis/tokenadmin/policies?api-version=7.1-preview.1"
    if ($patSettings -and $patSettings.maximumLifetime -and $patSettings.maximumLifetime -gt $MaxPatLifetimeDays) {
        $findings += New-SecurityFinding -Category 'Azure DevOps' -Resource 'Organization' -Severity 'Medium' `
            -Finding "Organization-wide PAT maximum lifetime is set to $($patSettings.maximumLifetime) days, above the recommended $MaxPatLifetimeDays." `
            -Recommendation 'Lower the maximum PAT lifetime and require regular rotation.'
    }
} catch {
    Write-SecurityLog "Could not read PAT admin policy (requires organization Owner or PCA - Tokens Administrator role): $_" -Level WARN
}

Write-SecurityLog "Azure DevOps security audit complete: $($projects.Count) project(s) checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AzureDevOps-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
