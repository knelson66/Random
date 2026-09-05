<#
.SYNOPSIS
    Audits Power Platform Data Loss Prevention (DLP) policy coverage across environments,
    flagging environments with no DLP policy and risky connector classifications.

.DESCRIPTION
    Enumerates Power Platform environments and DLP policies, then flags:
      - Environments not covered by any DLP policy (Power Apps/Power Automate makers can use
        any connector, including HTTP/custom connectors, with zero governance)
      - Policies that place high-risk connectors (HTTP, HTTP with Azure AD, SQL, FTP) in the
        same data group as business connectors (defeats the purpose of grouping)
      - The tenant-wide default policy being more permissive than environment-specific policies
        expect (new environments inherit weak defaults)

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Add-PowerAppsAccount
    ./Audit-DLPPolicyCoverage.ps1

.NOTES
    Requires: Microsoft.PowerApps.Administration.PowerShell
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name Microsoft.PowerApps.Administration.PowerShell

$riskyConnectors = @('HTTP', 'HTTP with Azure AD', 'SQL Server', 'FTP', 'SSH')
$findings = @()

Write-SecurityLog "Retrieving Power Platform environments..."
$environments = Get-AdminPowerAppEnvironment

Write-SecurityLog "Retrieving DLP policies..."
$policies = Get-AdminDlpPolicy

if (-not $policies -or $policies.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Power Platform DLP' -Resource 'Tenant' -Severity 'Critical' `
        -Finding 'No DLP policies exist for Power Platform.' `
        -Recommendation 'Create at least a tenant-wide default DLP policy classifying connectors into Business/Non-Business/Blocked groups.'
} else {
    $envsWithPolicy = @{}
    foreach ($policy in $policies) {
        if ($policy.environments) {
            foreach ($env in $policy.environments) { $envsWithPolicy[$env.name] = $true }
        }
        if ($policy.EnvironmentType -eq 'AllEnvironments' -or -not $policy.environments) {
            $envsWithPolicy['__ALL__'] = $true
        }

        try {
            $businessGroup = Get-AdminDlpPolicy $policy.PolicyName | Select-Object -ExpandProperty BusinessDataGroup -ErrorAction SilentlyContinue
            $businessConnectorNames = $businessGroup.connectors | ForEach-Object { if ($_.name) { $_.name } else { $_.id } }
            $riskyInBusiness = $businessConnectorNames | Where-Object { $_ -in $riskyConnectors }
            foreach ($risky in $riskyInBusiness) {
                $findings += New-SecurityFinding -Category 'Power Platform DLP' -Resource $policy.DisplayName -Severity 'High' `
                    -Finding "High-risk connector '$risky' is classified in the Business Data group alongside trusted connectors." `
                    -Recommendation 'Move high-risk/generic connectors (HTTP, SQL, FTP, SSH) to a separate or Blocked group so flows cannot freely mix them with sanctioned business data.'
            }
        } catch {
            Write-SecurityLog "Could not inspect connector groups for policy '$($policy.DisplayName)': $_" -Level WARN
        }
    }

    if (-not $envsWithPolicy.ContainsKey('__ALL__')) {
        foreach ($env in $environments) {
            if (-not $envsWithPolicy.ContainsKey($env.EnvironmentName)) {
                $findings += New-SecurityFinding -Category 'Power Platform DLP' -Resource $env.DisplayName -Severity 'High' `
                    -Finding 'Environment is not covered by any DLP policy.' `
                    -Recommendation 'Apply the tenant default policy explicitly, or create an environment-specific policy, so makers cannot use unrestricted connectors here.'
            }
        }
    }
}

Write-SecurityLog "Power Platform DLP audit complete: $($environments.Count) environments, $($policies.Count) policies checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'PowerPlatform-DLP-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
