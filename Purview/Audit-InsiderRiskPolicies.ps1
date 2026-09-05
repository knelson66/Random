<#
.SYNOPSIS
    Audits Microsoft Purview Insider Risk Management policy coverage and alert triage backlog.

.DESCRIPTION
    Checks:
      - No insider risk policy configured for common high-value scenarios (data theft by
        departing employees, data leaks, security policy violations)
      - Policies with no in-scope users/groups assigned (defined but covers nobody)
      - A large backlog of unresolved/unreviewed alerts (signal is being generated but not
        actioned, which defeats the purpose of the program)

.PARAMETER StaleAlertDaysThreshold
    Flag open alerts older than this many days as backlog risk. Default 14.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-IPPSSession
    ./Audit-InsiderRiskPolicies.ps1

.NOTES
    Requires: ExchangeOnlineManagement (Connect-IPPSSession). Insider Risk Management requires
    an E5/Compliance add-on license.
#>
[CmdletBinding()]
param(
    [int]$StaleAlertDaysThreshold = 14,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ExchangeOnlineManagement

$findings = @()

Write-SecurityLog "Retrieving Insider Risk Management policies..."
try {
    $policies = Get-InsiderRiskPolicy -ErrorAction Stop
} catch {
    Write-SecurityLog "Could not query insider risk policies (requires Connect-IPPSSession and an appropriate license/role): $_" -Level ERROR
    return
}

if (-not $policies -or $policies.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'Purview Insider Risk' -Resource 'Tenant' -Severity 'Medium' `
        -Finding 'No Insider Risk Management policies are configured.' `
        -Recommendation 'Configure policies for at least data theft by departing users and general data leaks, the two highest-value default templates.'
} else {
    foreach ($policy in $policies) {
        if (-not $policy.PriorityUserGroups -and -not $policy.UserGroups -and $policy.IncludeAllUsers -ne $true) {
            $findings += New-SecurityFinding -Category 'Purview Insider Risk' -Resource $policy.Name -Severity 'Medium' `
                -Finding 'Policy has no in-scope users/groups assigned.' `
                -Recommendation 'Assign the intended user scope, or remove the policy if unused.'
        }
    }
}

Write-SecurityLog "Checking insider risk alert backlog..."
try {
    $alerts = Get-InsiderRiskAlert -ErrorAction Stop
    $openAlerts = $alerts | Where-Object { $_.Status -in 'Active', 'InProgress', 'New' }
    $staleAlerts = $openAlerts | Where-Object {
        $_.CreatedDateTime -and (New-TimeSpan -Start $_.CreatedDateTime -End (Get-Date)).Days -gt $StaleAlertDaysThreshold
    }
    if ($staleAlerts.Count -gt 0) {
        $findings += New-SecurityFinding -Category 'Purview Insider Risk' -Resource 'Tenant' -Severity 'Medium' `
            -Finding "$($staleAlerts.Count) insider risk alert(s) have been open for more than $StaleAlertDaysThreshold days." `
            -Recommendation 'Triage the alert backlog; an insider risk program that never reviews its own alerts provides no actual protection.'
    }
} catch {
    Write-SecurityLog "Could not query insider risk alerts: $_" -Level WARN
}

Write-SecurityLog "Insider risk audit complete: $($policies.Count) policies checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Purview-InsiderRisk-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
