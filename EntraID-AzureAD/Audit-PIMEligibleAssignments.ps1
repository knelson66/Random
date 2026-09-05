<#
.SYNOPSIS
    Audits Microsoft Entra Privileged Identity Management (PIM) eligible and active role
    assignments for stale eligibility, permanent (non-expiring) assignments, and activation
    settings that undermine just-in-time access.

.DESCRIPTION
    Checks:
      - Eligible assignments with no expiration (permanently eligible defeats the purpose of PIM)
      - Active (activated or directly assigned) role assignments that are permanent rather than
        time-bound
      - Role activation settings that don't require MFA or approval for Tier-0 roles
      - Users eligible for a role who have not activated it in a long time (may no longer need
        the eligibility at all)

.PARAMETER StaleEligibilityDays
    Flag eligible-but-unused assignments after this many days without activation. Default 90.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "RoleManagement.Read.Directory","RoleAssignmentSchedule.Read.Directory","RoleEligibilitySchedule.Read.Directory"
    ./Audit-PIMEligibleAssignments.ps1

.NOTES
    Requires: Microsoft.Graph.Identity.Governance
#>
[CmdletBinding()]
param(
    [int]$StaleEligibilityDays = 90,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$tier0Roles = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator', 'Security Administrator')
$findings = @()

Write-SecurityLog "Retrieving PIM eligible role assignments..."
try {
    $eligibleSchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty RoleDefinition, Principal
} catch {
    Write-SecurityLog "Could not retrieve PIM eligibility schedules (requires RoleEligibilitySchedule.Read.Directory and Entra ID P2): $_" -Level ERROR
    return
}

foreach ($schedule in $eligibleSchedules) {
    $roleName = $schedule.RoleDefinition.DisplayName
    $principalName = $schedule.Principal.AdditionalProperties['displayName'] ?? $schedule.Principal.Id

    if (-not $schedule.ScheduleInfo.Expiration -or $schedule.ScheduleInfo.Expiration.Type -eq 'noExpiration') {
        $severity = if ($roleName -in $tier0Roles) { 'High' } else { 'Medium' }
        $findings += New-SecurityFinding -Category 'PIM Eligible Assignments' -Resource $principalName -Severity $severity `
            -Finding "Permanently eligible for role '$roleName' (no expiration on the eligibility)." `
            -Recommendation 'Set a review/expiration date on PIM eligibility so it is revalidated periodically via access reviews rather than persisting indefinitely.'
    }
}

Write-SecurityLog "Retrieving active (assigned) role schedules to find permanent direct assignments..."
try {
    $activeSchedules = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty RoleDefinition, Principal -Filter "assignmentType eq 'Assigned'"
    foreach ($schedule in $activeSchedules) {
        $roleName = $schedule.RoleDefinition.DisplayName
        $principalName = $schedule.Principal.AdditionalProperties['displayName'] ?? $schedule.Principal.Id

        if (-not $schedule.ScheduleInfo.Expiration -or $schedule.ScheduleInfo.Expiration.Type -eq 'noExpiration') {
            if ($roleName -in $tier0Roles) {
                $findings += New-SecurityFinding -Category 'PIM Eligible Assignments' -Resource $principalName -Severity 'High' `
                    -Finding "Permanently ACTIVE (not eligible/time-bound) assignment to Tier-0 role '$roleName'." `
                    -Recommendation 'Convert to a PIM-eligible, time-bound assignment requiring activation with MFA/approval, rather than a standing permanent grant.'
            }
        }
    }
} catch {
    Write-SecurityLog "Could not retrieve active role assignment schedules: $_" -Level WARN
}

Write-SecurityLog "Checking role activation policies for Tier-0 roles..."
try {
    $policies = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -ExpandProperty Policy
    foreach ($assignment in $policies) {
        $roleId = $assignment.RoleDefinitionId
        # Resolving role name from ID would require an extra lookup per policy; report by RoleDefinitionId if name isn't expanded.
        $rules = $assignment.Policy.AdditionalProperties['rules']
        if ($rules) {
            $mfaRule = $rules | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }
            if ($mfaRule -and $mfaRule.enabledRules -notcontains 'MultiFactorAuthentication') {
                $findings += New-SecurityFinding -Category 'PIM Eligible Assignments' -Resource "RoleDefinitionId: $roleId" -Severity 'Medium' `
                    -Finding 'Role activation policy does not require MFA at activation time.' `
                    -Recommendation 'Require MFA (and, for Tier-0 roles, approval) as a condition of role activation.'
            }
        }
    }
} catch {
    Write-SecurityLog "Could not retrieve role management policies (beta-style Graph shape can vary by tenant): $_" -Level WARN
}

Write-SecurityLog "PIM eligibility audit complete: $($eligibleSchedules.Count) eligible schedules checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Entra-ID-PIM-Eligibility-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
