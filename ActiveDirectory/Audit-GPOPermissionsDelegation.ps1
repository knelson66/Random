<#
.SYNOPSIS
    Audits Group Policy Object (GPO) permissions for delegation that would let a
    non-administrator edit or link policy - a common, overlooked privilege escalation path.

.DESCRIPTION
    For every GPO in the domain, checks ACLs for:
      - Non-privileged security principals (not Domain Admins/Enterprise Admins/SYSTEM/Domain
        Controllers) with Edit, Edit-Delete-Modify Security, or full control rights
      - "Authenticated Users", "Everyone", "Domain Users", or "Domain Computers" holding
        write-type permissions on any GPO (should only ever have Read + Apply Group Policy)

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    ./Audit-GPOPermissionsDelegation.ps1

.NOTES
    Requires: GroupPolicy and ActiveDirectory PowerShell modules (RSAT)
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name GroupPolicy
Assert-ModuleAvailable -Name ActiveDirectory

$expectedPrivileged = @('Domain Admins', 'Enterprise Admins', 'SYSTEM', 'ENTERPRISE DOMAIN CONTROLLERS', 'Group Policy Creator Owners')
$writePermissions = @('GpoEditDeleteModifySecurity', 'GpoEdit', 'GpoCustom')
$findings = @()

Write-SecurityLog "Enumerating all GPOs in the domain..."
$gpos = Get-GPO -All

foreach ($gpo in $gpos) {
    try {
        $permissions = Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop
    } catch {
        Write-SecurityLog "Could not read permissions for GPO '$($gpo.DisplayName)': $_" -Level WARN
        continue
    }

    foreach ($perm in $permissions) {
        $trusteeName = $perm.Trustee.Name
        $isExpected = $expectedPrivileged | Where-Object { $trusteeName -like "*$_*" }

        if ($trusteeName -in 'Authenticated Users', 'Everyone', 'Domain Users', 'Domain Computers') {
            if ($perm.Permission -in $writePermissions) {
                $findings += New-SecurityFinding -Category 'GPO Delegation' -Resource $gpo.DisplayName -Severity 'Critical' `
                    -Finding "Broad group '$trusteeName' has write-level permission '$($perm.Permission)' on this GPO." `
                    -Recommendation 'Remove write permissions from broad groups immediately; this allows any domain user/computer to modify policy applied domain-wide.'
            }
            continue
        }

        if (-not $isExpected -and $perm.Permission -in $writePermissions) {
            $findings += New-SecurityFinding -Category 'GPO Delegation' -Resource $gpo.DisplayName -Severity 'High' `
                -Finding "Non-standard principal '$trusteeName' has write-level permission '$($perm.Permission)' on this GPO." `
                -Recommendation 'Confirm this delegation is intentional and documented (e.g., a help desk OU-scoped policy); remove if it is unexplained standing access to a broadly-linked GPO.'
        }
    }

}

if ($findings.Count -eq 0) {
    $findings += New-SecurityFinding -Category 'GPO Delegation' -Resource 'Domain' -Severity 'Informational' `
        -Finding "Reviewed $($gpos.Count) GPOs; no unexpected write-level delegation found." -Recommendation 'None.'
}

Write-SecurityLog "GPO permissions audit complete: $($gpos.Count) GPOs checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AD-GPO-Permissions-Delegation-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
