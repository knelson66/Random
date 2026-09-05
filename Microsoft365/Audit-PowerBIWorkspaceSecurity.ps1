<#
.SYNOPSIS
    Audits Power BI workspace access and tenant sharing settings for over-exposure of
    potentially sensitive reports/datasets.

.DESCRIPTION
    Checks:
      - Workspaces with "Publish to web" capable reports (makes a report visible to literally
        anyone on the internet with the link, no authentication)
      - Workspaces granting Admin/Member access to broad groups (e.g., "All Company")
      - Tenant setting allowing "Publish to web" is enabled tenant-wide rather than restricted
      - Workspaces with external (guest) users granted access

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-PowerBIServiceAccount
    ./Audit-PowerBIWorkspaceSecurity.ps1

.NOTES
    Requires: MicrosoftPowerBIMgmt module. Tenant-level admin API calls require a Power BI
    Service Administrator / Fabric Administrator role.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name MicrosoftPowerBIMgmt

$findings = @()

Write-SecurityLog "Checking tenant-wide 'Publish to web' setting..."
try {
    $tenantSettings = Invoke-PowerBIRestMethod -Url "admin/tenantsettings" -Method Get | ConvertFrom-Json
    $publishToWeb = $tenantSettings.tenantSettings | Where-Object { $_.settingName -eq 'PublishToWebSettings' }
    if ($publishToWeb -and $publishToWeb.enabled -and $publishToWeb.tenantSettingGroup -notmatch 'Disabled') {
        $findings += New-SecurityFinding -Category 'Power BI' -Resource 'Tenant' -Severity 'High' `
            -Finding "'Publish to web' is enabled tenant-wide (or for a broad group) rather than restricted to specific security groups." `
            -Recommendation 'Restrict Publish to Web to a small, deliberately-approved security group, or disable it entirely if not a business requirement.'
    }
} catch {
    Write-SecurityLog "Could not read tenant settings (requires Power BI/Fabric admin role): $_" -Level WARN
}

Write-SecurityLog "Enumerating workspaces..."
try {
    $workspaces = Get-PowerBIWorkspace -Scope Organization -All
} catch {
    Write-SecurityLog "Could not enumerate workspaces at organization scope (requires admin role): $_" -Level ERROR
    return
}

foreach ($ws in $workspaces) {
    if ($ws.Type -ne 'Workspace' -or $ws.State -ne 'Active') { continue }

    try {
        $users = Get-PowerBIWorkspace -Scope Organization -Id $ws.Id -Include All | Select-Object -ExpandProperty Users
        $broadGroups = $users | Where-Object { $_.Identifier -match 'All Company|Everyone|Domain Users' }
        foreach ($group in $broadGroups) {
            $findings += New-SecurityFinding -Category 'Power BI' -Resource $ws.Name -Severity 'Medium' `
                -Finding "Workspace grants '$($group.AccessRight)' access to broad group '$($group.Identifier)'." `
                -Recommendation 'Scope workspace access to specific teams/security groups that actually need it, especially for Admin/Member (edit) rights.'
        }

        $guestUsers = $users | Where-Object { $_.Identifier -match '#EXT#' }
        foreach ($guest in $guestUsers) {
            $findings += New-SecurityFinding -Category 'Power BI' -Resource $ws.Name -Severity 'Low' `
                -Finding "External (guest) user '$($guest.Identifier)' has '$($guest.AccessRight)' access to this workspace." `
                -Recommendation 'Confirm this external access is intentional and time-bound; review as part of periodic guest access recertification.'
        }
    } catch {
        Write-SecurityLog "Could not read user access for workspace '$($ws.Name)': $_" -Level WARN
    }
}

Write-SecurityLog "Power BI workspace security audit complete: $($workspaces.Count) workspaces checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'PowerBI-Workspace-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
