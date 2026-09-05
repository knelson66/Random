<#
.SYNOPSIS
    Runs a selected suite of audit scripts from this toolkit end-to-end and produces one
    consolidated HTML/CSV report, in addition to each script's individual report.

.DESCRIPTION
    Acts as a lightweight orchestrator: given one or more categories (Azure resource security,
    Entra ID, Active Directory, Microsoft 365, Vulnerability Management, Compliance), it runs the
    corresponding scripts that don't require extra mandatory parameters, collects their finding
    objects, and writes a single combined report alongside the individual ones. Assumes you have
    already authenticated with Connect-SecurityToolkit.ps1 (or the individual Connect-* cmdlets)
    for the services relevant to the categories you select.

.PARAMETER Categories
    One or more of: Azure, EntraID, ActiveDirectory, Microsoft365, VulnerabilityManagement,
    Compliance, All. Default is All.

.PARAMETER OutputPath
    Directory to write reports to. Default is ./reports.

.EXAMPLE
    ./Connect-SecurityToolkit.ps1 -Services Azure, Graph
    ./Invoke-FullSecurityAudit.ps1 -Categories Azure, EntraID

.NOTES
    Scripts that require mandatory parameters unique to an environment (e.g. Windows Update scans
    against specific hosts, Defender device isolation) are intentionally excluded from the
    orchestrator and should be run individually.
#>
[CmdletBinding()]
param(
    [ValidateSet('Azure', 'EntraID', 'ActiveDirectory', 'Microsoft365', 'VulnerabilityManagement', 'Compliance', 'All')]
    [string[]]$Categories = @('All'),

    [string]$OutputPath = "./reports"
)

Import-Module (Join-Path $PSScriptRoot "modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1") -Force

if ($Categories -contains 'All') {
    $Categories = @('Azure', 'EntraID', 'ActiveDirectory', 'Microsoft365', 'VulnerabilityManagement', 'Compliance')
}

$scriptMap = @{
    'Azure' = @(
        'Azure-Resources/Audit-NetworkSecurityGroups.ps1',
        'Azure-Resources/Audit-StorageAccountSecurity.ps1',
        'Azure-Resources/Audit-KeyVaultSecurity.ps1',
        'Azure-Resources/Audit-PublicIPExposure.ps1',
        'Azure-Resources/Audit-RBACAssignments.ps1',
        'Azure-Resources/Audit-VMDiskEncryption.ps1',
        'Azure-Resources/Get-DefenderForCloudSecureScore.ps1'
    )
    'EntraID' = @(
        'EntraID-AzureAD/Audit-PrivilegedRoleAssignments.ps1',
        'EntraID-AzureAD/Audit-MFAStatus.ps1',
        'EntraID-AzureAD/Audit-GuestUsers.ps1',
        'EntraID-AzureAD/Audit-ConditionalAccessPolicies.ps1',
        'EntraID-AzureAD/Audit-AppRegistrationSecrets.ps1'
    )
    'ActiveDirectory' = @(
        'ActiveDirectory/Audit-StaleADAccounts.ps1',
        'ActiveDirectory/Audit-PrivilegedGroupMembership.ps1',
        'ActiveDirectory/Audit-DomainPasswordPolicy.ps1',
        'ActiveDirectory/Find-KerberoastableAccounts.ps1',
        'ActiveDirectory/Find-ASREPRoastableAccounts.ps1'
    )
    'Microsoft365' = @(
        'Microsoft365/Audit-ExchangeOnlineSecurity.ps1',
        'Microsoft365/Audit-MailboxDelegationAndInboxRules.ps1',
        'Microsoft365/Audit-SharePointExternalSharing.ps1',
        'Microsoft365/Audit-TeamsExternalAccess.ps1'
    )
    'VulnerabilityManagement' = @(
        'VulnerabilityManagement/Get-DefenderTVMVulnerabilities.ps1',
        'VulnerabilityManagement/Export-DefenderSoftwareInventory.ps1'
    )
    'Compliance' = @(
        'Compliance/Audit-AzurePolicyCompliance.ps1',
        'Compliance/Test-WindowsSecurityBaseline.ps1'
    )
}

$allFindings = @()

foreach ($category in $Categories) {
    foreach ($relativePath in $scriptMap[$category]) {
        $fullPath = Join-Path $PSScriptRoot $relativePath
        if (-not (Test-Path $fullPath)) {
            Write-SecurityLog "Script not found, skipping: $relativePath" -Level WARN
            continue
        }

        Write-SecurityLog "==== Running $relativePath ====" -Level INFO
        try {
            $findings = & $fullPath -OutputPath $OutputPath
            if ($findings) { $allFindings += $findings }
        } catch {
            Write-SecurityLog "Script $relativePath failed: $_" -Level ERROR
        }
    }
}

if ($allFindings.Count -gt 0) {
    Write-SecurityLog "Writing consolidated report across $($Categories -join ', ')..." -Level INFO
    $allFindings | Export-SecurityReport -Title 'Consolidated-Security-Audit' -OutputPath $OutputPath
}

$summary = $allFindings | Group-Object Severity | Sort-Object @{Expression={
    switch ($_.Name) { 'Critical' {0} 'High' {1} 'Medium' {2} 'Low' {3} default {4} }
}}
Write-SecurityLog "Full audit run complete. Findings by severity:" -Level SUCCESS
$summary | Select-Object Name, Count | Format-Table -AutoSize
