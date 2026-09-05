<#
.SYNOPSIS
    One-stop connection helper that authenticates to the Microsoft services this toolkit's
    scripts rely on, with the correct minimum scopes/permissions for read-only auditing.

.DESCRIPTION
    Connects to any combination of: Azure Resource Manager (Az), Microsoft Graph (Entra ID /
    Defender), Exchange Online, SharePoint Online, and Microsoft Teams - so you don't have to
    remember each module's connect cmdlet and scope list separately.

.PARAMETER Services
    One or more of: Azure, Graph, ExchangeOnline, SharePoint, Teams, All. Default is All.

.PARAMETER TenantId
    Optional tenant ID/domain to target explicitly (recommended in multi-tenant/delegated admin scenarios).

.PARAMETER SharePointAdminUrl
    Required if connecting to SharePoint, e.g. https://contoso-admin.sharepoint.com

.EXAMPLE
    ./Connect-SecurityToolkit.ps1 -Services Azure, Graph

.EXAMPLE
    ./Connect-SecurityToolkit.ps1 -Services All -TenantId contoso.onmicrosoft.com -SharePointAdminUrl https://contoso-admin.sharepoint.com

.NOTES
    This script only requests READ-oriented scopes needed for the audit scripts in this repo.
    The IncidentResponse/Invoke-DefenderDeviceIsolation.ps1 script requires the additional
    Machine.Isolate scope, which is intentionally NOT requested here by default since it grants
    a disruptive capability - request it explicitly if you need that script.
#>
[CmdletBinding()]
param(
    [ValidateSet('Azure', 'Graph', 'ExchangeOnline', 'SharePoint', 'Teams', 'All')]
    [string[]]$Services = @('All'),

    [string]$TenantId,
    [string]$SharePointAdminUrl
)

Import-Module (Join-Path $PSScriptRoot "modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1") -Force

if ($Services -contains 'All') {
    $Services = @('Azure', 'Graph', 'ExchangeOnline', 'SharePoint', 'Teams')
}

$graphScopes = @(
    'User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory',
    'UserAuthenticationMethod.Read.All', 'Policy.Read.All', 'Application.Read.All',
    'AuditLog.Read.Directory', 'AuditLog.Read.All', 'Reports.Read.All', 'IdentityRiskEvent.Read.All',
    'Vulnerability.Read.All'
)

foreach ($service in $Services) {
    switch ($service) {
        'Azure' {
            Write-SecurityLog "Connecting to Azure (Connect-AzAccount)..."
            Assert-ModuleAvailable -Name Az.Accounts
            if ($TenantId) { Connect-AzAccount -Tenant $TenantId | Out-Null } else { Connect-AzAccount | Out-Null }
            Write-SecurityLog "Connected as $((Get-AzContext).Account.Id) to tenant $((Get-AzContext).Tenant.Id)" -Level SUCCESS
        }
        'Graph' {
            Write-SecurityLog "Connecting to Microsoft Graph with read-only audit scopes..."
            Assert-ModuleAvailable -Name Microsoft.Graph.Authentication
            if ($TenantId) {
                Connect-MgGraph -TenantId $TenantId -Scopes $graphScopes -NoWelcome
            } else {
                Connect-MgGraph -Scopes $graphScopes -NoWelcome
            }
            Write-SecurityLog "Connected to Microsoft Graph as $((Get-MgContext).Account)" -Level SUCCESS
        }
        'ExchangeOnline' {
            Write-SecurityLog "Connecting to Exchange Online..."
            Assert-ModuleAvailable -Name ExchangeOnlineManagement
            if ($TenantId) { Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false } else { Connect-ExchangeOnline -ShowBanner:$false }
            Write-SecurityLog "Connected to Exchange Online." -Level SUCCESS
        }
        'SharePoint' {
            if (-not $SharePointAdminUrl) {
                Write-SecurityLog "Skipping SharePoint: -SharePointAdminUrl was not provided." -Level WARN
                continue
            }
            Write-SecurityLog "Connecting to SharePoint Online ($SharePointAdminUrl)..."
            Assert-ModuleAvailable -Name Microsoft.Online.SharePoint.PowerShell
            Connect-SPOService -Url $SharePointAdminUrl
            Write-SecurityLog "Connected to SharePoint Online." -Level SUCCESS
        }
        'Teams' {
            Write-SecurityLog "Connecting to Microsoft Teams..."
            Assert-ModuleAvailable -Name MicrosoftTeams
            if ($TenantId) { Connect-MicrosoftTeams -TenantId $TenantId | Out-Null } else { Connect-MicrosoftTeams | Out-Null }
            Write-SecurityLog "Connected to Microsoft Teams." -Level SUCCESS
        }
    }
}

Write-SecurityLog "All requested connections complete. You can now run scripts from the toolkit's category folders." -Level SUCCESS
