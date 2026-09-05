<#
.SYNOPSIS
    Audits Azure SQL Database/Server security configuration: firewall rules, auditing,
    Advanced Threat Protection, TDE, and Entra ID authentication.

.DESCRIPTION
    For every SQL Server (and its databases) in scope, checks:
      - Firewall rule allowing 0.0.0.0-255.255.255.255 (Allow all Azure services, or fully open)
      - Auditing not enabled at the server level
      - Microsoft Defender for SQL (Advanced Threat Protection) not enabled
      - Transparent Data Encryption disabled on a database
      - No Entra ID admin configured (SQL-auth-only server relies solely on SQL logins)
      - Public network access enabled with no private endpoint

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-SQLDatabaseSecurity.ps1

.NOTES
    Requires: Az.Accounts, Az.Sql
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.Sql

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for Azure SQL servers..."
    $servers = Get-AzSqlServer

    foreach ($server in $servers) {
        $resource = "$($server.ResourceGroupName)/$($server.ServerName)"

        if ($server.PublicNetworkAccess -eq 'Enabled') {
            $firewallRules = Get-AzSqlServerFirewallRule -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName
            $openRule = $firewallRules | Where-Object { $_.StartIpAddress -eq '0.0.0.0' -and $_.EndIpAddress -eq '255.255.255.255' }
            if ($openRule) {
                $findings += New-SecurityFinding -Category 'Azure SQL' -Resource $resource -Severity 'Critical' `
                    -Finding 'Firewall rule allows connections from ALL IP addresses (0.0.0.0-255.255.255.255).' `
                    -Recommendation 'Remove this rule; restrict to specific known IP ranges or use Private Link instead.'
            }
            $findings += New-SecurityFinding -Category 'Azure SQL' -Resource $resource -Severity 'Medium' `
                -Finding 'Public network access is enabled.' `
                -Recommendation 'Disable public network access and connect via Private Endpoint where feasible.'
        }

        if (-not $server.Identity) {
            $findings += New-SecurityFinding -Category 'Azure SQL' -Resource $resource -Severity 'Low' `
                -Finding 'Server has no managed identity, which some security features (e.g., certain TDE/CMK configurations) require.' `
                -Recommendation 'Enable a system-assigned managed identity if using customer-managed keys or other identity-dependent features.'
        }

        try {
            $aadAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction Stop
            if (-not $aadAdmin) {
                $findings += New-SecurityFinding -Category 'Azure SQL' -Resource $resource -Severity 'Medium' `
                    -Finding 'No Entra ID administrator is configured; the server relies solely on SQL authentication.' `
                    -Recommendation 'Configure an Entra ID admin and prefer Entra ID authentication over SQL logins where possible.'
            }
        } catch {
            Write-SecurityLog "Could not check Entra ID admin for $resource : $_" -Level WARN
        }

        try {
            $auditingPolicy = Get-AzSqlServerAudit -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction Stop
            if ($auditingPolicy.BlobStorageTargetState -ne 'Enabled' -and $auditingPolicy.LogAnalyticsTargetState -ne 'Enabled' -and $auditingPolicy.EventHubTargetState -ne 'Enabled') {
                $findings += New-SecurityFinding -Category 'Azure SQL' -Resource $resource -Severity 'High' `
                    -Finding 'Server-level auditing is not enabled to any target (storage/Log Analytics/Event Hub).' `
                    -Recommendation 'Enable auditing so query/access activity is retained for investigation and compliance.'
            }
        } catch {
            Write-SecurityLog "Could not check auditing policy for $resource : $_" -Level WARN
        }

        try {
            $atp = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction Stop
            if ($atp.ThreatDetectionState -ne 'Enabled') {
                $findings += New-SecurityFinding -Category 'Azure SQL' -Resource $resource -Severity 'High' `
                    -Finding 'Microsoft Defender for SQL (Advanced Threat Protection) is not enabled.' `
                    -Recommendation 'Enable Defender for SQL to detect SQL injection, anomalous access, and other database threats.'
            }
        } catch {
            Write-SecurityLog "Could not check Advanced Threat Protection for $resource : $_" -Level WARN
        }

        $databases = Get-AzSqlDatabase -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName | Where-Object { $_.DatabaseName -ne 'master' }
        foreach ($db in $databases) {
            try {
                $tde = Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -DatabaseName $db.DatabaseName -ErrorAction Stop
                if ($tde.State -ne 'Enabled') {
                    $findings += New-SecurityFinding -Category 'Azure SQL' -Resource "$resource/$($db.DatabaseName)" -Severity 'High' `
                        -Finding 'Transparent Data Encryption (TDE) is disabled.' `
                        -Recommendation 'Enable TDE to encrypt data at rest.'
                }
            } catch {
                Write-SecurityLog "Could not check TDE for $resource/$($db.DatabaseName): $_" -Level WARN
            }
        }
    }
}

Write-SecurityLog "Azure SQL audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-SQL-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
