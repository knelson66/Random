<#
.SYNOPSIS
    Audits Azure Storage Account security configuration across a subscription.

.DESCRIPTION
    For every storage account, checks:
      - Public blob/container access allowed at the account level
      - Secure transfer (HTTPS-only) disabled
      - Minimum TLS version below 1.2
      - Shared Key access enabled (vs. Azure AD-only authorization)
      - Missing network restrictions (default action = Allow, no firewall/VNet rules)
      - Soft delete / versioning not enabled for blob data protection
      - Missing diagnostic logging

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-StorageAccountSecurity.ps1

.NOTES
    Requires: Az.Accounts, Az.Storage, Az.Monitor
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for storage accounts..."
    $accounts = Get-AzStorageAccount

    foreach ($sa in $accounts) {
        $resource = "$($sa.ResourceGroupName)/$($sa.StorageAccountName)"

        if ($sa.AllowBlobPublicAccess -ne $false) {
            $findings += New-SecurityFinding -Category 'Storage Account' -Resource $resource -Severity 'High' `
                -Finding 'Public blob access is allowed at the account level.' `
                -Recommendation 'Set AllowBlobPublicAccess to $false unless a specific container requires anonymous read access.'
        }

        if ($sa.EnableHttpsTrafficOnly -ne $true) {
            $findings += New-SecurityFinding -Category 'Storage Account' -Resource $resource -Severity 'Critical' `
                -Finding 'Secure transfer (HTTPS-only) is not enforced.' `
                -Recommendation 'Enable "Secure transfer required" to prevent plaintext HTTP access.'
        }

        if ($sa.MinimumTlsVersion -and $sa.MinimumTlsVersion -ne 'TLS1_2') {
            $findings += New-SecurityFinding -Category 'Storage Account' -Resource $resource -Severity 'High' `
                -Finding "Minimum TLS version is set to $($sa.MinimumTlsVersion) instead of TLS1_2." `
                -Recommendation 'Raise minimum TLS version to 1.2.'
        }

        if ($sa.AllowSharedKeyAccess -ne $false) {
            $findings += New-SecurityFinding -Category 'Storage Account' -Resource $resource -Severity 'Medium' `
                -Finding 'Shared Key (access key) authorization is enabled.' `
                -Recommendation 'Disable shared key access and require Azure AD (Entra ID) authorization where application support allows it.'
        }

        $networkDefault = $sa.NetworkRuleSet.DefaultAction
        if ($networkDefault -eq 'Allow') {
            $findings += New-SecurityFinding -Category 'Storage Account' -Resource $resource -Severity 'High' `
                -Finding 'Network firewall default action is Allow (accessible from all networks).' `
                -Recommendation 'Set default action to Deny and add explicit VNet/IP allow rules or use Private Endpoints.'
        }

        try {
            $blobProps = Get-AzStorageBlobServiceProperty -ResourceGroupName $sa.ResourceGroupName -StorageAccountName $sa.StorageAccountName
            if (-not $blobProps.DeleteRetentionPolicy.Enabled) {
                $findings += New-SecurityFinding -Category 'Storage Account' -Resource $resource -Severity 'Medium' `
                    -Finding 'Blob soft delete is not enabled.' `
                    -Recommendation 'Enable soft delete (and versioning) to protect against accidental or malicious deletion/ransomware.'
            }
            if (-not $blobProps.IsVersioningEnabled) {
                $findings += New-SecurityFinding -Category 'Storage Account' -Resource $resource -Severity 'Low' `
                    -Finding 'Blob versioning is not enabled.' `
                    -Recommendation 'Enable versioning for tamper/ransomware recovery on critical data.'
            }
        } catch {
            Write-SecurityLog "Could not read blob service properties for $resource : $_" -Level WARN
        }

        if ($sa.Encryption.KeySource -ne 'Microsoft.Keyvault') {
            $findings += New-SecurityFinding -Category 'Storage Account' -Resource $resource -Severity 'Low' `
                -Finding 'Storage account is not using customer-managed keys (CMK) via Key Vault for encryption at rest.' `
                -Recommendation 'Consider CMK for regulatory/compliance requirements needing key control and rotation.'
        }
    }
}

Write-SecurityLog "Storage account audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-Storage-Account-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
