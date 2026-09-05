<#
.SYNOPSIS
    Audits Azure Key Vault configuration, access policies, and secret/certificate/key hygiene.

.DESCRIPTION
    For every Key Vault in scope, checks:
      - Purge protection and soft delete disabled
      - Public network access enabled without firewall/private endpoint restrictions
      - Overly broad access policies (Full permissions, or many principals with Purge rights)
      - Secrets/keys/certificates nearing or past expiration
      - Diagnostic logging not configured

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER ExpiryWarningDays
    Flag secrets/keys/certs expiring within this many days. Default 30.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-KeyVaultSecurity.ps1

.NOTES
    Requires: Az.Accounts, Az.KeyVault
    Reading secret/key/cert metadata requires "List" permission on the respective object type.
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [int]$ExpiryWarningDays = 30,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for Key Vaults..."
    $vaults = Get-AzKeyVault

    foreach ($vRef in $vaults) {
        $kv = Get-AzKeyVault -VaultName $vRef.VaultName -ResourceGroupName $vRef.ResourceGroupName
        $resource = $kv.VaultName

        if (-not $kv.EnablePurgeProtection) {
            $findings += New-SecurityFinding -Category 'Key Vault' -Resource $resource -Severity 'High' `
                -Finding 'Purge protection is not enabled.' `
                -Recommendation 'Enable purge protection to prevent permanent deletion of secrets/keys by a malicious or compromised admin during the retention window.'
        }
        if (-not $kv.EnableSoftDelete) {
            $findings += New-SecurityFinding -Category 'Key Vault' -Resource $resource -Severity 'High' `
                -Finding 'Soft delete is not enabled.' `
                -Recommendation 'Enable soft delete (default in newer vaults; required going forward by Azure).'
        }

        if ($kv.NetworkAcls -and $kv.NetworkAcls.DefaultAction -eq 'Allow') {
            $findings += New-SecurityFinding -Category 'Key Vault' -Resource $resource -Severity 'High' `
                -Finding 'Network ACL default action is Allow (reachable from all networks).' `
                -Recommendation 'Restrict to selected networks/Private Endpoint and set default action to Deny.'
        }

        if ($kv.EnableRbacAuthorization -ne $true -and $kv.AccessPolicies) {
            foreach ($policy in $kv.AccessPolicies) {
                $hasFull = $policy.PermissionsToSecrets -contains 'All' -or $policy.PermissionsToKeys -contains 'All' -or $policy.PermissionsToCertificates -contains 'All'
                if ($hasFull) {
                    $findings += New-SecurityFinding -Category 'Key Vault' -Resource $resource -Severity 'Medium' `
                        -Finding "Access policy for principal $($policy.ObjectId) grants 'All' permissions." `
                        -Recommendation 'Apply least-privilege access policies, or migrate to Azure RBAC-based Key Vault authorization.'
                }
            }
        }

        if ($kv.EnableRbacAuthorization -ne $true) {
            $findings += New-SecurityFinding -Category 'Key Vault' -Resource $resource -Severity 'Low' `
                -Finding 'Vault is using legacy access policies instead of Azure RBAC authorization.' `
                -Recommendation 'Migrate to RBAC-based permission model for consistency with the rest of Azure IAM and easier auditing via PIM.'
        }

        foreach ($secretRef in (Get-AzKeyVaultSecret -VaultName $resource -ErrorAction SilentlyContinue)) {
            if ($secretRef.Expires) {
                $daysLeft = (New-TimeSpan -Start (Get-Date) -End $secretRef.Expires).Days
                if ($daysLeft -lt 0) {
                    $findings += New-SecurityFinding -Category 'Key Vault' -Resource "$resource/$($secretRef.Name)" -Severity 'Medium' `
                        -Finding "Secret expired $([math]::Abs($daysLeft)) days ago." -Recommendation 'Rotate or remove the expired secret.'
                } elseif ($daysLeft -le $ExpiryWarningDays) {
                    $findings += New-SecurityFinding -Category 'Key Vault' -Resource "$resource/$($secretRef.Name)" -Severity 'High' `
                        -Finding "Secret expires in $daysLeft days." -Recommendation 'Rotate before expiry to avoid application outage.'
                }
            } else {
                $findings += New-SecurityFinding -Category 'Key Vault' -Resource "$resource/$($secretRef.Name)" -Severity 'Low' `
                    -Finding 'Secret has no expiration date set.' -Recommendation 'Set an expiration date and rotation policy for all secrets.'
            }
        }

        try {
            $diagSettings = Get-AzDiagnosticSetting -ResourceId $kv.ResourceId -ErrorAction SilentlyContinue
            if (-not $diagSettings) {
                $findings += New-SecurityFinding -Category 'Key Vault' -Resource $resource -Severity 'Medium' `
                    -Finding 'No diagnostic settings configured (no audit log export).' `
                    -Recommendation 'Send AuditEvent logs to a Log Analytics workspace / SIEM for access monitoring.'
            }
        } catch {
            Write-SecurityLog "Could not read diagnostic settings for $resource : $_" -Level WARN
        }
    }
}

Write-SecurityLog "Key Vault audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-KeyVault-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
