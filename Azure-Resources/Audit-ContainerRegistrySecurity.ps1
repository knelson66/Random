<#
.SYNOPSIS
    Audits Azure Container Registry (ACR) security configuration.

.DESCRIPTION
    For every registry in scope, checks:
      - Admin user account enabled (a shared, non-attributable credential instead of Entra ID/managed identity auth)
      - Public network access enabled with no IP restrictions or private endpoint
      - Anonymous pull access enabled
      - Microsoft Defender for Containers registry scanning not enabled
      - No retention policy configured for untagged manifests (unbounded storage growth and
        stale/unscanned image buildup)

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-ContainerRegistrySecurity.ps1

.NOTES
    Requires: Az.Accounts, Az.ContainerRegistry, Az.Security
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.ContainerRegistry

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for Container Registries..."
    $registries = Get-AzContainerRegistry

    foreach ($registry in $registries) {
        $resource = "$($registry.ResourceGroupName)/$($registry.Name)"

        if ($registry.AdminUserEnabled) {
            $findings += New-SecurityFinding -Category 'Container Registry' -Resource $resource -Severity 'High' `
                -Finding 'Admin user account is enabled (a shared, non-attributable credential).' `
                -Recommendation 'Disable the admin account; use Entra ID authentication or a managed identity with AcrPull/AcrPush role assignments instead.'
        }

        if ($registry.PublicNetworkAccess -eq 'Enabled') {
            $networkRuleSet = $registry.NetworkRuleSet
            if (-not $networkRuleSet -or $networkRuleSet.DefaultAction -eq 'Allow') {
                $findings += New-SecurityFinding -Category 'Container Registry' -Resource $resource -Severity 'High' `
                    -Finding 'Public network access is enabled with no restricting network rules (default action Allow).' `
                    -Recommendation 'Restrict to specific IP ranges/VNets, or disable public network access and use a Private Endpoint.'
            }
        }

        if ($registry.NetworkRuleBypassOptions -eq 'AzureServices' -and $registry.Sku.Name -eq 'Basic') {
            $findings += New-SecurityFinding -Category 'Container Registry' -Resource $resource -Severity 'Low' `
                -Finding 'Basic SKU does not support Private Endpoints; network restriction options are limited.' `
                -Recommendation 'Consider upgrading to Premium SKU if network isolation (Private Link) is required.'
        }

        try {
            $registryDetail = Invoke-AzRestMethod -Path "$($registry.Id)?api-version=2023-07-01" -Method GET
            $content = $registryDetail.Content | ConvertFrom-Json
            if ($content.properties.anonymousPullEnabled -eq $true) {
                $findings += New-SecurityFinding -Category 'Container Registry' -Resource $resource -Severity 'High' `
                    -Finding 'Anonymous pull access is enabled (any unauthenticated caller can pull images).' `
                    -Recommendation 'Disable anonymous pull unless this registry is intentionally hosting public images.'
            }
        } catch {
            Write-SecurityLog "Could not check anonymous pull setting for $resource : $_" -Level WARN
        }

        try {
            $retentionPolicy = Invoke-AzRestMethod -Path "$($registry.Id)/manifestRetentionPolicy?api-version=2023-07-01" -Method GET -ErrorAction Stop
            $retentionContent = $retentionPolicy.Content | ConvertFrom-Json
            if ($retentionContent.status -ne 'enabled') {
                $findings += New-SecurityFinding -Category 'Container Registry' -Resource $resource -Severity 'Low' `
                    -Finding 'No retention policy is configured for untagged manifests.' `
                    -Recommendation 'Enable a retention policy (Premium SKU) to automatically clean up untagged/stale images and cap unbounded storage growth.'
            }
        } catch {
            Write-SecurityLog "Could not check retention policy for $resource (feature requires Premium SKU): $_" -Level WARN
        }
    }

    try {
        $defenderPricing = Get-AzSecurityPricing -Name 'ContainerRegistry' -ErrorAction Stop
        if ($defenderPricing.PricingTier -ne 'Standard') {
            $findings += New-SecurityFinding -Category 'Container Registry' -Resource "Subscription $sub" -Severity 'High' `
                -Finding 'Microsoft Defender for Containers (registry vulnerability scanning) is not enabled at the subscription level.' `
                -Recommendation 'Enable Defender for Containers to scan pushed images for known vulnerabilities.'
        }
    } catch {
        Write-SecurityLog "Could not check Defender for Containers pricing tier for $sub : $_" -Level WARN
    }
}

Write-SecurityLog "Container Registry audit complete: $($registries.Count) registries checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-ContainerRegistry-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
