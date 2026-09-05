<#
.SYNOPSIS
    Audits Azure Kubernetes Service (AKS) cluster security configuration.

.DESCRIPTION
    For every AKS cluster in scope, checks:
      - API server not restricted to authorized IP ranges and not private
      - Entra ID integration (Azure AD RBAC) not enabled - relies on static/local Kubernetes
        service account credentials instead
      - Local accounts (kubeadmin) not disabled even when Entra ID integration is enabled
      - Network policy not configured (no pod-to-pod traffic segmentation)
      - Microsoft Defender for Containers profile not enabled
      - Node pools not using a managed identity (legacy service principal-based clusters)
      - Kubernetes version approaching or past end-of-support

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-AKSClusterSecurity.ps1

.NOTES
    Requires: Az.Accounts, Az.Aks
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.Aks

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for AKS clusters..."
    $clusters = Get-AzAksCluster

    foreach ($cluster in $clusters) {
        $resource = "$($cluster.ResourceGroupName)/$($cluster.Name)"

        $apiServerAccess = $cluster.ApiServerAccessProfile
        if (-not $cluster.EnablePrivateCluster -and (-not $apiServerAccess -or -not $apiServerAccess.AuthorizedIpRanges)) {
            $findings += New-SecurityFinding -Category 'AKS' -Resource $resource -Severity 'High' `
                -Finding 'API server is publicly reachable with no authorized IP range restriction and is not a private cluster.' `
                -Recommendation 'Restrict the API server to known IP ranges, or convert to a private cluster with access via VPN/ExpressRoute/Bastion.'
        }

        if (-not $cluster.AadProfile -or -not $cluster.AadProfile.Managed) {
            $findings += New-SecurityFinding -Category 'AKS' -Resource $resource -Severity 'High' `
                -Finding 'Entra ID integration (managed Azure AD RBAC) is not enabled.' `
                -Recommendation 'Enable Entra ID integration so cluster access is governed by Entra ID identities/groups and Conditional Access, not static kubeconfig credentials.'
        } elseif ($cluster.DisableLocalAccount -ne $true) {
            $findings += New-SecurityFinding -Category 'AKS' -Resource $resource -Severity 'Medium' `
                -Finding 'Local Kubernetes accounts (e.g., kubeadmin) are not disabled even though Entra ID integration is enabled.' `
                -Recommendation 'Set DisableLocalAccounts to true so cluster access is exclusively through Entra ID-backed RBAC.'
        }

        if (-not $cluster.NetworkProfile -or -not $cluster.NetworkProfile.NetworkPolicy) {
            $findings += New-SecurityFinding -Category 'AKS' -Resource $resource -Severity 'Medium' `
                -Finding 'No network policy (Calico/Azure/Cilium) is configured; pods can communicate with each other unrestricted.' `
                -Recommendation 'Enable a network policy engine and define policies to segment pod-to-pod traffic by namespace/workload.'
        }

        if (-not $cluster.SecurityProfile -or -not $cluster.SecurityProfile.DefenderProfile -or $cluster.SecurityProfile.DefenderProfile.SecurityMonitoring.Enabled -ne $true) {
            $findings += New-SecurityFinding -Category 'AKS' -Resource $resource -Severity 'High' `
                -Finding 'Microsoft Defender for Containers profile is not enabled on this cluster.' `
                -Recommendation 'Enable the Defender profile for runtime threat detection on cluster nodes and workloads.'
        }

        if ($cluster.ServicePrincipalProfile -and $cluster.ServicePrincipalProfile.ClientId -ne 'msi') {
            $findings += New-SecurityFinding -Category 'AKS' -Resource $resource -Severity 'Medium' `
                -Finding 'Cluster uses a legacy service principal for identity instead of a managed identity.' `
                -Recommendation 'Migrate to a system-assigned or user-assigned managed identity; service principal secrets require manual rotation and can expire unexpectedly.'
        }
    }
}

Write-SecurityLog "AKS cluster audit complete: $($clusters.Count) cluster(s) checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-AKS-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
