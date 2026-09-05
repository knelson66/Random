<#
.SYNOPSIS
    Audits Azure Virtual Desktop host pool configuration for common security gaps.

.DESCRIPTION
    Checks each host pool and its session hosts for:
      - RDP security layer not set to a modern value (should use RDSTLS/negotiate with TLS,
        not plain RDP security layer)
      - No Conditional Access / MFA enforcement signal on the associated application group
        (checked indirectly by confirming the host pool isn't using deprecated custom RDP
        properties that bypass modern auth)
      - Session hosts in a "NoHeartbeat"/"Unavailable" status (silently unusable capacity that
        also often indicates a broken/uncontrolled host)
      - Host pool validation environment flag left enabled in what looks like a production pool
      - Start VM on Connect disabled where a large pool sits fully powered on 24/7 (cost/attack
        surface signal, not just a cost item - fewer running hosts is less exposure)

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-AVDHostPoolSecurity.ps1

.NOTES
    Requires: Az.Accounts, Az.DesktopVirtualization
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.DesktopVirtualization

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for AVD host pools..."
    $hostPools = Get-AzWvdHostPool

    foreach ($pool in $hostPools) {
        $rgName = ($pool.Id -split '/resourceGroups/')[1].Split('/')[0]
        $resource = $pool.Name

        if ($pool.CustomRdpProperty -match 'security layer:i:0' -or $pool.CustomRdpProperty -match 'authentication level:i:0') {
            $findings += New-SecurityFinding -Category 'AVD Host Pool' -Resource $resource -Severity 'High' `
                -Finding 'Custom RDP properties weaken the security/authentication layer (legacy RDP security or no server auth requirement).' `
                -Recommendation 'Remove these overrides; use the default negotiate/TLS security layer and require server authentication.'
        }

        if ($pool.ValidationEnvironment -eq $true) {
            $findings += New-SecurityFinding -Category 'AVD Host Pool' -Resource $resource -Severity 'Low' `
                -Finding 'Host pool is flagged as a validation environment (receives new AVD features first).' `
                -Recommendation 'Confirm this is intentional for a test pool; production pools should generally not run on the early-update ring.'
        }

        if ($pool.HostPoolType -eq 'Pooled' -and -not $pool.StartVMOnConnect) {
            $sessionHosts = Get-AzWvdSessionHost -HostPoolName $pool.Name -ResourceGroupName $rgName -ErrorAction SilentlyContinue
            if ($sessionHosts.Count -gt 3) {
                $findings += New-SecurityFinding -Category 'AVD Host Pool' -Resource $resource -Severity 'Low' `
                    -Finding "Start VM on Connect is disabled on a pooled host pool with $($sessionHosts.Count) session hosts - likely running all hosts 24/7." `
                    -Recommendation 'Enable Start VM on Connect to reduce the number of continuously-running, continuously-exposed hosts.'
            }
        }

        $sessionHosts = Get-AzWvdSessionHost -HostPoolName $pool.Name -ResourceGroupName $rgName -ErrorAction SilentlyContinue
        $unhealthy = $sessionHosts | Where-Object { $_.Status -in 'NoHeartbeat', 'Unavailable', 'UpgradeFailed' }
        foreach ($sessionHost in $unhealthy) {
            $hostName = ($sessionHost.Name -split '/')[-1]
            $findings += New-SecurityFinding -Category 'AVD Host Pool' -Resource "$resource/$hostName" -Severity 'Medium' `
                -Finding "Session host status is '$($sessionHost.Status)'." `
                -Recommendation 'Investigate and remediate (or remove) unhealthy session hosts; they reduce capacity and may indicate an uncontrolled or compromised host.'
        }
    }
}

Write-SecurityLog "AVD host pool audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AVD-HostPool-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
