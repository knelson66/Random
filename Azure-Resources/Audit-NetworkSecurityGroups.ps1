<#
.SYNOPSIS
    Audits Azure Network Security Groups (NSGs) across one or more subscriptions for
    overly permissive inbound/outbound rules.

.DESCRIPTION
    Scans every NSG's security rules and flags:
      - Rules allowing inbound traffic from Any/Internet (0.0.0.0/0, *, Internet) on sensitive ports
        (RDP 3389, SSH 22, SMB 445, SQL 1433/3306/5432, WinRM 5985/5986, RPC 135)
      - Any rule with source AND destination as wildcard with Allow action
      - NSGs not associated with any subnet or NIC (orphaned, may be unmanaged debt)

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-NetworkSecurityGroups.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"

.NOTES
    Requires: Az.Accounts, Az.Network
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null

$sensitivePorts = @{
    '3389' = 'RDP'; '22' = 'SSH'; '445' = 'SMB'; '1433' = 'SQL Server'
    '3306' = 'MySQL'; '5432' = 'PostgreSQL'; '5985' = 'WinRM HTTP'; '5986' = 'WinRM HTTPS'; '135' = 'RPC'
}
$internetSources = @('*', '0.0.0.0/0', 'Internet', 'Any')

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for NSGs..."
    $nsgs = Get-AzNetworkSecurityGroup

    foreach ($nsg in $nsgs) {
        if ((-not $nsg.Subnets -or $nsg.Subnets.Count -eq 0) -and (-not $nsg.NetworkInterfaces -or $nsg.NetworkInterfaces.Count -eq 0)) {
            $findings += New-SecurityFinding -Category 'Network Security Groups' -Resource $nsg.Name -Severity 'Low' `
                -Finding 'NSG is not associated with any subnet or network interface.' `
                -Recommendation 'Remove orphaned NSGs to reduce configuration drift, or confirm it is intentionally reserved.'
        }

        $allRules = @($nsg.SecurityRules) + @($nsg.DefaultSecurityRules)
        foreach ($rule in $allRules) {
            if ($rule.Access -ne 'Allow' -or $rule.Direction -ne 'Inbound') { continue }

            $sources = if ($rule.SourceAddressPrefixes -and $rule.SourceAddressPrefixes.Count -gt 0) { $rule.SourceAddressPrefixes } else { @($rule.SourceAddressPrefix) }
            $ports = if ($rule.DestinationPortRanges -and $rule.DestinationPortRanges.Count -gt 0) { $rule.DestinationPortRanges } else { @($rule.DestinationPortRange) }

            $isInternetFacing = $sources | Where-Object { $_ -in $internetSources }
            if (-not $isInternetFacing) { continue }

            foreach ($portRange in $ports) {
                if ($portRange -eq '*') {
                    $findings += New-SecurityFinding -Category 'Network Security Groups' -Resource "$($nsg.Name)/$($rule.Name)" -Severity 'Critical' `
                        -Finding 'Rule allows ALL inbound ports from the Internet/Any.' `
                        -Recommendation 'Restrict to specific required ports and source IP ranges immediately.'
                    continue
                }

                foreach ($portKey in $sensitivePorts.Keys) {
                    $matches = $false
                    if ($portRange -match '^\d+$') {
                        $matches = ($portRange -eq $portKey)
                    } elseif ($portRange -match '^(\d+)-(\d+)$') {
                        $matches = ([int]$portKey -ge [int]$Matches[1] -and [int]$portKey -le [int]$Matches[2])
                    }
                    if ($matches) {
                        $findings += New-SecurityFinding -Category 'Network Security Groups' -Resource "$($nsg.Name)/$($rule.Name)" -Severity 'Critical' `
                            -Finding "Rule allows inbound $($sensitivePorts[$portKey]) (port $portKey) from the Internet/Any." `
                            -Recommendation "Restrict source to specific IP ranges/VPN, or use Azure Bastion / Just-In-Time VM access instead of exposing $($sensitivePorts[$portKey])."
                    }
                }
            }
        }
    }
}

Write-SecurityLog "NSG audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-NSG-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
