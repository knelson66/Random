<#
.SYNOPSIS
    Inventories all public IP addresses in a subscription and identifies what they're attached
    to, to catch unexpected internet-facing exposure.

.DESCRIPTION
    Lists every Public IP resource, resolves its attachment (VM NIC, Load Balancer, App Gateway,
    Bastion, unattached), and cross-references NSG rules on attached NICs to highlight resources
    that are both publicly reachable and have permissive inbound rules.

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-PublicIPExposure.ps1

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

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for public IPs..."
    $pips = Get-AzPublicIpAddress

    foreach ($pip in $pips) {
        $resource = "$($pip.ResourceGroupName)/$($pip.Name)"
        $ipConfigId = $pip.IpConfiguration.Id

        if (-not $ipConfigId) {
            $findings += New-SecurityFinding -Category 'Public IP Exposure' -Resource $resource -Severity 'Low' `
                -Finding "Unattached public IP ($($pip.IpAddress)) - not currently in use." `
                -Recommendation 'Release unused public IPs to reduce cost and attack surface.'
            continue
        }

        $attachmentType = switch -Wildcard ($ipConfigId) {
            '*networkInterfaces*'      { 'Network Interface (VM)' }
            '*loadBalancers*'          { 'Load Balancer' }
            '*applicationGateways*'    { 'Application Gateway' }
            '*bastionHosts*'           { 'Azure Bastion' }
            '*azureFirewalls*'         { 'Azure Firewall' }
            default                    { 'Unknown' }
        }

        $findings += New-SecurityFinding -Category 'Public IP Exposure' -Resource $resource -Severity 'Informational' `
            -Finding "Public IP $($pip.IpAddress) (SKU: $($pip.Sku.Name)) attached to: $attachmentType." `
            -Recommendation 'Confirm this resource is intended to be internet-facing; prefer Azure Firewall/App Gateway/Bastion fronting private resources over direct VM NIC public IPs.'

        if ($attachmentType -eq 'Network Interface (VM)') {
            try {
                $nicId = ($ipConfigId -split '/ipConfigurations/')[0]
                $nic = Get-AzNetworkInterface -ResourceId $nicId -ErrorAction Stop
                if ($nic.NetworkSecurityGroup) {
                    $nsg = Get-AzNetworkSecurityGroup -ResourceId $nic.NetworkSecurityGroup.Id
                    $risky = $nsg.SecurityRules | Where-Object {
                        $_.Access -eq 'Allow' -and $_.Direction -eq 'Inbound' -and
                        (($_.SourceAddressPrefix -in @('*', '0.0.0.0/0', 'Internet', 'Any')) -or
                         ($_.SourceAddressPrefixes -and ($_.SourceAddressPrefixes | Where-Object { $_ -in @('*', '0.0.0.0/0', 'Internet', 'Any') })))
                    }
                    if ($risky) {
                        $findings += New-SecurityFinding -Category 'Public IP Exposure' -Resource $resource -Severity 'Critical' `
                            -Finding "VM has a direct public IP AND its attached NSG allows inbound traffic from the Internet on $($risky.Count) rule(s)." `
                            -Recommendation 'Remove the public IP and place the VM behind a Load Balancer/Bastion, or tighten the NSG immediately.'
                    }
                } else {
                    $findings += New-SecurityFinding -Category 'Public IP Exposure' -Resource $resource -Severity 'High' `
                        -Finding 'VM has a direct public IP and its NIC has no NSG attached (relying solely on subnet-level NSG, if any).' `
                        -Recommendation 'Attach an NSG directly to the NIC/subnet with least-privilege inbound rules.'
                }
            } catch {
                Write-SecurityLog "Could not resolve NIC/NSG for $resource : $_" -Level WARN
            }
        }
    }
}

Write-SecurityLog "Public IP exposure audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-Public-IP-Exposure-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
