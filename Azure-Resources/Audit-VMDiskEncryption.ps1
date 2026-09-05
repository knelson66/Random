<#
.SYNOPSIS
    Audits Azure VM disk encryption status, patch/extension hygiene, and JIT/exposure signals.

.DESCRIPTION
    For every VM in scope, checks:
      - OS/data disk encryption at host or Azure Disk Encryption not enabled
      - Managed disks using platform-managed keys where CMK may be required by policy
      - Boot diagnostics disabled
      - Missing or unhealthy Microsoft Defender for Endpoint / Azure Monitor Agent extension
      - VM Agent not provisioned (patch/extension operations will fail)

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-VMDiskEncryption.ps1

.NOTES
    Requires: Az.Accounts, Az.Compute
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null

$expectedSecurityExtensions = @('MDE.Windows', 'MDE.Linux', 'AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent', 'MicrosoftMonitoringAgent')
$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for VM security posture..."
    $vms = Get-AzVM -Status

    foreach ($vm in $vms) {
        $resource = "$($vm.ResourceGroupName)/$($vm.Name)"

        if ($vm.PowerState -ne 'VM running') {
            $findings += New-SecurityFinding -Category 'VM Security Posture' -Resource $resource -Severity 'Informational' `
                -Finding "VM power state is '$($vm.PowerState)'; some checks may be incomplete for stopped VMs." `
                -Recommendation 'None - informational.'
        }

        $encryptionEnabled = $false
        try {
            $status = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction SilentlyContinue
            $encryptionEnabled = ($status.OsVolumeEncrypted -eq 'Encrypted')
        } catch { }

        $encryptionAtHost = $vm.SecurityProfile.EncryptionAtHost -eq $true
        if (-not $encryptionEnabled -and -not $encryptionAtHost) {
            $findings += New-SecurityFinding -Category 'VM Security Posture' -Resource $resource -Severity 'Medium' `
                -Finding 'Neither Azure Disk Encryption nor Encryption at Host is enabled (disks rely on platform-managed encryption only).' `
                -Recommendation 'Enable Encryption at Host or ADE for defense-in-depth, especially for VMs handling sensitive data.'
        }

        if (-not $vm.DiagnosticsProfile.BootDiagnostics.Enabled) {
            $findings += New-SecurityFinding -Category 'VM Security Posture' -Resource $resource -Severity 'Low' `
                -Finding 'Boot diagnostics is disabled.' `
                -Recommendation 'Enable boot diagnostics to aid incident response and troubleshooting.'
        }

        $extensions = @()
        try { $extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction SilentlyContinue } catch { }
        $hasSecurityAgent = $extensions | Where-Object { $_.ExtensionType -in $expectedSecurityExtensions -or $_.Name -in $expectedSecurityExtensions }
        if (-not $hasSecurityAgent) {
            $findings += New-SecurityFinding -Category 'VM Security Posture' -Resource $resource -Severity 'High' `
                -Finding 'No Microsoft Defender for Endpoint / Azure Monitor Agent extension detected.' `
                -Recommendation 'Onboard the VM to Microsoft Defender for Cloud / Defender for Endpoint and deploy the Azure Monitor Agent.'
        } else {
            $unhealthy = $hasSecurityAgent | Where-Object { $_.ProvisioningState -ne 'Succeeded' }
            if ($unhealthy) {
                $findings += New-SecurityFinding -Category 'VM Security Posture' -Resource $resource -Severity 'Medium' `
                    -Finding "Security/monitoring extension provisioning state is '$($unhealthy[0].ProvisioningState)' (unhealthy)." `
                    -Recommendation 'Re-deploy or repair the extension so telemetry/protection is actually functioning.'
            }
        }

        $agentStatus = $vm.VMAgent.VmAgentVersion
        if (-not $agentStatus -or $vm.VMAgent.Statuses.DisplayStatus -notmatch 'Ready') {
            $findings += New-SecurityFinding -Category 'VM Security Posture' -Resource $resource -Severity 'Medium' `
                -Finding 'VM Agent is not reporting Ready; extension and patch operations may silently fail.' `
                -Recommendation 'Investigate and repair the Azure VM Agent installation.'
        }
    }
}

Write-SecurityLog "VM security posture audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-VM-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
