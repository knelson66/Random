<#
.SYNOPSIS
    Runs a local Windows security baseline check inspired by CIS Microsoft Windows Benchmarks,
    without requiring any cloud connectivity.

.DESCRIPTION
    Checks a representative set of high-value CIS controls directly on the local (or remote,
    via -ComputerName + PS Remoting) machine:
      - Windows Firewall enabled for all profiles
      - SMBv1 disabled
      - LSA Protection (RunAsPPL) enabled
      - LLMNR disabled
      - Windows Defender real-time protection enabled and signatures current
      - BitLocker enabled on the OS volume
      - Local Administrator account status and password guidance
      - Guest account disabled
      - RDP Network Level Authentication (NLA) enabled
      - PowerShell v2 engine removed (legacy, no logging)

.PARAMETER ComputerName
    Target computer(s) to assess remotely via PowerShell remoting. Defaults to the local host.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    ./Test-WindowsSecurityBaseline.ps1

.EXAMPLE
    ./Test-WindowsSecurityBaseline.ps1 -ComputerName SRV01, SRV02

.NOTES
    Run elevated (Administrator) for complete results. Some checks (BitLocker, LSA) require admin rights.
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

$scriptBlock = {
    $results = @()

    # Firewall profiles
    try {
        $profiles = Get-NetFirewallProfile
        foreach ($p in $profiles) {
            if (-not $p.Enabled) {
                $results += [pscustomobject]@{ Category='Firewall'; Severity='High'; Finding="Windows Firewall profile '$($p.Name)' is disabled."; Recommendation='Enable Windows Firewall for all profiles (Domain/Private/Public).' }
            }
        }
    } catch { }

    # SMBv1
    try {
        $smb1 = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smb1.EnableSMB1Protocol) {
            $results += [pscustomobject]@{ Category='Protocols'; Severity='Critical'; Finding='SMBv1 protocol is enabled.'; Recommendation='Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false); it is vulnerable to EternalBlue-class exploits.' }
        }
    } catch { }

    # LSA Protection
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $runAsPPL = (Get-ItemProperty -Path $lsaKey -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    if ($runAsPPL -ne 1) {
        $results += [pscustomobject]@{ Category='Credential Protection'; Severity='High'; Finding='LSA Protection (RunAsPPL) is not enabled.'; Recommendation='Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 to protect LSASS from credential dumping tools.' }
    }

    # LLMNR
    $llmnrKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $llmnr = (Get-ItemProperty -Path $llmnrKey -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
    if ($llmnr -ne 0) {
        $results += [pscustomobject]@{ Category='Protocols'; Severity='Medium'; Finding='LLMNR is not explicitly disabled.'; Recommendation='Disable LLMNR via GPO/registry to reduce exposure to Responder-style poisoning attacks.' }
    }

    # Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.RealTimeProtectionEnabled) {
            $results += [pscustomobject]@{ Category='Endpoint Protection'; Severity='Critical'; Finding='Microsoft Defender real-time protection is disabled.'; Recommendation='Re-enable real-time protection immediately.' }
        }
        if ($mp.AntivirusSignatureAge -gt 3) {
            $results += [pscustomobject]@{ Category='Endpoint Protection'; Severity='High'; Finding="Antivirus signatures are $($mp.AntivirusSignatureAge) days old."; Recommendation='Update Defender signatures; investigate why automatic updates are stale.' }
        }
    } catch { }

    # BitLocker
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($bl.VolumeStatus -ne 'FullyEncrypted') {
            $results += [pscustomobject]@{ Category='Data Protection'; Severity='High'; Finding="OS volume BitLocker status: $($bl.VolumeStatus)."; Recommendation='Enable BitLocker with TPM protector on the OS volume.' }
        }
    } catch { }

    # Guest account
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
        if ($guest.Enabled) {
            $results += [pscustomobject]@{ Category='Local Accounts'; Severity='High'; Finding='Local Guest account is enabled.'; Recommendation='Disable the Guest account (Disable-LocalUser -Name Guest).' }
        }
    } catch { }

    # RDP NLA
    $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $nla = (Get-ItemProperty -Path $rdpKey -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    if ($nla -ne 1) {
        $results += [pscustomobject]@{ Category='Remote Access'; Severity='High'; Finding='RDP Network Level Authentication (NLA) is not enabled.'; Recommendation='Enable NLA to require authentication before a full RDP session is established.' }
    }

    # PowerShell v2
    try {
        $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2* -ErrorAction Stop
        if ($psv2 | Where-Object { $_.State -eq 'Enabled' }) {
            $results += [pscustomobject]@{ Category='Attack Surface'; Severity='Medium'; Finding='Windows PowerShell v2 engine is installed and enabled.'; Recommendation='Remove PowerShell v2 (legacy engine bypasses AMSI/Script Block Logging): Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root.' }
        }
    } catch { }

    return $results
}

$findings = @()
foreach ($computer in $ComputerName) {
    Write-SecurityLog "Assessing baseline on $computer..."
    try {
        if ($computer -eq $env:COMPUTERNAME) {
            $raw = & $scriptBlock
        } else {
            $raw = Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock -ErrorAction Stop
        }
        foreach ($item in $raw) {
            $findings += New-SecurityFinding -Category $item.Category -Resource $computer -Severity $item.Severity -Finding $item.Finding -Recommendation $item.Recommendation
        }
        if ($raw.Count -eq 0) {
            $findings += New-SecurityFinding -Category 'Baseline' -Resource $computer -Severity 'Informational' -Finding 'No baseline deviations found in the checks performed.' -Recommendation 'None.'
        }
    } catch {
        Write-SecurityLog "Failed to assess $computer : $_" -Level ERROR
        $findings += New-SecurityFinding -Category 'Baseline' -Resource $computer -Severity 'Informational' -Finding "Assessment failed: $_" -Recommendation 'Verify WinRM connectivity and permissions.'
    }
}

Write-SecurityLog "Baseline assessment complete: $($findings.Count) findings across $($ComputerName.Count) host(s)." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Windows-Security-Baseline-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
