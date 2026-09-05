<#
.SYNOPSIS
    Collects a lightweight forensic triage bundle from a Windows host for initial incident
    response, without requiring a dedicated forensic imaging tool.

.DESCRIPTION
    Gathers volatile and semi-volatile artifacts commonly needed in the first minutes of an
    investigation: running processes (with hashes and paths), network connections, autoruns-style
    persistence locations, recent scheduled tasks, local user/group changes, PowerShell history,
    and key Windows Event Log exports (Security, System, PowerShell Operational, Sysmon if present).
    Everything is written to a timestamped folder for later offline analysis.

.PARAMETER OutputPath
    Directory under which a timestamped triage folder is created. Default is ./triage.

.PARAMETER EventLogHours
    How many hours of event log history to export. Default 72.

.EXAMPLE
    ./Collect-WindowsForensicTriage.ps1 -OutputPath D:\IR\Case1234

.NOTES
    Run elevated (Administrator). Designed for on-host, defensive incident response collection.
    Does not modify system state; all actions are read-only collection.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./triage",
    [int]$EventLogHours = 72
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$caseDir = Join-Path $OutputPath "$($env:COMPUTERNAME)_$stamp"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
Write-SecurityLog "Collecting triage data to $caseDir"

# Processes with hashes
Write-SecurityLog "Collecting running process list with file hashes..."
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate |
    ForEach-Object {
        $hash = $null
        if ($_.ExecutablePath -and (Test-Path $_.ExecutablePath)) {
            try { $hash = (Get-FileHash -Path $_.ExecutablePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
        }
        $_ | Add-Member -NotePropertyName SHA256 -NotePropertyValue $hash -PassThru
    } | Export-Csv -Path (Join-Path $caseDir 'processes.csv') -NoTypeInformation

# Network connections
Write-SecurityLog "Collecting active network connections..."
Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Export-Csv -Path (Join-Path $caseDir 'network_connections.csv') -NoTypeInformation

# Persistence: Run keys, services, scheduled tasks, startup folders
Write-SecurityLog "Collecting persistence locations (run keys, services, scheduled tasks)..."
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
)
$runKeyData = foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Get-ItemProperty -Path $key | Select-Object * -ExcludeProperty PS* | ForEach-Object {
            $obj = $_
            $obj.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                [pscustomobject]@{ Key = $key; Name = $_.Name; Value = $_.Value }
            }
        }
    }
}
$runKeyData | Export-Csv -Path (Join-Path $caseDir 'run_keys.csv') -NoTypeInformation

Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName |
    Export-Csv -Path (Join-Path $caseDir 'services.csv') -NoTypeInformation

Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo
    [pscustomobject]@{
        TaskName = $_.TaskName; TaskPath = $_.TaskPath; State = $_.State
        Actions  = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        LastRunTime = $info.LastRunTime
    }
} | Export-Csv -Path (Join-Path $caseDir 'scheduled_tasks.csv') -NoTypeInformation

# Local accounts and group membership
Write-SecurityLog "Collecting local user and administrator group membership..."
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Export-Csv -Path (Join-Path $caseDir 'local_users.csv') -NoTypeInformation
Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Select-Object Name, PrincipalSource, ObjectClass |
    Export-Csv -Path (Join-Path $caseDir 'local_administrators.csv') -NoTypeInformation

# PowerShell history (current user context)
$psHistoryPath = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath
if ($psHistoryPath -and (Test-Path $psHistoryPath)) {
    Copy-Item -Path $psHistoryPath -Destination (Join-Path $caseDir 'powershell_history.txt') -ErrorAction SilentlyContinue
}

# Event logs
Write-SecurityLog "Exporting event logs for the last $EventLogHours hours..."
$startTime = (Get-Date).AddHours(-$EventLogHours)
$logsToExport = @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell', 'Microsoft-Windows-Sysmon/Operational')
foreach ($log in $logsToExport) {
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $startTime } -ErrorAction Stop
        $safeName = $log -replace '[\\/]', '_'
        $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            Export-Csv -Path (Join-Path $caseDir "eventlog_$safeName.csv") -NoTypeInformation
        Write-SecurityLog "Exported $($events.Count) events from '$log'."
    } catch {
        Write-SecurityLog "Log '$log' not present or no matching events: $_" -Level WARN
    }
}

# System info
Get-ComputerInfo | Out-File -FilePath (Join-Path $caseDir 'system_info.txt')

Write-SecurityLog "Triage collection complete: $caseDir" -Level SUCCESS
Write-SecurityLog "Remember to hash the resulting folder and preserve chain-of-custody documentation." -Level INFO
