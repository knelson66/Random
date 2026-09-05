#Requires -Version 5.1
<#
    SecurityToolkitCommon
    Shared helper functions used by the scripts in this repository:
      - consistent console/file logging
      - CSV/HTML/JSON export of findings
      - lightweight connection checks for Az / Microsoft Graph
    Import with:  Import-Module ./modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1
#>

function Write-SecurityLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO',

        [string]$LogPath
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'INFO'    { Write-Host $line -ForegroundColor Cyan }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
    }

    if ($LogPath) {
        Add-Content -Path $LogPath -Value $line
    }
}

function New-SecurityFinding {
    <#
        .SYNOPSIS
        Creates a standardized finding object so every audit script emits the same shape of data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Resource,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')][string]$Severity,
        [Parameter(Mandatory)][string]$Finding,
        [string]$Recommendation = '',
        [string]$Reference = ''
    )

    [pscustomobject]@{
        Timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Category       = $Category
        Resource       = $Resource
        Severity       = $Severity
        Finding        = $Finding
        Recommendation = $Recommendation
        Reference      = $Reference
    }
}

function Export-SecurityReport {
    <#
        .SYNOPSIS
        Exports a collection of finding objects (see New-SecurityFinding) to CSV and/or a self-contained HTML report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [ValidateSet('CSV', 'HTML', 'JSON', 'All')]
        [string]$Format = 'All'
    )

    begin { $all = @() }
    process { $all += $Findings }
    end {
        $base = [System.IO.Path]::Combine($OutputPath, ($Title -replace '[^\w\-]', '_'))
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

        if ($Format -in 'CSV', 'All') {
            $csvPath = "${base}_$stamp.csv"
            $all | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-SecurityLog "CSV report written to $csvPath" -Level SUCCESS
        }

        if ($Format -in 'JSON', 'All') {
            $jsonPath = "${base}_$stamp.json"
            $all | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
            Write-SecurityLog "JSON report written to $jsonPath" -Level SUCCESS
        }

        if ($Format -in 'HTML', 'All') {
            $htmlPath = "${base}_$stamp.html"
            $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
            $sorted = $all | Sort-Object { $severityOrder[[string]$_.Severity] }

            $rows = foreach ($f in $sorted) {
                $class = "sev-$($f.Severity.ToString().ToLower())"
                "<tr class='$class'><td>$($f.Timestamp)</td><td>$($f.Category)</td><td>$($f.Resource)</td><td>$($f.Severity)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>"
            }

            $counts = $all | Group-Object Severity | ForEach-Object { "<span class='badge $($_.Name.ToLower())'>$($_.Name): $($_.Count)</span>" }

            $html = @"
<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>$Title</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f5f6f8;color:#1b1f24;margin:2rem;}
h1{margin-bottom:.25rem;} .meta{color:#666;margin-bottom:1rem;}
table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1);}
th,td{padding:8px 10px;border-bottom:1px solid #e5e7eb;text-align:left;font-size:13px;vertical-align:top;}
th{background:#1b1f24;color:#fff;position:sticky;top:0;}
tr.sev-critical{border-left:4px solid #b91c1c;} tr.sev-high{border-left:4px solid #ea580c;}
tr.sev-medium{border-left:4px solid #ca8a04;} tr.sev-low{border-left:4px solid #2563eb;}
tr.sev-informational{border-left:4px solid #6b7280;}
.badge{display:inline-block;padding:4px 10px;border-radius:12px;color:#fff;font-size:12px;margin-right:6px;}
.badge.critical{background:#b91c1c;} .badge.high{background:#ea580c;} .badge.medium{background:#ca8a04;}
.badge.low{background:#2563eb;} .badge.informational{background:#6b7280;}
</style></head><body>
<h1>$Title</h1>
<div class='meta'>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &middot; $($all.Count) findings</div>
<div style='margin-bottom:1rem;'>$($counts -join ' ')</div>
<table><thead><tr><th>Timestamp</th><th>Category</th><th>Resource</th><th>Severity</th><th>Finding</th><th>Recommendation</th></tr></thead>
<tbody>$($rows -join "`n")</tbody></table>
</body></html>
"@
            $html | Out-File -FilePath $htmlPath -Encoding UTF8
            Write-SecurityLog "HTML report written to $htmlPath" -Level SUCCESS
        }
    }
}

function Assert-ModuleAvailable {
    <#
        .SYNOPSIS
        Verifies a module is installed and imports it, otherwise fails with a clear install hint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$MinimumVersion
    )

    $available = Get-Module -ListAvailable -Name $Name
    if (-not $available) {
        throw "Required module '$Name' is not installed. Install it with: Install-Module -Name $Name -Scope CurrentUser"
    }

    Import-Module -Name $Name -MinimumVersion $MinimumVersion -ErrorAction SilentlyContinue
    Import-Module -Name $Name -ErrorAction Stop
}

function Test-AzContext {
    [CmdletBinding()]
    param()
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        throw "No active Az context. Run Connect-AzAccount first (optionally -TenantId <tenant>)."
    }
    return $ctx
}

function Test-GraphContext {
    [CmdletBinding()]
    param()
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        throw "No active Microsoft Graph context. Run Connect-MgGraph with the required scopes first."
    }
    return $ctx
}

Export-ModuleMember -Function Write-SecurityLog, Export-SecurityReport, New-SecurityFinding, Assert-ModuleAvailable, Test-AzContext, Test-GraphContext
