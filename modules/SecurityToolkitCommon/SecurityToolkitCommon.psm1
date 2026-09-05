#Requires -Version 5.1
<#
    SecurityToolkitCommon
    Shared helper functions used by the scripts in this repository:
      - consistent console/file logging
      - CSV/JSON/HTML/Excel/PDF export of findings (Excel needs ImportExcel, PDF needs
        PSWriteOffice or a Chromium-based browser on PATH - both are optional, see README)
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

$script:SeverityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
$script:SeverityColors = @{
    Critical      = @{ Hex = '#B91C1C'; Excel = 'Red';       ExcelText = 'White' }
    High          = @{ Hex = '#EA580C'; Excel = 'Orange';    ExcelText = 'Black' }
    Medium        = @{ Hex = '#CA8A04'; Excel = 'Gold';      ExcelText = 'Black' }
    Low           = @{ Hex = '#2563EB'; Excel = 'LightBlue'; ExcelText = 'Black' }
    Informational = @{ Hex = '#6B7280'; Excel = 'LightGray'; ExcelText = 'Black' }
}

function Test-OptionalModule {
    <#
        .SYNOPSIS
        Checks whether an optional (non-fatal) module is installed, without throwing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Module -ListAvailable -Name $Name | Select-Object -First 1)
}

function Export-SecurityReport {
    <#
        .SYNOPSIS
        Exports a collection of finding objects (see New-SecurityFinding) to CSV, JSON, a
        self-contained HTML report, an Excel workbook, and/or a PDF report.

        .DESCRIPTION
        CSV/JSON/HTML have no external dependencies. Excel export uses the ImportExcel module
        (Install-Module ImportExcel) and PDF export uses PSWriteOffice (Install-Module
        PSWriteOffice) with a headless-browser print-to-PDF fallback if neither is installed.
        When -Format All is used (the default), CSV/JSON/HTML always succeed; Excel/PDF are
        best-effort and log a warning with install instructions instead of failing the whole
        report if their module isn't present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [ValidateSet('CSV', 'HTML', 'JSON', 'Excel', 'PDF', 'All', 'Polished')]
        [string]$Format = 'All'
    )
    # 'Polished' = HTML + Excel + PDF only, no CSV/JSON. Handy for bridging findings already
    # produced elsewhere (e.g. the Azure-Resources-CLI bash scripts) into the nicer formats
    # without re-dumping raw data that already exists on disk.

    begin { $all = @() }
    process { $all += $Findings }
    end {
        $base = [System.IO.Path]::Combine($OutputPath, ($Title -replace '[^\w\-]', '_'))
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

        $sorted = $all | Sort-Object { $script:SeverityOrder[[string]$_.Severity] }
        $htmlPath = $null

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

        if ($Format -in 'HTML', 'All', 'Polished') {
            $htmlPath = "${base}_$stamp.html"
            New-SecurityReportHtml -Findings $sorted -Title $Title -Path $htmlPath
            Write-SecurityLog "HTML report written to $htmlPath" -Level SUCCESS
        }

        if ($Format -in 'Excel', 'All', 'Polished') {
            try {
                if (Test-OptionalModule -Name ImportExcel) {
                    $xlsxPath = "${base}_$stamp.xlsx"
                    Export-SecurityReportExcel -Findings $sorted -Title $Title -Path $xlsxPath
                    Write-SecurityLog "Excel report written to $xlsxPath" -Level SUCCESS
                } else {
                    $level = if ($Format -eq 'Excel') { 'ERROR' } else { 'WARN' }
                    Write-SecurityLog "Skipping Excel export: module 'ImportExcel' is not installed. Install with: Install-Module ImportExcel -Scope CurrentUser" -Level $level
                }
            } catch {
                Write-SecurityLog "Excel export failed: $_" -Level ERROR
            }
        }

        if ($Format -in 'PDF', 'All', 'Polished') {
            try {
                if (Test-OptionalModule -Name PSWriteOffice) {
                    $pdfPath = "${base}_$stamp.pdf"
                    Export-SecurityReportPdf -Findings $sorted -Title $Title -Path $pdfPath
                    Write-SecurityLog "PDF report written to $pdfPath" -Level SUCCESS
                } elseif ($htmlPath -and (Convert-HtmlToPdfViaBrowser -HtmlPath $htmlPath -PdfPath "${base}_$stamp.pdf")) {
                    Write-SecurityLog "PDF report written to ${base}_$stamp.pdf (via headless browser print)" -Level SUCCESS
                } else {
                    $level = if ($Format -eq 'PDF') { 'ERROR' } else { 'WARN' }
                    Write-SecurityLog "Skipping PDF export: install PSWriteOffice (Install-Module PSWriteOffice -Scope CurrentUser) or ensure a Chromium-based browser (msedge/chrome/chromium) is on PATH." -Level $level
                }
            } catch {
                Write-SecurityLog "PDF export failed: $_" -Level ERROR
            }
        }
    }
}

function New-SecurityReportHtml {
    <#
        .SYNOPSIS
        Renders a self-contained, color-coded HTML findings report. No external dependencies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Path
    )

    $rows = foreach ($f in $Findings) {
        $class = "sev-$($f.Severity.ToString().ToLower())"
        "<tr class='$class'><td>$($f.Timestamp)</td><td>$($f.Category)</td><td>$($f.Resource)</td><td>$($f.Severity)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>"
    }

    $counts = $Findings | Group-Object Severity | Sort-Object { $script:SeverityOrder[[string]$_.Name] } |
        ForEach-Object { "<span class='badge $($_.Name.ToLower())'>$($_.Name): $($_.Count)</span>" }

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
@media print { body{margin:0.5in;background:#fff;} table{box-shadow:none;} }
</style></head><body>
<h1>$Title</h1>
<div class='meta'>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &middot; $($Findings.Count) findings</div>
<div style='margin-bottom:1rem;'>$($counts -join ' ')</div>
<table><thead><tr><th>Timestamp</th><th>Category</th><th>Resource</th><th>Severity</th><th>Finding</th><th>Recommendation</th></tr></thead>
<tbody>$($rows -join "`n")</tbody></table>
</body></html>
"@
    $html | Out-File -FilePath $Path -Encoding UTF8
}

function Export-SecurityReportExcel {
    <#
        .SYNOPSIS
        Writes a formatted .xlsx workbook (Findings + Summary + ByCategory sheets) using the
        ImportExcel module - no installation of Microsoft Excel required.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Path
    )

    Import-Module ImportExcel -ErrorAction Stop

    if (Test-Path $Path) { Remove-Item -Path $Path -Force }

    # Fixed column order so conditional formatting can reliably target the Severity column (D).
    $ordered = $Findings | Select-Object Timestamp, Category, Resource, Severity, Finding, Recommendation, Reference

    $conditionalRules = foreach ($sev in $script:SeverityColors.Keys) {
        $colors = $script:SeverityColors[$sev]
        New-ConditionalText -Text $sev -Range 'D:D' -BackgroundColor $colors.Excel -ConditionalTextColor $colors.ExcelText
    }

    $ordered | Export-Excel -Path $Path -WorksheetName 'Findings' -TableName 'Findings' -TableStyle Medium2 `
        -AutoSize -AutoFilter -FreezeTopRow -ConditionalText $conditionalRules

    $severitySummary = $Findings | Group-Object Severity | Sort-Object { $script:SeverityOrder[[string]$_.Name] } |
        Select-Object @{N = 'Severity'; E = { $_.Name } }, @{N = 'Count'; E = { $_.Count } }
    $severitySummary | Export-Excel -Path $Path -WorksheetName 'Summary' -TableName 'SeverityCounts' -TableStyle Medium6 `
        -AutoSize -AutoFilter -FreezeTopRow

    $categorySummary = $Findings | Group-Object Category | Sort-Object Count -Descending |
        Select-Object @{N = 'Category'; E = { $_.Name } }, @{N = 'Count'; E = { $_.Count } }
    $categorySummary | Export-Excel -Path $Path -WorksheetName 'ByCategory' -TableName 'CategoryCounts' -TableStyle Medium6 `
        -AutoSize -AutoFilter -FreezeTopRow
}

function Export-SecurityReportPdf {
    <#
        .SYNOPSIS
        Writes a portable/printable PDF summary using PSWriteOffice (OfficeIMO-backed, no
        Microsoft Office or external binary required; works on Windows, Linux, and macOS).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Path
    )

    Import-Module PSWriteOffice -ErrorAction Stop

    $severitySummary = $Findings | Group-Object Severity | Sort-Object { $script:SeverityOrder[[string]$_.Name] }
    $tableRows = $Findings | Select-Object Severity, Category, Resource, Finding, Recommendation

    New-OfficePdf -Path $Path {
        Add-OfficePdfHeading -Text $Title -Level 1
        Add-OfficePdfParagraph -Text "Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $($Findings.Count) findings"

        Add-OfficePdfHeading -Text 'Findings by Severity' -Level 2
        foreach ($group in $severitySummary) {
            Add-OfficePdfParagraph -Text "$($group.Name): $($group.Count)"
        }

        Add-OfficePdfHeading -Text 'Detailed Findings' -Level 2
        Add-OfficePdfTable -InputObject $tableRows -Property Severity, Category, Resource, Finding, Recommendation `
            -Header 'Severity', 'Category', 'Resource', 'Finding', 'Recommendation'

        Set-OfficePdfMetadata -Title $Title -Author 'Security Engineering Toolkit'
    }
}

function Convert-HtmlToPdfViaBrowser {
    <#
        .SYNOPSIS
        Fallback PDF generation: prints an already-rendered HTML report to PDF using whatever
        Chromium-based browser is available on PATH (msedge/chrome/chromium). Returns $true on
        success, $false if no suitable browser was found or the conversion failed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$PdfPath
    )

    $candidates = @('msedge', 'microsoft-edge', 'google-chrome', 'chrome', 'chromium', 'chromium-browser')
    $browser = $candidates | ForEach-Object { Get-Command $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
    if (-not $browser) { return $false }

    $absoluteHtml = (Resolve-Path $HtmlPath).Path
    $browserArgs = @('--headless', '--disable-gpu', "--print-to-pdf=$PdfPath", "file:///$absoluteHtml")

    try {
        $proc = Start-Process -FilePath $browser.Source -ArgumentList $browserArgs -PassThru -Wait -WindowStyle Hidden -ErrorAction Stop
        return ($proc.ExitCode -eq 0 -and (Test-Path $PdfPath))
    } catch {
        return $false
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

Export-ModuleMember -Function Write-SecurityLog, Export-SecurityReport, New-SecurityFinding, Assert-ModuleAvailable, `
    Test-AzContext, Test-GraphContext, Test-OptionalModule, New-SecurityReportHtml, Export-SecurityReportExcel, `
    Export-SecurityReportPdf, Convert-HtmlToPdfViaBrowser
