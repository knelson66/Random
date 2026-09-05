<#
.SYNOPSIS
    Bulk-indexes a security findings CSV/JSON report (as produced by any script in this
    toolkit) into Elasticsearch, so findings show up in existing SIEM dashboards/alerts.

.DESCRIPTION
    Reads a findings file matching the New-SecurityFinding schema and sends it to an
    Elasticsearch (or Elastic Cloud) cluster using the _bulk API, with each finding tagged
    with a RunId and SourceScript so repeated runs are distinguishable in Kibana.

.PARAMETER FindingsPath
    Path to a .csv or .json findings file produced by Export-SecurityReport.

.PARAMETER ElasticUrl
    Base URL of the Elasticsearch cluster, e.g. "https://my-deployment.es.us-central1.gcp.cloud.es.io:9243".

.PARAMETER ApiKey
    An Elasticsearch API key (base64 "id:api_key" form, as issued by Kibana Stack Management >
    API Keys). Prefer an environment variable over passing it on the command line.

.PARAMETER IndexName
    Target index (or a rolling alias). Default "security-toolkit-findings".

.PARAMETER SourceScript
    Optional label identifying which audit script produced this findings file, stored on each
    document. Defaults to the findings file's base name.

.EXAMPLE
    ./Send-FindingsToElastic.ps1 -FindingsPath ./reports/Azure-NSG-Audit_20260101.json `
        -ElasticUrl "https://my-deployment.es.io:9243" -ApiKey $env:ELASTIC_API_KEY

.NOTES
    Requires: network access to the Elasticsearch cluster and an API key with index privileges
    on the target index. Uses the Elasticsearch _bulk API directly (no client library dependency).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FindingsPath,
    [Parameter(Mandatory)][string]$ElasticUrl,
    [Parameter(Mandatory)][string]$ApiKey,
    [string]$IndexName = "security-toolkit-findings",
    [string]$SourceScript
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }

if (-not (Test-Path $FindingsPath)) { throw "Findings file not found: $FindingsPath" }
if (-not $SourceScript) { $SourceScript = [System.IO.Path]::GetFileNameWithoutExtension($FindingsPath) }

$findings = if ($FindingsPath -like '*.json') {
    Get-Content -Raw $FindingsPath | ConvertFrom-Json
} else {
    Import-Csv $FindingsPath
}

if (-not $findings -or $findings.Count -eq 0) {
    Write-SecurityLog "No findings to index." -Level WARN
    return
}

$runId = [guid]::NewGuid().ToString()
$headers = @{ Authorization = "ApiKey $ApiKey" }
$elasticUrlTrimmed = $ElasticUrl.TrimEnd('/')

Write-SecurityLog "Indexing $($findings.Count) finding(s) into '$IndexName' (RunId: $runId)..."

$ndjsonLines = foreach ($finding in $findings) {
    $doc = @{
        '@timestamp'    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        RunId           = $runId
        SourceScript    = $SourceScript
        Category        = $finding.Category
        Resource        = $finding.Resource
        Severity        = $finding.Severity
        Finding         = $finding.Finding
        Recommendation  = $finding.Recommendation
        Reference       = $finding.Reference
        OriginalTimestamp = $finding.Timestamp
    }
    (@{ index = @{ _index = $IndexName } } | ConvertTo-Json -Compress)
    ($doc | ConvertTo-Json -Compress)
}
$bulkBody = ($ndjsonLines -join "`n") + "`n"

try {
    $response = Invoke-RestMethod -Uri "$elasticUrlTrimmed/_bulk" -Headers $headers -Method POST -Body $bulkBody -ContentType 'application/x-ndjson' -ErrorAction Stop
    $errorCount = ($response.items | Where-Object { $_.index.error }).Count
    if ($errorCount -gt 0) {
        Write-SecurityLog "$errorCount of $($findings.Count) document(s) failed to index. Sample error: $($response.items | Where-Object { $_.index.error } | Select-Object -First 1 | ConvertTo-Json -Depth 5 -Compress)" -Level ERROR
    } else {
        Write-SecurityLog "All $($findings.Count) finding(s) indexed successfully into '$IndexName'." -Level SUCCESS
    }
} catch {
    Write-SecurityLog "Bulk index request failed: $_" -Level ERROR
    throw
}
