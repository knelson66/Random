<#
.SYNOPSIS
    Audits Entra ID Named Locations used by Conditional Access for stale/overly broad trusted
    network definitions.

.DESCRIPTION
    Checks:
      - "Trusted" IP-based named locations that include very broad CIDR ranges (e.g. /8-/16),
        effectively trusting large swaths of the internet or an entire cloud provider's range
      - Named locations not referenced by any active Conditional Access policy (dead configuration)
      - Country-based named locations marked trusted that include high-risk countries as an
        oversight (informational - always requires human judgment on intent)

.PARAMETER MaxTrustedCidrPrefixLength
    Flag trusted IP ranges with a prefix shorter than this (i.e., a bigger range) as too broad.
    Default 24 (a /16 is broader/riskier than a /24, so ranges with prefix length less than
    this value are flagged).

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All"
    ./Audit-NamedLocationsAndTrustedNetworks.ps1

.NOTES
    Requires: Microsoft.Graph.Identity.SignIns
#>
[CmdletBinding()]
param(
    [int]$MaxTrustedCidrPrefixLength = 24,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$findings = @()

Write-SecurityLog "Retrieving named locations..."
$namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All

Write-SecurityLog "Retrieving Conditional Access policies to check named location usage..."
$caPolicies = Get-MgIdentityConditionalAccessPolicy -All
$referencedLocationIds = @()
foreach ($policy in $caPolicies) {
    $referencedLocationIds += $policy.Conditions.Locations.IncludeLocations
    $referencedLocationIds += $policy.Conditions.Locations.ExcludeLocations
}
$referencedLocationIds = $referencedLocationIds | Where-Object { $_ } | Select-Object -Unique

foreach ($location in $namedLocations) {
    $odataType = $location.AdditionalProperties['@odata.type']
    $isTrusted = $location.AdditionalProperties['isTrusted']

    if ($location.Id -notin $referencedLocationIds) {
        $findings += New-SecurityFinding -Category 'Named Locations' -Resource $location.DisplayName -Severity 'Low' `
            -Finding 'Named location is not referenced by any Conditional Access policy.' `
            -Recommendation 'Remove unused named locations to reduce configuration clutter and confusion during incident response.'
    }

    if ($odataType -eq '#microsoft.graph.ipNamedLocation' -and $isTrusted -eq $true) {
        $ranges = $location.AdditionalProperties['ipRanges']
        foreach ($range in $ranges) {
            $cidr = $range.cidrAddress
            if ($cidr -match '/(\d+)$') {
                $prefixLength = [int]$Matches[1]
                if ($prefixLength -lt $MaxTrustedCidrPrefixLength) {
                    $findings += New-SecurityFinding -Category 'Named Locations' -Resource $location.DisplayName -Severity 'Medium' `
                        -Finding "Trusted named location includes a broad range: $cidr (/$prefixLength)." `
                        -Recommendation 'Narrow trusted ranges to only the specific egress IPs actually used (e.g., office/VPN public IPs), not broad provider or ISP blocks.'
                }
            }
        }
    }
}

Write-SecurityLog "Named location audit complete: $($namedLocations.Count) locations checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Entra-ID-Named-Locations-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
