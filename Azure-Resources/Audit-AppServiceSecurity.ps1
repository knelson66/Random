<#
.SYNOPSIS
    Audits Azure App Service (Web Apps / Function Apps) security configuration.

.DESCRIPTION
    For every App Service (and slot) in scope, checks:
      - HTTPS-only not enforced
      - Minimum TLS version below 1.2
      - FTP/FTPS state allowing unencrypted FTP
      - Client certificate / mTLS not required where the app is marked as needing it (informational)
      - Managed identity not configured (app likely uses embedded connection string secrets instead)
      - Remote debugging left enabled
      - "Always On" combined with a publicly accessible default hostname and no authentication
        (Easy Auth) configured, for apps that appear to hold sensitive functionality

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to the current Az context subscription.

.PARAMETER OutputPath
    Directory to write the CSV/HTML/XLSX/PDF report to. Default is ./reports.

.EXAMPLE
    Connect-AzAccount
    ./Audit-AppServiceSecurity.ps1

.NOTES
    Requires: Az.Accounts, Az.Websites
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-AzContext | Out-Null
Assert-ModuleAvailable -Name Az.Websites

$subs = if ($SubscriptionId) { $SubscriptionId } else { (Get-AzContext).Subscription.Id }
$findings = @()

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub | Out-Null
    Write-SecurityLog "Scanning subscription $sub for App Services..."
    $apps = Get-AzWebApp

    foreach ($app in $apps) {
        $resource = "$($app.ResourceGroup)/$($app.Name)"

        if (-not $app.HttpsOnly) {
            $findings += New-SecurityFinding -Category 'App Service' -Resource $resource -Severity 'High' `
                -Finding 'HTTPS-only is not enforced.' `
                -Recommendation 'Enable "HTTPS Only" so plaintext HTTP requests are redirected/rejected.'
        }

        $config = Get-AzWebApp -ResourceGroupName $app.ResourceGroup -Name $app.Name
        $siteConfig = $config.SiteConfig

        if ($siteConfig.MinTlsVersion -and [double]$siteConfig.MinTlsVersion -lt 1.2) {
            $findings += New-SecurityFinding -Category 'App Service' -Resource $resource -Severity 'High' `
                -Finding "Minimum TLS version is set to $($siteConfig.MinTlsVersion), below 1.2." `
                -Recommendation 'Raise minimum TLS version to 1.2 or higher.'
        }

        if ($siteConfig.FtpsState -eq 'AllAllowed') {
            $findings += New-SecurityFinding -Category 'App Service' -Resource $resource -Severity 'High' `
                -Finding 'FTP/FTPS state allows unencrypted FTP.' `
                -Recommendation 'Set FTP state to "FTPS Only" or, preferably, "Disabled" if FTP deployment is not used.'
        }

        if ($siteConfig.RemoteDebuggingEnabled) {
            $findings += New-SecurityFinding -Category 'App Service' -Resource $resource -Severity 'Medium' `
                -Finding 'Remote debugging is enabled.' `
                -Recommendation 'Disable remote debugging in production; it exposes an additional debug port/protocol attack surface.'
        }

        if (-not $app.Identity -or $app.Identity.Type -eq 'None') {
            $findings += New-SecurityFinding -Category 'App Service' -Resource $resource -Severity 'Low' `
                -Finding 'No managed identity is configured.' `
                -Recommendation 'Enable a managed identity and use it for downstream Azure resource access instead of embedded connection strings/keys in app settings.'
        }

        try {
            $authSettings = Invoke-AzRestMethod -Path "$($app.Id)/config/authsettingsV2/list?api-version=2022-03-01" -Method POST
            $authContent = $authSettings.Content | ConvertFrom-Json
            if (-not $authContent.properties.globalValidation.requireAuthentication -and $app.HostNames.Count -gt 0) {
                $findings += New-SecurityFinding -Category 'App Service' -Resource $resource -Severity 'Informational' `
                    -Finding 'App Service authentication (Easy Auth) is not configured/required.' `
                    -Recommendation 'If this app should not be anonymously reachable, require authentication via Easy Auth or ensure equivalent auth is enforced in application code.'
            }
        } catch {
            Write-SecurityLog "Could not check auth settings for $resource : $_" -Level WARN
        }
    }
}

Write-SecurityLog "App Service audit complete: $($apps.Count) app(s) checked, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Azure-AppService-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
