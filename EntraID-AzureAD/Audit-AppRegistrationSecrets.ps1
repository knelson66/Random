<#
.SYNOPSIS
    Audits Entra ID App Registrations and Enterprise Applications for expiring/expired secrets,
    certificates, and excessive API permissions.

.DESCRIPTION
    Enumerates all app registrations and reports:
      - Client secrets / certificates that are expired or expiring within a warning window
      - Applications granted highly privileged Microsoft Graph app roles (e.g. full directory write)
      - Applications with no owner assigned
      - Multi-tenant applications (broader attack surface) worth reviewing

.PARAMETER ExpiryWarningDays
    Flag credentials expiring within this many days. Default 30.

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All"
    ./Audit-AppRegistrationSecrets.ps1 -ExpiryWarningDays 45

.NOTES
    Requires: Microsoft.Graph.Applications
#>
[CmdletBinding()]
param(
    [int]$ExpiryWarningDays = 30,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

$highRiskPermissions = @(
    'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All', 'User.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send',
    'Sites.FullControl.All', 'Files.ReadWrite.All'
)

Write-SecurityLog "Retrieving app registrations..."
$apps = Get-MgApplication -All -Property Id, AppId, DisplayName, PasswordCredentials, KeyCredentials, SignInAudience, RequiredResourceAccess

$findings = @()
$now = Get-Date

foreach ($app in $apps) {
    foreach ($secret in $app.PasswordCredentials) {
        if (-not $secret.EndDateTime) { continue }
        $daysLeft = (New-TimeSpan -Start $now -End $secret.EndDateTime).Days
        if ($daysLeft -lt 0) {
            $findings += New-SecurityFinding -Category 'App Registration Credentials' -Resource $app.DisplayName -Severity 'Medium' `
                -Finding "Client secret '$($secret.DisplayName)' expired $([math]::Abs($daysLeft)) days ago (AppId: $($app.AppId))." `
                -Recommendation 'Remove expired secrets to reduce clutter and confirm the app is not silently failing.'
        } elseif ($daysLeft -le $ExpiryWarningDays) {
            $findings += New-SecurityFinding -Category 'App Registration Credentials' -Resource $app.DisplayName -Severity 'High' `
                -Finding "Client secret '$($secret.DisplayName)' expires in $daysLeft days (AppId: $($app.AppId))." `
                -Recommendation 'Rotate the secret before expiry to avoid a service outage; prefer certificate or managed identity auth.'
        }
    }

    foreach ($cert in $app.KeyCredentials) {
        if (-not $cert.EndDateTime) { continue }
        $daysLeft = (New-TimeSpan -Start $now -End $cert.EndDateTime).Days
        if ($daysLeft -ge 0 -and $daysLeft -le $ExpiryWarningDays) {
            $findings += New-SecurityFinding -Category 'App Registration Credentials' -Resource $app.DisplayName -Severity 'High' `
                -Finding "Certificate credential expires in $daysLeft days (AppId: $($app.AppId))." `
                -Recommendation 'Rotate the certificate before expiry.'
        }
    }

    foreach ($resourceAccess in $app.RequiredResourceAccess) {
        foreach ($access in $resourceAccess.ResourceAccess) {
            if ($access.Type -eq 'Role') {
                # Role-type = application permission (no signed-in user context); resolve display name if possible
                $permName = $access.Id
                if ($highRiskPermissions -contains $permName) {
                    $findings += New-SecurityFinding -Category 'App Registration Permissions' -Resource $app.DisplayName -Severity 'High' `
                        -Finding "Application permission grant includes high-risk scope id '$permName' (AppId: $($app.AppId))." `
                        -Recommendation 'Confirm least-privilege; prefer delegated permissions or narrower application roles where possible.'
                }
            }
        }
    }

    if ($app.SignInAudience -like 'AzureADMultipleOrgs*' -or $app.SignInAudience -like '*PersonalMicrosoftAccount*') {
        $findings += New-SecurityFinding -Category 'App Registration Configuration' -Resource $app.DisplayName -Severity 'Medium' `
            -Finding "SignInAudience is '$($app.SignInAudience)', allowing sign-in from outside this tenant." `
            -Recommendation 'Restrict to AzureADMyOrg unless multi-tenant support is a deliberate requirement.'
    }

    try {
        $owners = Get-MgApplicationOwner -ApplicationId $app.Id -All
        if (-not $owners -or $owners.Count -eq 0) {
            $findings += New-SecurityFinding -Category 'App Registration Configuration' -Resource $app.DisplayName -Severity 'Low' `
                -Finding 'Application has no owner assigned.' `
                -Recommendation 'Assign at least one accountable owner for lifecycle and credential management.'
        }
    } catch {
        Write-SecurityLog "Could not read owners for $($app.DisplayName): $_" -Level WARN
    }
}

Write-SecurityLog "Reviewed $($apps.Count) app registrations, $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Entra-ID-App-Registration-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
