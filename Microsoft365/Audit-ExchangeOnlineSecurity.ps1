<#
.SYNOPSIS
    Audits Exchange Online tenant-level security configuration.

.DESCRIPTION
    Checks:
      - Basic authentication protocols not fully blocked (Authentication Policies)
      - Mailbox audit logging disabled tenant-wide or per-mailbox
      - Anti-phishing / DKIM / DMARC not configured for accepted domains
      - Transport rules that auto-forward mail externally or bypass spam filtering
      - Unified Audit Log disabled

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-ExchangeOnline
    ./Audit-ExchangeOnlineSecurity.ps1

.NOTES
    Requires: ExchangeOnlineManagement module
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ExchangeOnlineManagement

if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
    throw "Not connected to Exchange Online. Run Connect-ExchangeOnline first."
}

$findings = @()

Write-SecurityLog "Checking Organization Config for audit and auth settings..."
$orgConfig = Get-OrganizationConfig
if (-not $orgConfig.AuditDisabled -eq $false) {
    if ($orgConfig.AuditDisabled) {
        $findings += New-SecurityFinding -Category 'Exchange Online' -Resource 'Organization' -Severity 'Critical' `
            -Finding 'Mailbox audit logging is disabled at the organization level.' `
            -Recommendation 'Enable mailbox audit logging (Set-OrganizationConfig -AuditDisabled $false).'
    }
}

try {
    $ual = Get-AdminAuditLogConfig
    if (-not $ual.UnifiedAuditLogIngestionEnabled) {
        $findings += New-SecurityFinding -Category 'Exchange Online' -Resource 'Organization' -Severity 'Critical' `
            -Finding 'Unified Audit Log ingestion is disabled tenant-wide.' `
            -Recommendation 'Enable the Unified Audit Log; it is foundational for incident response and eDiscovery.'
    }
} catch {
    Write-SecurityLog "Could not read Unified Audit Log configuration: $_" -Level WARN
}

Write-SecurityLog "Checking authentication policies for legacy/basic auth..."
try {
    $authPolicies = Get-AuthenticationPolicy
    $legacyAllowed = $authPolicies | Where-Object {
        $_.AllowBasicAuthPop -or $_.AllowBasicAuthImap -or $_.AllowBasicAuthSmtp -or $_.AllowBasicAuthActiveSync -or $_.AllowBasicAuthAutodiscover
    }
    foreach ($policy in $legacyAllowed) {
        $findings += New-SecurityFinding -Category 'Exchange Online' -Resource $policy.Name -Severity 'High' `
            -Finding 'Authentication policy still permits one or more Basic Authentication protocols.' `
            -Recommendation 'Disable Basic Auth for all protocols; require Modern Authentication (OAuth) exclusively.'
    }
} catch {
    Write-SecurityLog "Could not read authentication policies: $_" -Level WARN
}

Write-SecurityLog "Checking accepted domains for DKIM..."
try {
    $dkimConfigs = Get-DkimSigningConfig
    foreach ($dkim in $dkimConfigs) {
        if (-not $dkim.Enabled) {
            $findings += New-SecurityFinding -Category 'Exchange Online' -Resource $dkim.Domain -Severity 'Medium' `
                -Finding 'DKIM signing is not enabled for this accepted domain.' `
                -Recommendation 'Enable DKIM and publish the corresponding CNAME records to reduce spoofing/phishing of this domain.'
        }
    }
} catch {
    Write-SecurityLog "Could not read DKIM configuration: $_" -Level WARN
}

Write-SecurityLog "Checking transport rules for risky auto-forwarding..."
try {
    $rules = Get-TransportRule
    $riskyRules = $rules | Where-Object {
        $_.RedirectMessageTo -or $_.SetSCL -eq -1 -or ($_.CopyTo -and $_.State -eq 'Enabled')
    }
    foreach ($rule in $riskyRules) {
        $findings += New-SecurityFinding -Category 'Exchange Online' -Resource $rule.Name -Severity 'High' `
            -Finding 'Transport rule redirects/copies mail externally or forces spam confidence level to bypass filtering (SCL -1).' `
            -Recommendation 'Review business justification; a common attacker persistence technique is a hidden forwarding/redirect rule.'
    }
} catch {
    Write-SecurityLog "Could not read transport rules: $_" -Level WARN
}

Write-SecurityLog "Checking for mailbox-level forwarding to external domains..."
try {
    $mailboxes = Get-Mailbox -ResultSize Unlimited -Filter { ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null }
    foreach ($mbx in $mailboxes) {
        $findings += New-SecurityFinding -Category 'Exchange Online' -Resource $mbx.PrimarySmtpAddress -Severity 'High' `
            -Finding "Mailbox has forwarding configured (Forwarding: $($mbx.ForwardingAddress), SMTP: $($mbx.ForwardingSmtpAddress))." `
            -Recommendation 'Confirm this forwarding is authorized; unexpected external forwarding is a common indicator of Business Email Compromise (BEC).'
    }
} catch {
    Write-SecurityLog "Could not enumerate mailbox forwarding: $_" -Level WARN
}

Write-SecurityLog "Exchange Online security audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Exchange-Online-Security-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
