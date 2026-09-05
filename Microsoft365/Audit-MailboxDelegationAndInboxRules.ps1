<#
.SYNOPSIS
    Audits Exchange Online mailbox delegation (Full Access, Send As, Send on Behalf) and inbox
    rules for common Business Email Compromise (BEC) persistence patterns.

.DESCRIPTION
    For every mailbox (or a supplied list), checks:
      - Full Access / Send As / Send on Behalf permissions granted to unexpected principals
      - Inbox rules that delete, move to RSS/Archive, or forward messages matching keywords like
        "invoice", "wire", "password" (classic attacker cover-your-tracks and BEC rules)
      - Inbox rules forwarding to external SMTP addresses

.PARAMETER Mailboxes
    Optional list of mailbox identities to check. Defaults to all mailboxes (can be slow on large tenants).

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    Connect-ExchangeOnline
    ./Audit-MailboxDelegationAndInboxRules.ps1

.NOTES
    Requires: ExchangeOnlineManagement module
#>
[CmdletBinding()]
param(
    [string[]]$Mailboxes,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ExchangeOnlineManagement

if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
    throw "Not connected to Exchange Online. Run Connect-ExchangeOnline first."
}

$suspiciousKeywords = @('invoice', 'wire', 'payment', 'password', 'bank', 'w-2', 'w2', 'urgent')
$findings = @()

$targets = if ($Mailboxes) { $Mailboxes | ForEach-Object { Get-Mailbox -Identity $_ } } else { Get-Mailbox -ResultSize Unlimited }
Write-SecurityLog "Auditing $($targets.Count) mailbox(es) for delegation and inbox rule risk..."

$i = 0
foreach ($mbx in $targets) {
    $i++
    Write-Progress -Activity "Auditing mailboxes" -Status $mbx.PrimarySmtpAddress -PercentComplete (($i / $targets.Count) * 100)

    try {
        $fullAccess = Get-MailboxPermission -Identity $mbx.Identity | Where-Object {
            $_.AccessRights -contains 'FullAccess' -and -not $_.IsInherited -and $_.User -notmatch 'NT AUTHORITY|SELF'
        }
        foreach ($perm in $fullAccess) {
            $findings += New-SecurityFinding -Category 'Mailbox Delegation' -Resource $mbx.PrimarySmtpAddress -Severity 'Medium' `
                -Finding "Full Access granted to '$($perm.User)'." `
                -Recommendation 'Confirm this delegation is expected (e.g., shared mailbox, EA support); remove unused grants.'
        }

        $sendAs = Get-RecipientPermission -Identity $mbx.Identity | Where-Object { $_.Trustee -notmatch 'NT AUTHORITY|SELF' }
        foreach ($perm in $sendAs) {
            $findings += New-SecurityFinding -Category 'Mailbox Delegation' -Resource $mbx.PrimarySmtpAddress -Severity 'Medium' `
                -Finding "Send As granted to '$($perm.Trustee)'." `
                -Recommendation 'Confirm business need; Send As on an executive mailbox is a common BEC escalation target.'
        }
    } catch {
        Write-SecurityLog "Could not read permissions for $($mbx.PrimarySmtpAddress): $_" -Level WARN
    }

    try {
        $rules = Get-InboxRule -Mailbox $mbx.Identity -IncludeHidden -ErrorAction Stop
        foreach ($rule in $rules) {
            $ruleText = "$($rule.Name) $($rule.Description)"

            if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                $findings += New-SecurityFinding -Category 'Mailbox Inbox Rules' -Resource $mbx.PrimarySmtpAddress -Severity 'High' `
                    -Finding "Inbox rule '$($rule.Name)' forwards/redirects mail externally." `
                    -Recommendation 'Verify with the mailbox owner; unauthorized forwarding rules are a top BEC persistence technique. Disable if not recognized.'
            }

            if ($rule.Enabled -and ($rule.DeleteMessage -or $rule.MoveToFolder -match 'RSS|Archive|Deleted') -and
                ($suspiciousKeywords | Where-Object { $ruleText -match $_ -or ($rule.SubjectContainsWords -join ' ') -match $_ })) {
                $findings += New-SecurityFinding -Category 'Mailbox Inbox Rules' -Resource $mbx.PrimarySmtpAddress -Severity 'Critical' `
                    -Finding "Inbox rule '$($rule.Name)' auto-deletes/archives messages matching a sensitive keyword (invoice/wire/password/etc.)." `
                    -Recommendation 'Investigate immediately - this pattern is commonly used by attackers to hide replies during BEC fraud.'
            }

            if ($rule.Hidden) {
                $findings += New-SecurityFinding -Category 'Mailbox Inbox Rules' -Resource $mbx.PrimarySmtpAddress -Severity 'High' `
                    -Finding "Hidden inbox rule detected: '$($rule.Name)'." `
                    -Recommendation 'Hidden rules are unusual for legitimate end-user configuration; review and remove if not explainable.'
            }
        }
    } catch {
        Write-SecurityLog "Could not read inbox rules for $($mbx.PrimarySmtpAddress): $_" -Level WARN
    }
}

Write-Progress -Activity "Auditing mailboxes" -Completed
Write-SecurityLog "Mailbox delegation/inbox rule audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'Exchange-Online-Delegation-InboxRule-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
