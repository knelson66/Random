<#
.SYNOPSIS
    Revokes all active sign-in sessions and refresh tokens for a user, and optionally disables
    the account and resets its password, as an incident-response containment action for a
    suspected compromised identity.

.DESCRIPTION
    Wraps the Microsoft Graph "revoke sign-in sessions" action (invalidates all refresh tokens
    and, once Continuous Access Evaluation propagates, active sessions) for one or more users.
    This is a DISRUPTIVE action: the user will be signed out of everything and must
    re-authenticate. It will prompt for confirmation unless -Confirm:$false / -Force is used.

.PARAMETER UserPrincipalName
    One or more user UPNs to act on.

.PARAMETER DisableAccount
    Also disable the account (AccountEnabled = false) so it cannot sign back in at all until
    an admin re-enables it.

.PARAMETER ResetPassword
    Also set a random temporary password and require the user to change it at next sign-in.
    Use this when credential compromise (not just a hijacked session/token) is suspected.

.PARAMETER Reason
    Free-text justification recorded in the console/log output for audit trail purposes.

.EXAMPLE
    Connect-MgGraph -Scopes "User.ReadWrite.All"
    ./Revoke-UserSessionsAndCredentials.ps1 -UserPrincipalName "jdoe@contoso.com" -DisableAccount -ResetPassword -Reason "IR-2026-014: confirmed BEC compromise"

.NOTES
    Requires: Microsoft.Graph.Users. Required Graph scope: User.ReadWrite.All (and
    User-PasswordProfile.ReadWrite.All is covered by the same scope for password resets).
    THIS IS A DISRUPTIVE ACTION affecting the target user's ability to work. Coordinate with
    the user/helpdesk before or immediately after running this.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string[]]$UserPrincipalName,
    [switch]$DisableAccount,
    [switch]$ResetPassword,
    [Parameter(Mandatory)][string]$Reason,
    [switch]$Force
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Test-GraphContext | Out-Null

function New-RandomPassword {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%'
    -join (1..20 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

foreach ($upn in $UserPrincipalName) {
    $actions = @('revoke all sign-in sessions')
    if ($DisableAccount) { $actions += 'disable the account' }
    if ($ResetPassword) { $actions += 'reset the password' }
    $description = "$($actions -join ', ') for $upn (Reason: $Reason)"

    if (-not $Force -and -not $PSCmdlet.ShouldProcess($upn, $description)) {
        Write-SecurityLog "Action cancelled by user for $upn." -Level WARN
        continue
    }

    try {
        $user = Get-MgUser -UserId $upn -ErrorAction Stop
    } catch {
        Write-SecurityLog "Could not find user $upn : $_" -Level ERROR
        continue
    }

    try {
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$($user.Id)/revokeSignInSessions" | Out-Null
        Write-SecurityLog "Revoked all sign-in sessions/refresh tokens for $upn. (Reason: $Reason)" -Level SUCCESS
    } catch {
        Write-SecurityLog "Failed to revoke sessions for $upn : $_" -Level ERROR
    }

    if ($DisableAccount) {
        try {
            Update-MgUser -UserId $user.Id -AccountEnabled:$false -ErrorAction Stop
            Write-SecurityLog "Disabled account for $upn." -Level SUCCESS
        } catch {
            Write-SecurityLog "Failed to disable account for $upn : $_" -Level ERROR
        }
    }

    if ($ResetPassword) {
        $tempPassword = New-RandomPassword
        try {
            $passwordProfile = @{ Password = $tempPassword; ForceChangePasswordNextSignIn = $true }
            Update-MgUser -UserId $user.Id -PasswordProfile $passwordProfile -ErrorAction Stop
            Write-SecurityLog "Password reset for $upn. Temporary password: $tempPassword (share via a secure, out-of-band channel only - never email/chat)." -Level SUCCESS
        } catch {
            Write-SecurityLog "Failed to reset password for $upn : $_" -Level ERROR
        }
    }
}

Write-SecurityLog "Session/credential revocation actions complete for $($UserPrincipalName.Count) user(s)." -Level SUCCESS
