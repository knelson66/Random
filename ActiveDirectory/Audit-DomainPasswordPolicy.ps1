<#
.SYNOPSIS
    Audits the default domain password/lockout policy and any fine-grained password policies
    (FGPPs) against a configurable security baseline.

.DESCRIPTION
    Compares the domain's default password policy and all fine-grained password policy objects
    against recommended minimums (e.g., NIST SP 800-63B / common enterprise baseline) and flags
    gaps such as short minimum length, reversible encryption, and weak lockout thresholds.

.PARAMETER MinPasswordLength
    Minimum acceptable password length. Default 14.

.PARAMETER MaxLockoutThreshold
    Maximum acceptable number of failed attempts before lockout. Default 10 (0 = never lock out,
    always flagged).

.PARAMETER OutputPath
    Directory to write the CSV/HTML report to. Default is ./reports.

.EXAMPLE
    ./Audit-DomainPasswordPolicy.ps1 -MinPasswordLength 14

.NOTES
    Requires: ActiveDirectory PowerShell module (RSAT)
#>
[CmdletBinding()]
param(
    [int]$MinPasswordLength = 14,
    [int]$MaxLockoutThreshold = 10,
    [string]$OutputPath = "./reports"
)

$commonModule = Join-Path $PSScriptRoot "../modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1"
if (Test-Path $commonModule) { Import-Module $commonModule -Force }
Assert-ModuleAvailable -Name ActiveDirectory

$findings = @()

function Test-PasswordPolicyObject {
    param($Policy, [string]$ResourceName)

    $result = @()
    if ($Policy.MinPasswordLength -lt $MinPasswordLength) {
        $result += New-SecurityFinding -Category 'Password Policy' -Resource $ResourceName -Severity 'High' `
            -Finding "Minimum password length is $($Policy.MinPasswordLength), below the recommended $MinPasswordLength." `
            -Recommendation "Raise minimum password length to at least $MinPasswordLength characters (favor passphrases)."
    }
    if (-not $Policy.ComplexityEnabled) {
        $result += New-SecurityFinding -Category 'Password Policy' -Resource $ResourceName -Severity 'Medium' `
            -Finding 'Password complexity requirement is disabled.' `
            -Recommendation 'Enable complexity, or compensate with a significantly higher minimum length and banned-password list (Azure AD Password Protection).'
    }
    if ($Policy.ReversibleEncryptionEnabled) {
        $result += New-SecurityFinding -Category 'Password Policy' -Resource $ResourceName -Severity 'Critical' `
            -Finding 'Store passwords using reversible encryption is enabled.' `
            -Recommendation 'Disable immediately; this stores the equivalent of plaintext passwords.'
    }
    if ($Policy.LockoutThreshold -eq 0) {
        $result += New-SecurityFinding -Category 'Password Policy' -Resource $ResourceName -Severity 'High' `
            -Finding 'Account lockout is disabled (LockoutThreshold = 0), allowing unlimited password guesses.' `
            -Recommendation 'Set a lockout threshold (e.g., 10) with a reasonable observation window, or deploy smart lockout / Azure AD Password Protection.'
    } elseif ($Policy.LockoutThreshold -gt $MaxLockoutThreshold) {
        $result += New-SecurityFinding -Category 'Password Policy' -Resource $ResourceName -Severity 'Medium' `
            -Finding "Lockout threshold is $($Policy.LockoutThreshold), higher than the recommended max of $MaxLockoutThreshold." `
            -Recommendation "Reduce lockout threshold to $MaxLockoutThreshold or fewer failed attempts."
    }
    if ($Policy.MaxPasswordAge.TotalDays -eq 0) {
        $result += New-SecurityFinding -Category 'Password Policy' -Resource $ResourceName -Severity 'Low' `
            -Finding 'Passwords never expire under this policy.' `
            -Recommendation 'Modern guidance favors long passphrases + MFA over forced rotation, but confirm this is an intentional decision, not an oversight.'
    }
    return $result
}

Write-SecurityLog "Reading default domain password policy..."
$defaultPolicy = Get-ADDefaultDomainPasswordPolicy
$findings += Test-PasswordPolicyObject -Policy $defaultPolicy -ResourceName 'Default Domain Policy'

Write-SecurityLog "Reading fine-grained password policies (if any)..."
try {
    $fgpps = Get-ADFineGrainedPasswordPolicy -Filter *
    foreach ($fgpp in $fgpps) {
        $findings += Test-PasswordPolicyObject -Policy $fgpp -ResourceName "FGPP: $($fgpp.Name)"
    }
    if (-not $fgpps) {
        $findings += New-SecurityFinding -Category 'Password Policy' -Resource 'Domain' -Severity 'Informational' `
            -Finding 'No fine-grained password policies are configured; only the default domain policy applies.' `
            -Recommendation 'Consider a stricter FGPP for privileged/admin accounts (shorter max age, longer min length).'
    }
} catch {
    Write-SecurityLog "Could not query fine-grained password policies: $_" -Level WARN
}

Write-SecurityLog "Password policy audit complete: $($findings.Count) findings." -Level SUCCESS
$findings | Export-SecurityReport -Title 'AD-Password-Policy-Audit' -OutputPath $OutputPath
$findings | Sort-Object Severity | Format-Table Severity, Resource, Finding -AutoSize | Out-Host
return $findings
