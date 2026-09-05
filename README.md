# Azure & Microsoft 365 Security Engineering Toolkit

A collection of PowerShell scripts for security engineers running **audits, vulnerability
management, and day-to-day security maintenance** across **Azure** and the broader Microsoft
ecosystem: Entra ID (Azure AD), Microsoft 365 (Exchange Online, SharePoint, Teams), on-prem
Active Directory, and Microsoft Defender.

Every script is **read-only by default** (report/finding generation), with the exception of the
one clearly-marked incident-response action script (device isolation), which requires explicit
confirmation before it changes anything. Nothing here exploits, attacks, or bypasses controls —
this is defensive tooling for auditing your own (or an authorized client's) environment.

## What's in here

```
├── Connect-SecurityToolkit.ps1        # One-stop auth helper for Az / Graph / EXO / SPO / Teams
├── Invoke-FullSecurityAudit.ps1       # Orchestrator: runs a category of scripts, merges reports
├── modules/SecurityToolkitCommon/     # Shared logging + CSV/HTML/JSON report export helpers
│
├── EntraID-AzureAD/                   # Identity: roles, MFA, guests, Conditional Access, apps
├── Azure-Resources/                   # NSGs, Storage, Key Vault, public IPs, RBAC, VM posture
├── VulnerabilityManagement/           # Defender TVM, software inventory, missing patches
├── ActiveDirectory/                   # Stale accounts, privileged groups, Kerberoast/AS-REP
├── Microsoft365/                      # Exchange Online, mailbox rules, SharePoint, Teams
├── IncidentResponse/                  # Forensic triage, suspicious sign-ins, device isolation
├── Compliance/                        # Azure Policy compliance, CIS-inspired Windows baseline
└── reports/                           # Default output folder for CSV/HTML/JSON reports (gitignored)
```

### Entra ID / Azure AD (`EntraID-AzureAD/`)
| Script | Purpose |
|---|---|
| `Audit-PrivilegedRoleAssignments.ps1` | Flags Tier-0 role holders, stale/disabled privileged accounts, guests with directory roles |
| `Audit-MFAStatus.ps1` | Finds users with no MFA, weak (SMS-only) MFA, or privileged accounts without phishing-resistant MFA |
| `Audit-GuestUsers.ps1` | Stale/unused B2B guests, guests from non-approved domains, over-permissioned guests |
| `Audit-ConditionalAccessPolicies.ps1` | Coverage gaps: no MFA-for-all, no legacy-auth block, report-only policies |
| `Audit-AppRegistrationSecrets.ps1` | Expiring/expired app secrets & certs, high-risk API permissions, multi-tenant apps |

### Azure Resources (`Azure-Resources/`)
| Script | Purpose |
|---|---|
| `Audit-NetworkSecurityGroups.ps1` | Internet-exposed RDP/SSH/SMB/SQL/WinRM rules, wildcard-allow rules |
| `Audit-StorageAccountSecurity.ps1` | Public blob access, HTTPS/TLS enforcement, shared key auth, network defaults, soft delete |
| `Audit-KeyVaultSecurity.ps1` | Purge protection, network ACLs, overly broad access policies, expiring secrets |
| `Audit-PublicIPExposure.ps1` | Inventories public IPs, what they're attached to, and NSG exposure on VM NICs |
| `Audit-RBACAssignments.ps1` | Direct high-privilege grants at subscription scope, classic admins, wildcard custom roles |
| `Audit-VMDiskEncryption.ps1` | Disk encryption, boot diagnostics, missing Defender/AMA extensions, VM Agent health |
| `Get-DefenderForCloudSecureScore.ps1` | Pulls Secure Score and unhealthy recommendations, ranked for remediation |

### Vulnerability Management (`VulnerabilityManagement/`)
| Script | Purpose |
|---|---|
| `Get-DefenderTVMVulnerabilities.ps1` | Exposed CVEs from Defender TVM via Graph, ranked by CVSS + exposed device count |
| `Export-DefenderSoftwareInventory.ps1` | End-of-support software, high-weakness-count products, unauthorized software detection |
| `Get-MissingWindowsUpdates.ps1` | Local/remote scan for missing security updates via the Windows Update Agent API |

### Active Directory (`ActiveDirectory/`)
| Script | Purpose |
|---|---|
| `Audit-StaleADAccounts.ps1` | Enabled users/computers with no recent logon, password-never-expires flags |
| `Audit-PrivilegedGroupMembership.ps1` | Tier-0 group membership, nesting, disabled/stale privileged accounts |
| `Audit-DomainPasswordPolicy.ps1` | Default + fine-grained password policy vs. a configurable baseline |
| `Find-KerberoastableAccounts.ps1` | SPN-bearing accounts, RC4 usage, password age, privileged+SPN combinations (defensive, no ticket requests) |
| `Find-ASREPRoastableAccounts.ps1` | Accounts with Kerberos pre-auth disabled (defensive, read-only) |

### Microsoft 365 (`Microsoft365/`)
| Script | Purpose |
|---|---|
| `Audit-ExchangeOnlineSecurity.ps1` | Audit logging, Unified Audit Log, legacy/basic auth, DKIM, risky transport rules, forwarding |
| `Audit-MailboxDelegationAndInboxRules.ps1` | Full Access/Send As grants, hidden or auto-delete inbox rules (BEC indicators) |
| `Audit-SharePointExternalSharing.ps1` | Tenant + site-level sharing capability, anonymous link expiration |
| `Audit-TeamsExternalAccess.ps1` | Federation openness, guest access, anonymous meeting join/start settings |

### Incident Response (`IncidentResponse/`)
| Script | Purpose |
|---|---|
| `Collect-WindowsForensicTriage.ps1` | Read-only triage bundle: processes+hashes, network connections, persistence, event logs |
| `Get-SuspiciousSignInActivity.ps1` | Impossible travel, brute force/spray bursts, Identity Protection risk correlation |
| `Invoke-DefenderDeviceIsolation.ps1` | **Disruptive.** Isolates/un-isolates a Defender for Endpoint device (confirmation required) |

### Compliance (`Compliance/`)
| Script | Purpose |
|---|---|
| `Audit-AzurePolicyCompliance.ps1` | Summarizes non-compliant resources against assigned Azure Policy initiatives |
| `Test-WindowsSecurityBaseline.ps1` | Local/remote CIS-inspired checks: firewall, SMBv1, LSA protection, BitLocker, RDP NLA, etc. |

## Prerequisites

Install the modules relevant to what you plan to run:

```powershell
Install-Module Az -Scope CurrentUser
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
Install-Module MicrosoftTeams -Scope CurrentUser
# For ActiveDirectory/*.ps1 scripts, install RSAT on Windows:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

PowerShell 7+ is recommended tenant-wide, but scripts are written to also run on Windows
PowerShell 5.1 where the underlying module supports it.

## Quick start

```powershell
# 1. Authenticate to the services you need (least privilege: only request what you'll use)
./Connect-SecurityToolkit.ps1 -Services Azure, Graph

# 2. Run an individual audit
./Azure-Resources/Audit-NetworkSecurityGroups.ps1 -OutputPath ./reports

# 3. ...or run a whole category and get one consolidated report
./Invoke-FullSecurityAudit.ps1 -Categories Azure, EntraID -OutputPath ./reports
```

Every audit script:
- Emits standardized finding objects (`Category`, `Resource`, `Severity`, `Finding`, `Recommendation`)
- Writes CSV, JSON, and a self-contained, color-coded HTML report to `-OutputPath` (default `./reports`)
- Prints a live summary table to the console as it runs
- Can be run standalone or via `Invoke-FullSecurityAudit.ps1`

## Required permissions (least privilege)

Scripts request read-only Microsoft Graph scopes such as `User.Read.All`,
`RoleManagement.Read.Directory`, `Policy.Read.All`, `Vulnerability.Read.All`, and
`AuditLog.Read.All`/`AuditLog.Read.Directory` — see each script's `.NOTES` block for its exact
requirements, and `Connect-SecurityToolkit.ps1` for the full default scope list. The one exception
is `IncidentResponse/Invoke-DefenderDeviceIsolation.ps1`, which needs the disruptive
`Machine.Isolate` scope and is never requested by default.

For Azure, an account with **Reader** at the subscription/management-group scope is sufficient
for every `Azure-Resources/` and `Compliance/Audit-AzurePolicyCompliance.ps1` script.

## Responsible use

These scripts are intended for auditing environments you own or are explicitly authorized to
assess (internal security team, engaged pentest/audit, or your own tenant/lab). The Kerberoasting
and AS-REP Roasting scripts are read-only detection tools — they enumerate exposure without
requesting any tickets — and the device isolation script requires interactive confirmation because
it is disruptive to the target endpoint.

## Contributing

New scripts should follow the existing pattern: comment-based help (`SYNOPSIS`/`DESCRIPTION`/
`PARAMETER`/`EXAMPLE`/`NOTES`), emit findings via `New-SecurityFinding`, export via
`Export-SecurityReport`, and `return $findings` so the script composes with
`Invoke-FullSecurityAudit.ps1`.
