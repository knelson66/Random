# Azure & Microsoft 365 Security Engineering Toolkit

A collection of PowerShell (and, for the Azure-resource checks, native Azure CLI/bash) scripts for
security engineers running **audits, vulnerability management, and day-to-day security
maintenance** across **Azure** and the broader Microsoft ecosystem: Entra ID, Intune, Purview,
Defender (Cloud Apps, Endpoint, XDR), Sentinel, Power Platform, Azure Virtual Desktop/Windows 365,
Microsoft 365 (Exchange Online, SharePoint, OneDrive, Teams, Power BI), on-prem Active Directory,
Azure DevOps/GitHub, and a handful of third-party integrations (Jira, Elastic, Nudge Security,
SafeBase).

Every script is **read-only by default** (report/finding generation), with the exception of two
clearly-marked incident-response action scripts (Defender device isolation, session/credential
revocation), which require explicit confirmation before they change anything. Nothing here
exploits, attacks, or bypasses controls — this is defensive tooling for auditing your own (or an
authorized client's) environment.

## What's in here

```
├── Connect-SecurityToolkit.ps1        # One-stop auth helper for Az / Graph / EXO / SPO / Teams
├── Invoke-FullSecurityAudit.ps1       # Orchestrator: runs a category of scripts, merges reports
├── modules/SecurityToolkitCommon/     # Shared logging + CSV/JSON/HTML/Excel/PDF report export
│
├── EntraID-AzureAD/         # Identity: roles, PIM, MFA, guests, Conditional Access, apps, consent
├── Azure-Resources/         # NSGs, Storage, Key Vault, SQL, App Service, AKS, ACR, VM posture
├── Azure-Resources-CLI/     # Same core checks as Azure-Resources/, as az cli + bash + jq
├── Intune/                  # Device compliance, config profiles, MAM, update rings, BitLocker
├── Purview/                 # DLP, sensitivity labels, retention, insider risk, eDiscovery
├── DefenderCloudApps/       # OAuth app grants, MDA policy coverage, alert triage
├── Sentinel/                # Analytics rules, incidents, data connectors, automation rules
├── PowerPlatform/           # DLP policy coverage, Power Automate flow risk
├── VirtualDesktop/          # Azure Virtual Desktop host pools, Windows 365 Cloud PCs
├── DevOpsSecurity/          # Azure DevOps and GitHub organization security
├── VulnerabilityManagement/ # Defender TVM, software inventory, missing patches, ASR rules
├── ActiveDirectory/         # Stale accounts, privileged groups, Kerberoast/AS-REP, delegation, LAPS
├── Microsoft365/            # Exchange Online, mailbox rules, SharePoint, Teams, OneDrive, Power BI
├── IncidentResponse/        # Forensic triage, suspicious sign-ins, XDR incidents, containment
├── Compliance/              # Azure Policy, CIS-inspired Windows baseline, Microsoft Secure Score
├── ThirdParty/              # Jira, Elastic, Nudge Security, SafeBase integrations
└── reports/                 # Default output folder for CSV/JSON/HTML/XLSX/PDF reports (gitignored)
```

### Entra ID / Azure AD (`EntraID-AzureAD/`)
| Script | Purpose |
|---|---|
| `Audit-PrivilegedRoleAssignments.ps1` | Flags Tier-0 role holders, stale/disabled privileged accounts, guests with directory roles |
| `Audit-MFAStatus.ps1` | Finds users with no MFA, weak (SMS-only) MFA, or privileged accounts without phishing-resistant MFA |
| `Audit-GuestUsers.ps1` | Stale/unused B2B guests, guests from non-approved domains, over-permissioned guests |
| `Audit-ConditionalAccessPolicies.ps1` | Coverage gaps: no MFA-for-all, no legacy-auth block, report-only policies |
| `Audit-AppRegistrationSecrets.ps1` | Expiring/expired app secrets & certs, high-risk API permissions, multi-tenant apps |
| `Audit-PIMEligibleAssignments.ps1` | Permanently eligible/active PIM assignments, Tier-0 activation policy gaps (MFA/approval) |
| `Audit-EnterpriseAppConsentGrants.ps1` | Tenant user-consent policy risk, admin consent workflow status, sensitive-scope user consents |
| `Audit-NamedLocationsAndTrustedNetworks.ps1` | Overly broad trusted IP ranges, unused named locations |
| `Audit-CrossTenantAccessSettings.ps1` | Default/partner B2B trust settings, unscoped B2B direct connect |

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
| `Audit-SQLDatabaseSecurity.ps1` | Firewall exposure, auditing, Defender for SQL, TDE, Entra ID admin |
| `Audit-AppServiceSecurity.ps1` | HTTPS/TLS/FTP enforcement, remote debugging, managed identity, Easy Auth |
| `Audit-ContainerRegistrySecurity.ps1` | Admin account, network exposure, anonymous pull, retention policy |
| `Audit-AKSClusterSecurity.ps1` | API server exposure, Entra ID RBAC, network policy, Defender profile, legacy service principals |
| `Audit-ManagedIdentityUsage.ps1` | Orphaned user-assigned identities, over-privileged/subscription-scope grants |

### Azure Resources via the Azure CLI (`Azure-Resources-CLI/`)

A native `az` + `bash` + `jq` port of the core `Azure-Resources/` scripts, for anyone who prefers
(or is standardized on) the Azure CLI over the Az PowerShell module — Azure Cloud Shell's bash
mode, CI pipelines, WSL, etc. Same checks, same finding schema, same severities.

| Script | PowerShell equivalent |
|---|---|
| `audit-network-security-groups.sh` | `Audit-NetworkSecurityGroups.ps1` |
| `audit-storage-account-security.sh` | `Audit-StorageAccountSecurity.ps1` |
| `audit-keyvault-security.sh` | `Audit-KeyVaultSecurity.ps1` |
| `audit-public-ip-exposure.sh` | `Audit-PublicIPExposure.ps1` |
| `audit-rbac-assignments.sh` | `Audit-RBACAssignments.ps1` |
| `audit-vm-disk-encryption.sh` | `Audit-VMDiskEncryption.ps1` |
| `get-defender-secure-score.sh` | `Get-DefenderForCloudSecureScore.ps1` (uses `az rest` against the Microsoft.Security API directly, so it doesn't depend on the `az security` extension) |
| `connect-azure-cli.sh` | `Connect-SecurityToolkit.ps1` (runs `az login` if needed, lets you pick a subscription) |
| `invoke-full-security-audit.sh` | `Invoke-FullSecurityAudit.ps1` (runs all of the above, merges findings) |

**Requirements:** `az` (logged in via `az login`) and `jq`. Both ship by default in Azure Cloud
Shell. Nothing else is required to get CSV + JSON output.

**Getting HTML/Excel/PDF too, not just CSV/JSON:** bash has no native Excel/PDF writer, so these
scripts lean on the same `modules/SecurityToolkitCommon` PowerShell module the `.ps1` scripts use.
Every script writes CSV + JSON via pure `jq`, then — **only if `pwsh` is found on PATH** —
automatically calls into `SecurityToolkitCommon` to upgrade that same data into HTML/Excel/PDF too
(the `ImportExcel`/`PSWriteOffice` caveats from "Report output formats" below still apply). If
`pwsh` isn't installed, you still get complete CSV/JSON, plus a log line telling you the exact
command to run later once PowerShell 7 is available:

```bash
./connect-azure-cli.sh                              # az login + pick a subscription
./audit-network-security-groups.sh -o ./reports      # CSV + JSON always; HTML/Excel/PDF if pwsh is present
./invoke-full-security-audit.sh -o ./reports         # run all 7 + one consolidated report
```

Azure Cloud Shell conveniently has `pwsh` available too (switch modes with the dropdown, or run
`pwsh` from bash) so the upgrade step works there out of the box once `Install-Module ImportExcel,
PSWriteOffice -Scope CurrentUser` has been run once.

### Microsoft Intune (`Intune/`)
| Script | Purpose |
|---|---|
| `Audit-DeviceCompliancePolicies.ps1` | Policy assignment coverage per platform, non-compliant/grace-period/unknown-state devices |
| `Audit-ConfigurationProfileCoverage.ps1` | Unassigned profiles, deployment errors/conflicts, missing security baselines |
| `Audit-AppProtectionPolicies.ps1` | iOS/Android MAM policy coverage, PIN/Save-As/managed-browser/offline-grace settings |
| `Get-NonCompliantDevices.ps1` | Per-device breakdown of exactly which compliance setting is failing, plus jailbreak/encryption/staleness |
| `Audit-WindowsUpdateRings.ps1` | Quality update deferral length, restart/deadline behavior, unassigned rings |
| `Audit-BitLockerRecoveryKeyEscrow.ps1` | Encrypted Windows devices with no recovery key escrowed to Entra ID |

### Microsoft Purview (`Purview/`)
| Script | Purpose |
|---|---|
| `Audit-DLPPolicies.ps1` | Test-mode policies, workload coverage gaps, rules with no notify/block/alert action |
| `Audit-SensitivityLabels.ps1` | No encrypting label, no default label, mandatory labeling, auto-labeling presence |
| `Audit-RetentionPolicies.ps1` | Workload coverage gaps, unbounded delete rules, disabled policies |
| `Audit-InsiderRiskPolicies.ps1` | Policy scope gaps, open-alert triage backlog |
| `Audit-EDiscoveryAndAuditStatus.ps1` | Unified Audit Log status, stale eDiscovery cases, active legal holds |

### Microsoft Defender for Cloud Apps (`DefenderCloudApps/`)
| Script | Purpose |
|---|---|
| `Audit-OAuthAppGrants.ps1` | High-risk delegated scopes, unverified publishers, tenant-wide admin consent (via Graph) |
| `Audit-CloudAppSecurityPolicies.ps1` | File/activity/anomaly policy coverage and Cloud Discovery shadow IT risk (via MDA API) |
| `Get-CloudAppSecurityAlerts.ps1` | Open-alert SLA breach, volume, and per-user alert clustering (via MDA API) |

### Microsoft Sentinel (`Sentinel/`)
| Script | Purpose |
|---|---|
| `Audit-AnalyticsRuleCoverage.ps1` | Disabled rules, MITRE ATT&CK tactic coverage gaps, grouping/query-gap issues |
| `Get-OpenIncidentsSummary.ps1` | High/Critical SLA breach, unassigned incidents, New-status queue depth |
| `Audit-DataConnectorStatus.ps1` | Missing/disabled key Microsoft data connectors (Entra ID, M365, Defender, Cloud Apps) |
| `Audit-AutomationRuleCoverage.ps1` | No-action rules, broken/disabled playbook (Logic App) references |

### Power Platform (`PowerPlatform/`)
| Script | Purpose |
|---|---|
| `Audit-DLPPolicyCoverage.ps1` | Environments with no DLP policy, risky connectors grouped with business connectors |
| `Audit-PowerAutomateFlowRisk.ps1` | Single-owner flows, generic/HTTP connector usage |

### Virtual Desktop (`VirtualDesktop/`)
| Script | Purpose |
|---|---|
| `Audit-AVDHostPoolSecurity.ps1` | RDP security layer overrides, validation-environment flag, Start VM on Connect, unhealthy hosts |
| `Audit-Windows365CloudPCSecurity.ps1` | Provisioning policy network/SSO config, Cloud PC provisioning/Intune-enrollment health |

### DevOps Security (`DevOpsSecurity/`)
| Script | Purpose |
|---|---|
| `Audit-AzureDevOpsSecurity.ps1` | Missing branch/build policies, PAT max-lifetime policy (via Azure DevOps REST API) |
| `Audit-GitHubOrgSecurity.ps1` | 2FA enforcement, owner count, outside collaborators, branch protection, secret scanning (via GitHub REST API) |

### Vulnerability Management (`VulnerabilityManagement/`)
| Script | Purpose |
|---|---|
| `Get-DefenderTVMVulnerabilities.ps1` | Exposed CVEs from Defender TVM via Graph, ranked by CVSS + exposed device count |
| `Export-DefenderSoftwareInventory.ps1` | End-of-support software, high-weakness-count products, unauthorized software detection |
| `Get-MissingWindowsUpdates.ps1` | Local/remote scan for missing security updates via the Windows Update Agent API |
| `Audit-ASRRulesCoverage.ps1` | Attack Surface Reduction rule coverage against Microsoft's high-value rule set (Block vs. Audit) |
| `Audit-DefenderAVExclusions.ps1` | Overly broad path/process/extension exclusions, unpruned exclusion lists |

### Active Directory (`ActiveDirectory/`)
| Script | Purpose |
|---|---|
| `Audit-StaleADAccounts.ps1` | Enabled users/computers with no recent logon, password-never-expires flags |
| `Audit-PrivilegedGroupMembership.ps1` | Tier-0 group membership, nesting, disabled/stale privileged accounts |
| `Audit-DomainPasswordPolicy.ps1` | Default + fine-grained password policy vs. a configurable baseline |
| `Find-KerberoastableAccounts.ps1` | SPN-bearing accounts, RC4 usage, password age, privileged+SPN combinations (defensive, no ticket requests) |
| `Find-ASREPRoastableAccounts.ps1` | Accounts with Kerberos pre-auth disabled (defensive, read-only) |
| `Find-UnconstrainedDelegation.ps1` | Non-DC computer/user accounts trusted for unconstrained delegation (defensive, read-only) |
| `Audit-LAPSCoverage.ps1` | Windows LAPS/legacy LAPS schema presence, password-never-set/stale-rotation coverage |
| `Audit-GPOPermissionsDelegation.ps1` | Non-standard or overly broad (Authenticated Users/Everyone) write-level GPO delegation |

### Microsoft 365 (`Microsoft365/`)
| Script | Purpose |
|---|---|
| `Audit-ExchangeOnlineSecurity.ps1` | Audit logging, Unified Audit Log, legacy/basic auth, DKIM, risky transport rules, forwarding |
| `Audit-MailboxDelegationAndInboxRules.ps1` | Full Access/Send As grants, hidden or auto-delete inbox rules (BEC indicators) |
| `Audit-SharePointExternalSharing.ps1` | Tenant + site-level sharing capability, anonymous link expiration |
| `Audit-TeamsExternalAccess.ps1` | Federation openness, guest access, anonymous meeting join/start settings |
| `Audit-OneDriveSharingSettings.ps1` | Per-user OneDrive sharing drift from tenant default, large+broadly-shared accounts |
| `Audit-PowerBIWorkspaceSecurity.ps1` | Publish-to-web tenant setting, broad-group workspace access, guest access |

### Incident Response (`IncidentResponse/`)
| Script | Purpose |
|---|---|
| `Collect-WindowsForensicTriage.ps1` | Read-only triage bundle: processes+hashes, network connections, persistence, event logs |
| `Get-SuspiciousSignInActivity.ps1` | Impossible travel, brute force/spray bursts, Identity Protection risk correlation |
| `Get-DefenderIncidents.ps1` | Microsoft 365 Defender (XDR) open-incident SLA, ownership, and blast-radius summary |
| `Invoke-DefenderDeviceIsolation.ps1` | **Disruptive.** Isolates/un-isolates a Defender for Endpoint device (confirmation required) |
| `Revoke-UserSessionsAndCredentials.ps1` | **Disruptive.** Revokes sessions and optionally disables/resets a compromised user (confirmation required) |

### Compliance (`Compliance/`)
| Script | Purpose |
|---|---|
| `Audit-AzurePolicyCompliance.ps1` | Summarizes non-compliant resources against assigned Azure Policy initiatives |
| `Test-WindowsSecurityBaseline.ps1` | Local/remote CIS-inspired checks: firewall, SMBv1, LSA protection, BitLocker, RDP NLA, etc. |
| `Get-MicrosoftSecureScoreTrend.ps1` | Tenant-wide Microsoft Secure Score trend and point-value-ranked remediation gaps |

### Third-Party Integrations (`ThirdParty/`)
| Script | Purpose |
|---|---|
| `New-JiraTicketsFromFindings.ps1` | Bulk-creates Jira issues from any toolkit findings file, severity-filtered, dry-run supported |
| `Send-FindingsToElastic.ps1` | Bulk-indexes any toolkit findings file into Elasticsearch for SIEM dashboards |
| `Get-NudgeSecurityShadowIT.ps1` | Unsanctioned/high-risk/unowned SaaS apps via the Nudge Security API |
| `Get-SafeBaseTrustCenterActivity.ps1` | Pending Trust Center access requests past SLA, access from unrecognized domains |

> The Nudge Security and SafeBase scripts carry an explicit disclaimer in their `.NOTES`: live API
> documentation for those two products could not be fetched while writing them (network egress to
> their docs sites was blocked), so field/endpoint names are best-effort — verify against current
> vendor docs before relying on them in production.

## Prerequisites

Install the modules relevant to what you plan to run:

```powershell
Install-Module Az -Scope CurrentUser
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
Install-Module MicrosoftTeams -Scope CurrentUser
Install-Module MicrosoftPowerBIMgmt -Scope CurrentUser
Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser
# For ActiveDirectory/*.ps1 scripts, install RSAT on Windows:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Optional, for Excel (.xlsx) and PDF report output - see "Report output formats" below:
Install-Module ImportExcel -Scope CurrentUser
Install-Module PSWriteOffice -Scope CurrentUser
```

`Sentinel/*.ps1` additionally needs `Az.SecurityInsights`; `Azure-Resources/*.ps1` scripts touching
SQL/App Service/Container Registry/AKS/managed identities need `Az.Sql`, `Az.Websites`,
`Az.ContainerRegistry`, `Az.Aks`, and `Az.ManagedServiceIdentity` respectively (all `Install-Module
<name> -Scope CurrentUser`). `DefenderCloudApps/`, `DevOpsSecurity/`, and `ThirdParty/` scripts call
REST APIs directly with `Invoke-RestMethod`/`Invoke-MgGraphRequest` and need no extra module beyond
`SecurityToolkitCommon` itself — just the API token/credential each script's `-ApiToken`/`-Token`
parameter asks for.

PowerShell 7+ is recommended tenant-wide, but scripts are written to also run on Windows
PowerShell 5.1 where the underlying module supports it.

### Running from Azure Cloud Shell / alongside the Azure CLI

If you'd rather stay entirely in the Azure CLI, use **`Azure-Resources-CLI/`** (see above) instead
of the PowerShell scripts for the core Azure-resource checks — it's a native `az`/`bash`/`jq` port
that authenticates the same way you already do (`az login`), no separate PowerShell login required.

The `.ps1` scripts, on the other hand, use the **Az PowerShell module** (`Connect-AzAccount`),
Microsoft Graph PowerShell SDK, and the Exchange Online/SharePoint/Teams/Power BI/Power Platform
modules — they don't call the `az` CLI directly, so an `az login` alone will not authenticate them
(Az PowerShell keeps a separate token cache from the Azure CLI). If you do want to run those
(there's no CLI/bash port outside of the core `Azure-Resources/` category), two easy paths:

- **Azure Cloud Shell (PowerShell mode)** — the Az PowerShell module ships pre-installed and is
  already authenticated to your signed-in account for the session, so `Azure-Resources/`,
  `EntraID-AzureAD/`, and `Compliance/Audit-AzurePolicyCompliance.ps1` scripts work with no
  `Connect-AzAccount` step. Just `Install-Module Microsoft.Graph, ImportExcel, PSWriteOffice
  -Scope CurrentUser` once per Cloud Shell storage account for the rest.
- **Local machine with the Azure CLI installed** — run `./Connect-SecurityToolkit.ps1` once per
  session (see Quick start below); it calls `Connect-AzAccount`/`Connect-MgGraph` etc. for you.
  You can keep using `az` for everything else — the two tools coexist fine side by side.

## Report output formats

Every script writes its findings via the shared `Export-SecurityReport` function
(`modules/SecurityToolkitCommon`), which can produce five formats. `-Format All` (the default) is
requested by every script and is layered so the formats with no extra dependencies always
succeed:

| Format | Dependency | Notes |
|---|---|---|
| CSV | None | Raw data, easiest to pull into another tool |
| JSON | None | For feeding into a SIEM/ticketing pipeline |
| HTML | None | Self-contained, color-coded by severity, opens in any browser |
| **Excel (.xlsx)** | [`ImportExcel`](https://github.com/dfinke/ImportExcel) | `Findings` sheet (filterable table, frozen header, rows colored by severity), plus `Summary` and `ByCategory` roll-up sheets. No Microsoft Excel installation needed to generate it. |
| **PDF** | [`PSWriteOffice`](https://github.com/EvotecIT/PSWriteOffice) | A portable, printable summary (severity counts + full findings table). Cross-platform (Windows/Linux/macOS), no Office install needed. If PSWriteOffice isn't installed, the toolkit automatically falls back to printing the HTML report to PDF with a headless Chromium-based browser (Edge/Chrome/Chromium) if one is found on PATH. |

If neither the Excel nor PDF dependency (nor a fallback browser, for PDF) is available, that one
format is skipped with a warning telling you what to install — the rest of the report still
completes. To force a single format instead of the full set:

```powershell
./Azure-Resources/Audit-KeyVaultSecurity.ps1 -OutputPath ./reports
# then, from the returned findings, generate just one extra format if you'd rather not re-run the audit:
Import-Module ./modules/SecurityToolkitCommon/SecurityToolkitCommon.psd1
$findings | Export-SecurityReport -Title 'KeyVault-Audit' -OutputPath ./reports -Format Excel
```

There's also a `-Format Polished` option (HTML + Excel + PDF, no CSV/JSON) - useful for bridging
findings you already have in JSON (e.g., from an `Azure-Resources-CLI/` run) into the nicer formats
without re-dumping raw data that's already on disk.

## Quick start

```powershell
# 1. Authenticate to the services you need (least privilege: only request what you'll use)
./Connect-SecurityToolkit.ps1 -Services Azure, Graph

# 2. Run an individual audit
./Azure-Resources/Audit-NetworkSecurityGroups.ps1 -OutputPath ./reports

# 3. ...or run a whole category and get one consolidated report
./Invoke-FullSecurityAudit.ps1 -Categories Azure, EntraID -OutputPath ./reports

# ...or everything the orchestrator supports in one go
./Invoke-FullSecurityAudit.ps1 -OutputPath ./reports
```

Every audit script:
- Emits standardized finding objects (`Category`, `Resource`, `Severity`, `Finding`, `Recommendation`)
- Writes CSV, JSON, HTML, Excel, and PDF reports to `-OutputPath` (default `./reports`) — see
  "Report output formats" above for the Excel/PDF dependencies
- Prints a live summary table to the console as it runs
- Can be run standalone or via `Invoke-FullSecurityAudit.ps1` (for categories with no
  environment-specific mandatory parameters - see that script's `.NOTES` for what's excluded and why)

## Required permissions (least privilege)

Scripts request read-only Microsoft Graph scopes such as `User.Read.All`,
`RoleManagement.Read.Directory`, `Policy.Read.All`, `Vulnerability.Read.All`,
`DeviceManagementConfiguration.Read.All`, `SecurityIncident.Read.All`, and
`AuditLog.Read.All`/`AuditLog.Read.Directory` — see each script's `.NOTES` block for its exact
requirements, and `Connect-SecurityToolkit.ps1` for the full default scope list. The exceptions are
`IncidentResponse/Invoke-DefenderDeviceIsolation.ps1` (needs `Machine.Isolate`) and
`IncidentResponse/Revoke-UserSessionsAndCredentials.ps1` (needs `User.ReadWrite.All`), both
disruptive and never requested by default.

For Azure, an account with **Reader** at the subscription/management-group scope is sufficient for
every read-only `Azure-Resources/` and `Compliance/Audit-AzurePolicyCompliance.ps1` script.
`DefenderCloudApps/`, `DevOpsSecurity/`, and `ThirdParty/` scripts authenticate with their own
API token/PAT rather than Entra ID sign-in - see each script's `.PARAMETER ApiToken`/`-Token` help.

## Responsible use

These scripts are intended for auditing environments you own or are explicitly authorized to
assess (internal security team, engaged pentest/audit, or your own tenant/lab). The Kerberoasting,
AS-REP Roasting, and unconstrained-delegation scripts are read-only detection tools — they
enumerate exposure without requesting any tickets — and both action scripts (device isolation,
session/credential revocation) require interactive confirmation because they are disruptive to the
target endpoint/user.

## Related open-source security tools

This toolkit is intentionally lightweight and focused on producing clean, portable reports. For
deeper or more specialized coverage, these are established, widely-used open-source projects worth
knowing about. **Several are dual-use (they can enumerate/attack as well as audit) and must only be
run against a tenant/environment you own or are explicitly authorized to test** — that's called out
below where it applies.

**Curated lists** (good starting points for anything not covered here):
- [merill/awesome-entra](https://github.com/merill/awesome-entra) — curated list of Microsoft Entra ID tools, docs, and scripts
- [kmcquade/awesome-azure-security](https://github.com/kmcquade/awesome-azure-security) — curated list of Azure security tooling
- [Kyuu-Ji/Awesome-Azure-Pentest](https://github.com/Kyuu-Ji/Awesome-Azure-Pentest) — Azure-focused pentest resource collection

**Configuration/posture auditing** (closest in spirit to this repo — read-only, report-generating):
- [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) — multi-cloud (incl. Azure) security auditing, generates an interactive HTML report
- [CrowdStrike/CRT](https://github.com/CrowdStrike/CRT) — CrowdStrike Reporting Tool for Azure; reviews Entra ID role assignments and configuration weaknesses, HTML output
- [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) — open-source CSPM covering AWS/Azure/GCP/K8s against CIS and other compliance frameworks
- [PingCastle](https://github.com/vletoux/PingCastle) (now maintained by Netwrix) — on-prem AD risk assessment with a maturity-model score and polished HTML report; a good reference for report design
- PowerShell Gallery `ORCA` (Office 365 Recommended Configuration Analyzer) — checks Defender for Office 365 configuration; note Microsoft has been folding this into the native Configuration Analyzer in the Defender portal, so check current maintenance status before relying on it

**Incident response / threat hunting for Entra ID & Microsoft 365** (complements `IncidentResponse/`):
- [T0pCat/Hawk](https://github.com/T0pCat/Hawk) — actively maintained M365/Entra ID incident response data-gathering module (successor in spirit to CISA's Sparrow)
- [cisagov/Sparrow](https://github.com/cisagov/Sparrow) — CISA's original M365/Azure AD post-compromise detection tool (archived, but a solid reference for what to check after a suspected breach)

**Attack-path / identity graphing** (run defensively against your own tenant to see what an attacker's recon would surface — requires authorization):
- [SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) + [BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound) — attack-path graphing for on-prem AD and Entra ID
- [dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools) — Entra ID enumeration/analysis framework (ROADrecon)
- [Azure/Stormspotter](https://github.com/Azure/Stormspotter) — Azure resource/Entra ID attack-surface graphing, originally a Microsoft red-team tool
- [hausec/PowerZure](https://github.com/hausec/PowerZure) and [Gerenios/AADInternals](https://github.com/Gerenios/AADInternals) — deep Azure/Entra ID recon, privilege-escalation identification, and (for AADInternals) low-level admin/testing functions not exposed elsewhere. Powerful and genuinely dual-use — treat as red-team/pentest tooling, not something to run casually against production.
- [dafthack/MFASweep](https://github.com/dafthack/MFASweep) — checks whether MFA is actually enforced across individual M365 protocols/services; performs live sign-in attempts, so only run it with explicit authorization and test credentials

**Reporting libraries this toolkit builds on directly:**
- [dfinke/ImportExcel](https://github.com/dfinke/ImportExcel) — Excel file generation/formatting without installing Microsoft Excel
- [EvotecIT/PSWriteOffice](https://github.com/EvotecIT/PSWriteOffice) — cross-platform Word/Excel/PDF document automation (successor to the now-archived `PSWritePDF`)
- [EvotecIT/PSWriteHTML](https://github.com/EvotecIT/PSWriteHTML) — an option if you outgrow this repo's built-in HTML report and want interactive dashboards (sortable/searchable tables, charts) instead

## Contributing

New PowerShell scripts should follow the existing pattern: comment-based help
(`SYNOPSIS`/`DESCRIPTION`/`PARAMETER`/`EXAMPLE`/`NOTES`), emit findings via `New-SecurityFinding`,
export via `Export-SecurityReport`, and `return $findings` so the script composes with
`Invoke-FullSecurityAudit.ps1`. If it calls a REST API you're not fully certain of the exact
field/endpoint names for (as with the Nudge Security/SafeBase scripts), say so explicitly in
`.NOTES` rather than presenting a guess as verified.

New `Azure-Resources-CLI/` scripts should `source lib/common.sh`, emit findings via `add_finding`
(or a `jq` filter piped into `$FINDINGS_FILE` for bulk transforms), and end with `write_report
"Title" "$OUTPUT_DIR"` so they pick up CSV/JSON output and the automatic HTML/Excel/PDF upgrade
path. Run `shellcheck` on any new script before submitting it.
