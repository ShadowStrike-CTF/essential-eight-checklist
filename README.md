# Essential Eight Compliance Checker

**Version 1.0.0**

Automate Australian Signals Directorate (ASD) Essential Eight compliance audits with PowerShell. This script checks Windows systems against all eight baseline mitigation strategies and produces comprehensive compliance reports.

## What is Essential Eight?

The Essential Eight is a set of baseline cyber security mitigation strategies published by the Australian Signals Directorate (ASD). It's referenced in government procurement, security assessments, and organisational policies across Australian public and private sectors.

The eight strategies are:
1. Application Control
2. Patch Applications
3. Configure Microsoft Office Macro Settings
4. User Application Hardening
5. Restrict Administrative Privileges
6. Patch Operating Systems
7. Multi-Factor Authentication
8. Regular Backups

## Features

- **Comprehensive audit:** Checks all eight Essential Eight strategies
- **Colour-coded output:** PASS (green), FAIL (red), WARN (yellow), INFO (cyan)
- **Timestamped reports:** Automatic `.txt` file generation
- **No dependencies:** Uses built-in PowerShell cmdlets only
- **ML1 baseline focus:** Checks foundational controls before maturity progression
- **Quick execution:** Complete audit in seconds

## Requirements

- PowerShell 5.1 or later (Windows 10+)
- Administrator privileges recommended for complete audit

## Quick Start

### Execution Policy Setup

First-time PowerShell script runners may need to enable script execution:

**Step 1: Set policy**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Step 2: Unblock if downloaded from GitHub**

```powershell
Unblock-File .\essential_eight.ps1
```

### ⚠️ Security: Verify Before Executing

**Before running this script:**
- Read the entire source code
- Verify it does what it claims
- Check for unexpected behaviour

**ABC principle:** Assume nothing. Believe nothing. Check everything.

This script is unsigned because open-source transparency beats blind trust in signatures. You are responsible for verifying code before execution.

---

### Basic Audit

```powershell
.\essential_eight.ps1
```

Runs the audit and writes report to current directory.

### Specify Output Directory

```powershell
.\essential_eight.ps1 -OutputDir "C:\Compliance\Reports"
```

### Run as Administrator

For complete audit coverage, run with elevation:

```powershell
# Right-click PowerShell → "Run as Administrator"
.\essential_eight.ps1
```

## Sample Output

```
[ESSENTIAL EIGHT COMPLIANCE AUDIT]
System: WORKSTATION-01

[STRATEGY 1: APPLICATION CONTROL]
[PASS] AppControl - AppLocker Policy: Effective rules configured
[INFO] AppControl - WDAC Policy: Not deployed (AppLocker in use)

[STRATEGY 2: PATCH APPLICATIONS]
[PASS] Patching - Windows Update Service: Running
[PASS] Patching - Last Update: 2026-04-18 - 6 days ago

[STRATEGY 3: OFFICE MACRO SETTINGS]
[PASS] MacroSettings - Excel VBA Warnings: Restricted
[PASS] MacroSettings - Word VBA Warnings: Restricted

[STRATEGY 4: USER APPLICATION HARDENING]
[PASS] Hardening - PowerShell v2: Disabled
[PASS] Hardening - Script Block Logging: Enabled

[STRATEGY 5: RESTRICT ADMINISTRATIVE PRIVILEGES]
[PASS] Privileges - UAC Status: Enabled
[PASS] Privileges - Local Administrators: 2 account(s)

[STRATEGY 6: PATCH OPERATING SYSTEMS]
[PASS] OS Patching - OS Support Status: Supported build

[STRATEGY 7: MULTI-FACTOR AUTHENTICATION]
[INFO] MFA - Assessment: Requires directory-level audit

[STRATEGY 8: REGULAR BACKUPS]
[PASS] Backups - Volume Shadow Copy: Running
[PASS] Backups - Latest Shadow Copy: 1 day ago

[AUDIT SUMMARY]
  PASS: 15
  FAIL: 0
  WARN: 1
```

## What Gets Checked

### Strategy 1: Application Control
- AppLocker policy configuration
- Windows Defender Application Control (WDAC) deployment

### Strategy 2: Patch Applications
- Windows Update service status
- Last successful patch date (flags if >30 days old)

### Strategy 3: Office Macro Settings
- Excel VBA macro restrictions
- Word VBA macro restrictions

### Strategy 4: User Application Hardening
- PowerShell v2 removal (legacy security risk)
- PowerShell version (should be 5.1+)
- PowerShell language mode (ConstrainedLanguage = restricted)
- Script block logging (audit trail for forensics)

### Strategy 5: Restrict Administrative Privileges
- Current user privilege level
- UAC (User Account Control) status
- Local administrator account count

### Strategy 6: Patch Operating Systems
- OS version and build number
- Support status (supported vs. legacy builds)

### Strategy 7: Multi-Factor Authentication
- Windows Hello credential provider
- Registered authentication methods
- **Note:** Full MFA assessment requires Azure AD / Active Directory audit

### Strategy 8: Regular Backups
- Windows Backup service status
- Volume Shadow Copy Service status
- Latest shadow copy age (flags if >7 days old)

## Use Cases

- **Pre-audit preparation:** Identify gaps before formal compliance assessments
- **Continuous monitoring:** Schedule daily audits and track compliance drift
- **Incident response:** Document Essential Eight posture after security events
- **Procurement verification:** Verify new system configurations before acceptance
- **Maturity progression:** Identify systems ready for ML2/ML3 implementation

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-OutputDir` | No | Current directory | Where to write report file |
| `-Verbose` | No | False | Enable verbose output |

## Output Files

Report filename format: `EssentialEight_Audit_YYYYMMDD_HHMMSS.txt`

Example: `EssentialEight_Audit_20260424_153045.txt`

## Maturity Levels

This script focuses on **Maturity Level 1 (ML1)** baseline checks. The ASD Essential Eight Maturity Model defines three levels:

- **ML1:** Partly aligned with intent - baseline controls exist
- **ML2:** Mostly aligned with intent - comprehensive coverage
- **ML3:** Fully aligned with intent - complete implementation with monitoring

Progression beyond ML1 requires increasingly stringent controls and centralised management (SCCM, Intune, GPO).

## Extending the Script

- **HTML reports:** Generate formatted HTML output with charts
- **Email integration:** Auto-send reports to compliance teams
- **Remote execution:** Audit multiple systems from central workstation
- **SIEM integration:** Parse output and feed to security monitoring
- **Auto-remediation:** Add a `-Remediate` switch to fix common failures

## Tutorial

Read the full tutorial on DEV Community: [Automating Essential Eight Compliance Checks with PowerShell](https://dev.to/shadowstrike/automating-essential-eight-compliance-checks-with-powershell-b9g)

## Official ASD Guidance

For detailed Essential Eight documentation:
https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight

## License

MIT License - See LICENSE file for details

## Author

Built by **ShadowStrike** (Strategos) — where we build actual security tools instead of theatre. 🎃

Part of the Strategos project for APAC forensic and security tooling.
