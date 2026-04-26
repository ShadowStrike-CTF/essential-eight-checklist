# Essential Eight Compliance Checker
# Version: 1.0.0
# Purpose: Audit Windows system against ASD Essential Eight baseline controls
# Author: ShadowStrike (Strategos)
# License: MIT

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "."
)

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = Join-Path $OutputDir "EssentialEight_Audit_$timestamp.txt"

$report = @()
$report += "=" * 70
$report += "ESSENTIAL EIGHT COMPLIANCE AUDIT"
$report += "Australian Signals Directorate (ASD) Baseline Controls"
$report += "Audit Time: $(Get-Date)"
$report += "System: $env:COMPUTERNAME"
$report += "=" * 70
$report += ""

Write-Host "`n[ESSENTIAL EIGHT COMPLIANCE AUDIT]" -ForegroundColor Cyan
Write-Host "System: $env:COMPUTERNAME`n" -ForegroundColor Yellow

# Track overall results
$passCount = 0
$failCount = 0
$warnCount = 0

function Write-Check {
    param(
        [string]$Strategy,
        [string]$Check,
        [string]$Status,
        [string]$Detail = ""
    )
    
    $color = switch ($Status) {
        "PASS" { "Green"; $script:passCount++ }
        "FAIL" { "Red"; $script:failCount++ }
        "WARN" { "Yellow"; $script:warnCount++ }
        "INFO" { "Cyan" }
    }
    
    $line = "[$Status] $Strategy - $Check"
    if ($Detail) { $line += ": $Detail" }
    
    Write-Host $line -ForegroundColor $color
    $script:report += $line
}

# ============================================================================
# STRATEGY 1: APPLICATION CONTROL
# ============================================================================

$report += ""
$report += "STRATEGY 1: APPLICATION CONTROL"
$report += "-" * 70

Write-Host "`n[STRATEGY 1: APPLICATION CONTROL]" -ForegroundColor Magenta

# Check for AppLocker
try {
    $appLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    if ($appLockerPolicy.RuleCollections.Count -gt 0) {
        Write-Check "AppControl" "AppLocker Policy" "PASS" "Effective policy found with $($appLockerPolicy.RuleCollections.Count) rule collection(s)"
    } else {
        Write-Check "AppControl" "AppLocker Policy" "FAIL" "No effective rules configured"
    }
} catch {
    Write-Check "AppControl" "AppLocker Policy" "FAIL" "AppLocker not configured or inaccessible"
}

# Check for WDAC (Windows Defender Application Control)
$wdacPath = "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
if (Test-Path $wdacPath) {
    $wdacPolicies = Get-ChildItem $wdacPath -Filter "*.cip" -ErrorAction SilentlyContinue
    if ($wdacPolicies.Count -gt 0) {
        Write-Check "AppControl" "WDAC Policy" "PASS" "$($wdacPolicies.Count) active policy/policies found"
    } else {
        Write-Check "AppControl" "WDAC Policy" "WARN" "WDAC path exists but no policies found"
    }
} else {
    Write-Check "AppControl" "WDAC Policy" "INFO" "WDAC not deployed (AppLocker may be in use instead)"
}

# ============================================================================
# STRATEGY 2: PATCH APPLICATIONS
# ============================================================================

$report += ""
$report += "STRATEGY 2: PATCH APPLICATIONS"
$report += "-" * 70

Write-Host "`n[STRATEGY 2: PATCH APPLICATIONS]" -ForegroundColor Magenta

# Check Windows Update service
$wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($wuService -and $wuService.Status -eq "Running") {
    Write-Check "Patching" "Windows Update Service" "PASS" "Running"
} else {
    Write-Check "Patching" "Windows Update Service" "FAIL" "Not running or not found"
}

# Check last successful patch date
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $historyCount = $searcher.GetTotalHistoryCount()
    
    if ($historyCount -gt 0) {
        $history = $searcher.QueryHistory(0, 1) | Select-Object -First 1
        $lastUpdate = $history.Date
        $daysSince = (Get-Date) - $lastUpdate
        
        if ($daysSince.Days -le 30) {
            Write-Check "Patching" "Last Update" "PASS" "$(($lastUpdate).ToString('yyyy-MM-dd')) - $([math]::Round($daysSince.TotalDays)) days ago"
        } elseif ($daysSince.Days -le 60) {
            Write-Check "Patching" "Last Update" "WARN" "$(($lastUpdate).ToString('yyyy-MM-dd')) - $([math]::Round($daysSince.TotalDays)) days ago (outdated)"
        } else {
            Write-Check "Patching" "Last Update" "FAIL" "$(($lastUpdate).ToString('yyyy-MM-dd')) - $([math]::Round($daysSince.TotalDays)) days ago (severely outdated)"
        }
    } else {
        Write-Check "Patching" "Last Update" "FAIL" "No update history found"
    }
} catch {
    Write-Check "Patching" "Last Update" "WARN" "Could not retrieve update history"
}

# ============================================================================
# STRATEGY 3: CONFIGURE MICROSOFT OFFICE MACRO SETTINGS
# ============================================================================

$report += ""
$report += "STRATEGY 3: OFFICE MACRO SETTINGS"
$report += "-" * 70

Write-Host "`n[STRATEGY 3: OFFICE MACRO SETTINGS]" -ForegroundColor Magenta

# Check Office macro registry settings (common Office versions)
$officeVersions = @("16.0", "15.0", "14.0")  # Office 2016/2019/365, 2013, 2010
$macroCheckDone = $false

foreach ($version in $officeVersions) {
    $excelPath = "HKCU:\Software\Microsoft\Office\$version\Excel\Security"
    $wordPath = "HKCU:\Software\Microsoft\Office\$version\Word\Security"
    
    if (Test-Path $excelPath) {
        $vbaWarnings = (Get-ItemProperty -Path $excelPath -Name VBAWarnings -ErrorAction SilentlyContinue).VBAWarnings
        if ($vbaWarnings -eq 3 -or $vbaWarnings -eq 4) {
            Write-Check "MacroSettings" "Excel VBA Warnings" "PASS" "Macros disabled or notification enabled (Value: $vbaWarnings)"
        } elseif ($vbaWarnings -eq 1) {
            Write-Check "MacroSettings" "Excel VBA Warnings" "FAIL" "All macros enabled without notification"
        } else {
            Write-Check "MacroSettings" "Excel VBA Warnings" "WARN" "Non-standard setting detected (Value: $vbaWarnings)"
        }
        $macroCheckDone = $true
    }
    
    if (Test-Path $wordPath) {
        $vbaWarnings = (Get-ItemProperty -Path $wordPath -Name VBAWarnings -ErrorAction SilentlyContinue).VBAWarnings
        if ($vbaWarnings -eq 3 -or $vbaWarnings -eq 4) {
            Write-Check "MacroSettings" "Word VBA Warnings" "PASS" "Macros disabled or notification enabled (Value: $vbaWarnings)"
        } elseif ($vbaWarnings -eq 1) {
            Write-Check "MacroSettings" "Word VBA Warnings" "FAIL" "All macros enabled without notification"
        } else {
            Write-Check "MacroSettings" "Word VBA Warnings" "WARN" "Non-standard setting detected (Value: $vbaWarnings)"
        }
        $macroCheckDone = $true
    }
}

if (-not $macroCheckDone) {
    Write-Check "MacroSettings" "Office Installation" "INFO" "Microsoft Office not detected or registry settings not accessible"
}

# ============================================================================
# STRATEGY 4: USER APPLICATION HARDENING
# ============================================================================

$report += ""
$report += "STRATEGY 4: USER APPLICATION HARDENING"
$report += "-" * 70

Write-Host "`n[STRATEGY 4: USER APPLICATION HARDENING]" -ForegroundColor Magenta

# Check PowerShell v2 status
$psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
if ($psv2) {
    if ($psv2.State -eq "Disabled") {
        Write-Check "Hardening" "PowerShell v2" "PASS" "Disabled"
    } else {
        Write-Check "Hardening" "PowerShell v2" "FAIL" "Enabled (legacy version should be removed)"
    }
} else {
    Write-Check "Hardening" "PowerShell v2" "WARN" "Could not determine status"
}

# Check current PowerShell version
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -ge 5) {
    Write-Check "Hardening" "PowerShell Version" "PASS" "v$($psVersion.Major).$($psVersion.Minor)"
} else {
    Write-Check "Hardening" "PowerShell Version" "FAIL" "v$($psVersion.Major).$($psVersion.Minor) (should be 5.1 or later)"
}

# Check PowerShell language mode
$langMode = $ExecutionContext.SessionState.LanguageMode
if ($langMode -eq "ConstrainedLanguage") {
    Write-Check "Hardening" "PowerShell Language Mode" "PASS" "ConstrainedLanguage (restricted)"
} elseif ($langMode -eq "FullLanguage") {
    Write-Check "Hardening" "PowerShell Language Mode" "WARN" "FullLanguage (unrestricted - acceptable for admin workstations)"
} else {
    Write-Check "Hardening" "PowerShell Language Mode" "INFO" "$langMode"
}

# Check script block logging
$scriptBlockPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (Test-Path $scriptBlockPath) {
    $scriptBlockEnabled = (Get-ItemProperty -Path $scriptBlockPath -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($scriptBlockEnabled -eq 1) {
        Write-Check "Hardening" "Script Block Logging" "PASS" "Enabled"
    } else {
        Write-Check "Hardening" "Script Block Logging" "FAIL" "Disabled"
    }
} else {
    Write-Check "Hardening" "Script Block Logging" "FAIL" "Not configured"
}

# ============================================================================
# STRATEGY 5: RESTRICT ADMINISTRATIVE PRIVILEGES
# ============================================================================

$report += ""
$report += "STRATEGY 5: RESTRICT ADMINISTRATIVE PRIVILEGES"
$report += "-" * 70

Write-Host "`n[STRATEGY 5: RESTRICT ADMINISTRATIVE PRIVILEGES]" -ForegroundColor Magenta

# Check if current user is admin
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Check "Privileges" "Current User Role" "WARN" "Running as Administrator (acceptable for admin tasks, not for daily use)"
} else {
    Write-Check "Privileges" "Current User Role" "PASS" "Running as standard user"
}

# Check UAC status
$uacPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$uacEnabled = (Get-ItemProperty -Path $uacPath -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
if ($uacEnabled -eq 1) {
    Write-Check "Privileges" "UAC Status" "PASS" "Enabled"
} else {
    Write-Check "Privileges" "UAC Status" "FAIL" "Disabled (should be enabled)"
}

# Check local admin count
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
if ($admins) {
    if ($admins.Count -le 3) {
        Write-Check "Privileges" "Local Administrators" "PASS" "$($admins.Count) account(s) - acceptable range"
    } else {
        Write-Check "Privileges" "Local Administrators" "WARN" "$($admins.Count) account(s) - consider reducing"
    }
} else {
    Write-Check "Privileges" "Local Administrators" "WARN" "Could not enumerate group members"
}

# ============================================================================
# STRATEGY 6: PATCH OPERATING SYSTEMS
# ============================================================================

$report += ""
$report += "STRATEGY 6: PATCH OPERATING SYSTEMS"
$report += "-" * 70

Write-Host "`n[STRATEGY 6: PATCH OPERATING SYSTEMS]" -ForegroundColor Magenta

# Check OS version and build
$os = Get-CimInstance Win32_OperatingSystem
$osVersion = $os.Version
$osBuild = $os.BuildNumber
$osName = $os.Caption

Write-Check "OS Patching" "Operating System" "INFO" "$osName (Build $osBuild)"

# Check if OS is supported (simplified check - Windows 10/11 build numbers)
if ([int]$osBuild -ge 22000) {
    Write-Check "OS Patching" "OS Support Status" "PASS" "Windows 11 (supported)"
} elseif ([int]$osBuild -ge 19041) {
    Write-Check "OS Patching" "OS Support Status" "PASS" "Windows 10 version 2004+ (supported)"
} elseif ([int]$osBuild -ge 18362) {
    Write-Check "OS Patching" "OS Support Status" "WARN" "Windows 10 version 1903 (support status depends on edition)"
} else {
    Write-Check "OS Patching" "OS Support Status" "FAIL" "Legacy Windows version (likely unsupported)"
}

# ============================================================================
# STRATEGY 7: MULTI-FACTOR AUTHENTICATION
# ============================================================================

$report += ""
$report += "STRATEGY 7: MULTI-FACTOR AUTHENTICATION"
$report += "-" * 70

Write-Host "`n[STRATEGY 7: MULTI-FACTOR AUTHENTICATION]" -ForegroundColor Magenta

# Check for Windows Hello
$helloPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider"
if (Test-Path $helloPath) {
    Write-Check "MFA" "Windows Hello" "INFO" "Credential provider detected (may indicate biometric MFA)"
} else {
    Write-Check "MFA" "Windows Hello" "INFO" "Not detected"
}

# Check for registered security devices (FIDO2, smart cards)
$credProviders = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" -ErrorAction SilentlyContinue
if ($credProviders.Count -gt 1) {
    Write-Check "MFA" "Credential Providers" "INFO" "$($credProviders.Count) provider(s) registered (standard password + potentially MFA)"
} else {
    Write-Check "MFA" "Credential Providers" "INFO" "Standard credential provider only"
}

Write-Check "MFA" "Note" "INFO" "Full MFA assessment requires Azure AD / Active Directory audit"

# ============================================================================
# STRATEGY 8: REGULAR BACKUPS
# ============================================================================

$report += ""
$report += "STRATEGY 8: REGULAR BACKUPS"
$report += "-" * 70

Write-Host "`n[STRATEGY 8: REGULAR BACKUPS]" -ForegroundColor Magenta

# Check Windows Backup status
$backupService = Get-Service -Name SDRSVC -ErrorAction SilentlyContinue
if ($backupService -and $backupService.Status -eq "Running") {
    Write-Check "Backups" "Windows Backup Service" "PASS" "Running"
} else {
    Write-Check "Backups" "Windows Backup Service" "INFO" "Not active (may use third-party backup)"
}

# Check Volume Shadow Copy Service
$vssService = Get-Service -Name VSS -ErrorAction SilentlyContinue
if ($vssService -and $vssService.Status -eq "Running") {
    Write-Check "Backups" "Volume Shadow Copy" "PASS" "Running"
} else {
    Write-Check "Backups" "Volume Shadow Copy" "WARN" "Not running (required for system restore)"
}

# Check for shadow copies on C: drive
$shadows = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.VolumeName -like "*C:*" }
if ($shadows) {
    $latestShadow = $shadows | Sort-Object InstallDate -Descending | Select-Object -First 1
    $daysSince = (Get-Date) - $latestShadow.InstallDate
    
    if ($daysSince.Days -le 7) {
        Write-Check "Backups" "Latest Shadow Copy" "PASS" "$(($latestShadow.InstallDate).ToString('yyyy-MM-dd')) - $([math]::Round($daysSince.TotalDays)) days ago"
    } else {
        Write-Check "Backups" "Latest Shadow Copy" "WARN" "$(($latestShadow.InstallDate).ToString('yyyy-MM-dd')) - $([math]::Round($daysSince.TotalDays)) days ago (outdated)"
    }
} else {
    Write-Check "Backups" "Shadow Copies" "FAIL" "No shadow copies found on C: drive"
}

# ============================================================================
# SUMMARY
# ============================================================================

$report += ""
$report += "=" * 70
$report += "AUDIT SUMMARY"
$report += "=" * 70
$report += "PASS: $passCount"
$report += "FAIL: $failCount"
$report += "WARN: $warnCount"
$report += ""
$report += "Report saved to: $outputFile"
$report += "=" * 70

Write-Host "`n[AUDIT SUMMARY]" -ForegroundColor Cyan
Write-Host "  PASS: $passCount" -ForegroundColor Green
Write-Host "  FAIL: $failCount" -ForegroundColor Red
Write-Host "  WARN: $warnCount" -ForegroundColor Yellow
Write-Host "`n[COMPLETE] Report written to: $outputFile" -ForegroundColor Green

# Write report to file
$report | Out-File -FilePath $outputFile -Encoding UTF8

Write-Host "`nFor detailed Essential Eight guidance, visit:" -ForegroundColor Cyan
Write-Host "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight`n" -ForegroundColor Yellow
