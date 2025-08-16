<#
.SYNOPSIS
    This PowerShell script creates the missing registry path and sets the policy so administrator accounts are not enumerated on elevation (i.e., users must type a username and password).

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-08-15
    Last Modified   : 2025-08-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000200

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    The script ensures compliance with the STIG requirement:
        -STIG Rule: "Enumerate administrator accounts on elevation" must be disabled.
        -Registry Key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI
        -Value Name: EnumerateAdministrators
        -Value Type: REG_DWORD
        -Required Value: 0 (disabled)
    STIG compliance scans flagging this setting as non-compliant.
    Hardening builds of Windows 10/11 images before deployment.
    Remediation during a DISA, NIST 800-53, or CIS benchmark compliance project.
    Auditing — you can provide the log file as evidence that remediation was applied.
    Example syntax:
    PS C:\> .\WN10-CC-000200.ps1 
#>
<#
.SYNOPSIS
  Remediates STIG: Disable enumeration of administrator accounts on elevation.

.DESCRIPTION
  Sets HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators = 0 (REG_DWORD).
  Creates the \Policies\CredUI key if it does not exist.
  Logs actions for audit evidence.

.REQUIREMENTS
  Run from an elevated PowerShell session (as Administrator).

.NOTES
  STIG: "Enumerate administrator accounts on elevation" must be Disabled.
#>

# --- Config ---
$RegPath   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$ValueName = "EnumerateAdministrators"
$Desired   = 0
$LogDir    = "C:\STIG_Remediation"
$LogFile   = Join-Path $LogDir "Disable-AdminEnumOnElevation.log"

# --- Prep logging ---
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
function Write-Log($msg) {
    $line = "{0} - {1}" -f (Get-Date -Format "u"), $msg
    Write-Output $line
    Add-Content -Path $LogFile -Value $line
}

# --- Admin check ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Log "Starting remediation: Disable enumeration of admin accounts on elevation."

# --- Backup current key (if exists) for rollback evidence ---
try {
    $BackupFile = Join-Path $LogDir ("CredUI_Backup_{0:yyyyMMdd_HHmmss}.reg" -f (Get-Date))
    if (Test-Path $RegPath) {
        & reg.exe export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" $BackupFile /y | Out-Null
        Write-Log "Backed up existing CredUI key to $BackupFile"
    } else {
        Write-Log "CredUI key not present; no backup needed."
    }
} catch {
    Write-Log "WARNING: Failed to export backup. Error: $_"
}

# --- Ensure registry path exists ---
try {
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Log "Created missing registry path: $RegPath"
    }
} catch {
    Write-Log "ERROR: Could not create registry path $RegPath. Error: $_"
    exit 2
}

# --- Set value to 0 (Disabled) ---
try {
    New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $Desired -Force | Out-Null
    Write-Log "Set $RegPath\$ValueName to $Desired (REG_DWORD)."
} catch {
    Write-Log "ERROR: Failed to set $ValueName. Error: $_"
    exit 3
}

# --- Verify ---
try {
    $current = (Get-ItemProperty -Path $RegPath -Name $ValueName).$ValueName
    if ($current -eq $Desired) {
        Write-Log "Verification PASSED: $ValueName equals $Desired."
        Write-Log "Remediation complete."
        Write-Log "NOTE: A sign-out or policy refresh may be required for UI prompts to reflect this change."
        # Optional: refresh policy (uncomment if you want to force it)
        # & gpupdate.exe /target:computer /force | Out-Null
    } else {
        Write-Log "Verification FAILED: Expected $Desired, found $current."
        exit 4
    }
} catch {
    Write-Log "ERROR: Verification step failed. Error: $_"
    exit 5
}
