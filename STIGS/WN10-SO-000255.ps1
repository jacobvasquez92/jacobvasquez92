<#
.SYNOPSIS
    This PowerShell script configures Windows 10 to auomatically deny elevation requests from standard users.
    It makes sure standard users cannot elevate privileges through UAC prompts.

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-08-16
    Last Modified   : 2025-08-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000255

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Save as C:\Scripts\Remediate-WN10-SO-000255.ps1
    Run PowerShell as Administrator
    Execute one of:
        # Standard remediation + logging
        C:\Scripts\Remediate-WN10-SO-000255.ps1

        # Also refresh local policy after setting the value
        C:\Scripts\Remediate-WN10-SO-000255.ps1 -RefreshPolicy

        # Audit-only (no changes) to see current state
        C:\Scripts\Remediate-WN10-SO-000255.ps1 -AuditOnly

    Logs and the .reg backup are stored in:
        C:\STIG_Remediation\UAC\
    
  Standard users can no longer elevate by providing credentials at UAC—Windows will automatically deny such elevation attempts.
  Ensure you have at least one admin-capable account for legitimate admin tasks.

    Example syntax:
    PS C:\> .\WN10-SO-000255.ps1 
#>

<#
.SYNOPSIS
  Remediate STIG WN10-SO-000255:
  "User Account Control: Behavior of the elevation prompt for standard users" = Automatically deny (0)

.DESCRIPTION
  Sets HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser (REG_DWORD) to 0.
  Creates the key if missing, backs up existing values, logs all actions, and verifies.

.NOTES
  Run from an elevated PowerShell session (Administrator).
  This script targets the 64-bit registry view to avoid WOW64 redirection.

.PARAMETER EvidencePath
  Folder to store logs and registry backup. Default: C:\STIG_Remediation\UAC

.PARAMETER RefreshPolicy
  If supplied, runs gpupdate /target:computer /force at the end.

.PARAMETER AuditOnly
  If supplied, only reports current setting without making changes.

.EXAMPLES
  .\Remediate-WN10-SO-000255.ps1
  .\Remediate-WN10-SO-000255.ps1 -RefreshPolicy
  .\Remediate-WN10-SO-000255.ps1 -AuditOnly
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$EvidencePath = "C:\STIG_Remediation\UAC",
  [switch]$RefreshPolicy,
  [switch]$AuditOnly
)

$ErrorActionPreference = 'Stop'
$RegSubPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName  = "ConsentPromptBehaviorUser"
[int]$Desired = 0

#--- Admin check ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "This script must be run as Administrator."
  exit 1
}

#--- Logging setup ---
$null = New-Item -ItemType Directory -Path $EvidencePath -Force -ErrorAction SilentlyContinue
$LogFile = Join-Path $EvidencePath ("WN10-SO-000255_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
function Write-Log([string]$Message) {
  $line = "{0} - {1}" -f (Get-Date -Format 'u'), $Message
  Write-Output $line
  Add-Content -Path $LogFile -Value $line
}

Write-Log "Starting remediation for WN10-SO-000255."

#--- Helper: open 64-bit HKLM base key to avoid WOW64 redirection ---
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

#--- Backup existing key (if present) ---
try {
  $BackupFile = Join-Path $EvidencePath ("Policies_System_Backup_{0:yyyyMMdd_HHmmss}.reg" -f (Get-Date))
  & reg.exe export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" $BackupFile /y | Out-Null
  Write-Log "Exported backup to $BackupFile"
} catch {
  Write-Log "WARNING: Registry export failed (may be first-time config). $_"
}

#--- Read current value (if any) ---
$key = $baseKey.CreateSubKey($RegSubPath)  # creates if missing
$current = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)

if ($AuditOnly) {
  $state = if ($null -eq $current) { "<not set>" } else { $current }
  Write-Log "AUDIT-ONLY: Current $ValueName = $state (expected $Desired). No changes made."
  exit 0
}

#--- Remediate if needed ---
$needsChange = $true
if ($current -ne $null -and [int]$current -eq $Desired) { $needsChange = $false }

if (-not $needsChange) {
  Write-Log "No change required. $ValueName already set to $Desired."
} else {
  if ($PSCmdlet.ShouldProcess("HKLM:\$RegSubPath", "Set $ValueName to $Desired")) {
    try {
      $key.SetValue($ValueName, $Desired, [Microsoft.Win32.RegistryValueKind]::DWord)
      Write-Log "Set $ValueName to $Desired (REG_DWORD)."
    } catch {
      Write-Log "ERROR: Failed to set $ValueName. $_"
      exit 2
    }
  }
}

#--- Verify ---
$verify = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
if ($verify -ne $null -and [int]$verify -eq $Desired) {
  Write-Log "Verification PASSED: $ValueName = $Desired."
} else {
  Write-Log "Verification FAILED: $ValueName expected $Desired, found '$verify'."
  exit 3
}

#--- Optional policy refresh ---
if ($RefreshPolicy) {
  try {
    Write-Log "Running gpupdate /target:computer /force ..."
    & gpupdate.exe /target:computer /force | Out-Null
    Write-Log "Policy refresh completed."
  } catch {
    Write-Log "WARNING: gpupdate failed. $_"
  }
}

Write-Log "Remediation complete. Log: $LogFile"
exit 0
