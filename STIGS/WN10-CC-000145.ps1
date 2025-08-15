<#
.SYNOPSIS
    This PowerShell script addresses a security vulnerability by enforcing a password requirement when a computer wakes from sleep while running on battery power. It does this by modifying the Windows Registry.

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-08-13
    Last Modified   : 2025-08-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000145

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
⚠️ Administrative Privileges
The script modifies a HKEY_LOCAL_MACHINE registry hive, which requires administrator rights. The user must run PowerShell as an administrator for the script to execute successfully. If not, you will encounter an "Access is denied" error.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000145.ps1 
#>
# Define the registry path, value name, and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
$valueName = "DCSettingIndex"
$value = 1
$valueType = "DWord"

# Check if the registry path exists, create it if it doesn't
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Host "Registry path created: $registryPath"
}

# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type $valueType

Write-Host "Registry value '$valueName' has been set to '$value' at path '$registryPath'."
