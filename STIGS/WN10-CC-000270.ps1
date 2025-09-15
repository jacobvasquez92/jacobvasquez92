<#
.SYNOPSIS
    Sets DisablePasswordSaving to 1 (Enabled), which enforces the GPO setting “Do not allow passwords to be saved.”  Creates the required registry path if missing.  
.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-09-05
    Last Modified   : 2025-09-05
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000270

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    The system must be configured to prevent users from saving passwords in the Remote Desktop Client.  Check if the following registry value does not exist or is not configured as specified, this is a finding:
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
    Value Name: DisablePasswordSaving
    Value Type: REG_DWORD
    Value: 1

    Example syntax:
    PS C:\> .\WN10-CC-000270.ps1 

Creates the required registry path if missing.
Sets DisablePasswordSaving to 1 (Enabled), which enforces the GPO setting “Do not allow passwords to be saved.”
Prints confirmation to the console
#>
# PowerShell Script to Prevent Saving Passwords in RDP Client

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "DisablePasswordSaving"
$desiredValue = 1

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set DisablePasswordSaving to 1 (Enabled)
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $desiredValue -Force | Out-Null

Write-Output "RDP Client password saving has been disabled successfully."
Write-Output "Registry Path: $regPath"
Write-Output "Value ($valueName): $desiredValue"

}
