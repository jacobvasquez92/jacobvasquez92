<#
.SYNOPSIS
    This PowerShell script will apply the fix by setting the FilterAdministratorToken registry value to 1. This enables Admin Approval Mode for the built-in Administrator account as per the security policy.

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-08-19
    Last Modified   : 2025-08-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000245

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Check if the following registry value does not exist or is not configured as specified, this is a finding:
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
    Value Name: FilterAdministratorToken
    Value Type: REG_DWORD
    Value: 1

    Example syntax:
    PS C:\> .\WN10-SO-000245.ps1 
#>

# This script sets the registry value to enable Admin Approval Mode for the
# built-in Administrator account, as specified in the security policy.

# Define the registry path and value details.
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
$valueName = "FilterAdministratorToken"
$valueData = 1

# Check if the registry path exists. If not, create it.
if (-not (Test-Path $registryPath)) {
    # If the path doesn't exist, create it.
    New-Item -Path $registryPath -Force | Out-Null
    Write-Host "Registry path '$registryPath' was created."
}

# Set the registry value to enable the UAC policy.
try {
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWORD -Force
    Write-Host "Successfully configured 'FilterAdministratorToken' to $valueData."
}
catch {
    Write-Error "Failed to set the registry value. Please ensure you are running PowerShell with administrative privileges."
    Write-Error $_.Exception.Message
}
