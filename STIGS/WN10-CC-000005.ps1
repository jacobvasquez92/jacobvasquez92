<#
.SYNOPSIS
   This Powershell script disables access to the camera from the lock screen.
.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-08-14
    Last Modified   : 2025-08-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    If the device does not have a camera, this is NA.
    If the following registry value does not exist or is not configured as specified, this is a finding.
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\
    Value Name: NoLockScreenCamera
    Value Type: REG_DWORD
    Value: 1
    Example syntax:
    PS C:\> .\WN10-CC-000005.ps1 
#>
# Define the registry path, value name, and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
$valueName = "NoLockScreenCamera"
$value = 1
$valueType = "DWord"

# Check if the registry path exists, create it if it doesn't
if (-not (Test-Path $registryPath)) {
    try {
        New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Registry path created successfully: $registryPath"
    } catch {
        Write-Error "Failed to create registry path: $registryPath. Error: $_"
        exit
    }
}

# Set the registry value
try {
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type $valueType -ErrorAction Stop
    Write-Host "Registry value '$valueName' has been set to '$value' at path '$registryPath'."
} catch {
    Write-Error "Failed to set registry value '$valueName'. Error: $_"
}
