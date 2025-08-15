<#
.SYNOPSIS
    This PowerShell script disables Windows Copilot by configuring a specific registry setting. It does this by creating a new registry key and value or modifying an existing one to conform to the required policy.

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-08-14
    Last Modified   : 2025-08-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000107

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    If the following local computer policy is not configured as specified, this is a finding:
    User Configuration >> Administrative Templates >> Windows Components >> Windows Copilot >> "Turn off Windows Copilot" to "Enabled".
    Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> Windows Copilot >> "Turn off Windows Copilot" to "Enabled".
    Example syntax:
    PS C:\> .\WN10-00-000107.ps1 
#>
# Define the registry path, value name, and value to disable Windows Copilot
$registryPath = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"
$valueName = "TurnOffWindowsCopilot"
$value = 1
$valueType = "DWord"

# Check if the registry path exists, create it if it doesn't
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Host "Registry path created: $registryPath"
}

# Set the registry value to disable Windows Copilot
Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type $valueType

Write-Host "Registry value '$valueName' has been set to '$value' at path '$registryPath' to disable Windows Copilot."
