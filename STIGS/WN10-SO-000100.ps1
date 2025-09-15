<#
.SYNOPSIS
    The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. 
    If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing.

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-09-06
    Last Modified   : 2025-09-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000100

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Check if the following registry value does not exist or is not configured as specified, this is a finding:
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
    Value Name: RequireSecuritySignatureFilterAdministratorToken
    Value Type: REG_DWORD
    Value: 1

    Example syntax:
    PS C:\> .\WN10-SO-000100.ps1 
    
#>

# This script creates or updates the RequireSecuritySignature registry value to 1.
# Ensures the registry path exists.  Confirms the change to the console.

# PowerShell Script to Enforce SMB Client Packet Signing

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$valueName = "RequireSecuritySignature"
$desiredValue = 1

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set RequireSecuritySignature to 1 (Enabled)
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $desiredValue -Force | Out-Null

Write-Output "SMB Client Signing has been configured successfully."
Write-Output "Registry Path: $regPath"
Write-Output "Value ($valueName): $desiredValue"
}
