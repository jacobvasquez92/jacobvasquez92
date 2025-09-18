<#
.SYNOPSIS
    Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. 
    By default Windows uses ECC curves with shorter key lengths first. Requiring ECC curves with longer key lengths
    to be prioritized first helps ensure more secure algorithms are used.

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-09-17
    Last Modified   : 2025-09-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000052

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Check if the following registry value does not exist or is not configured as specified, this is a finding:
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\
    Value Name: EccCurves
    Value Type: REG_MULTI_SZ
    Value: NistP384 NistP256

    Example syntax:
    PS C:\> .\WN10-CC-000052.ps1 
#>

# This script Ensures the required registry path exists.
# Creates/updates the EccCurves multi-string value with NistP384 first, then NistP256. Outputs confirmation once complete.

# PowerShell Script to Configure ECC Curve Order Fix

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$valueName = "EccCurves"
$desiredOrder = @("NistP384", "NistP256")

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the ECC Curve Order
Set-ItemProperty -Path $regPath -Name $valueName -Value $desiredOrder -Type MultiString

Write-Output "ECC Curve Order has been configured successfully."
Write-Output "Registry Path: $regPath"
Write-Output "Value ($valueName): $($desiredOrder -join ', ')"

