<#
.SYNOPSIS
    This PowerShell script clears “Password never expires” on all enabled local accounts 
    (the exact fix text says to ensure “Password never expires” is not checked for each active account).
    Built-in accounts (Administrator, Guest) are excluded.

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-08-15
    Last Modified   : 2025-08-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000090

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    -During a STIG compliance audit where you find local accounts flagged with “Password never expires”.
    -As part of a remediation step in a security hardening project (DISA STIG, CIS Benchmarks, NIST 800-53 alignment, etc.).
    -In a SOC / compliance environment where you need to prove that accounts are configured securely.
    -When managing multiple systems and you want an automated way to fix accounts without manually opening Computer Management → Local Users and Groups → Users.
    PS C:\> .\WN10-00-000090.ps1 
#>

<#
.SYNOPSIS
  Remediates STIG compliance check for "Password Never Expires" on local accounts.

.DESCRIPTION
  Ensures that all active (enabled) local user accounts do not have the 
  "Password never expires" setting enabled. Built-in accounts (Administrator, Guest) are excluded.

.NOTES
  STIG Reference: Windows 10 STIG - WN10-AC-000030
#>

# Define log file
$LogFile = "C:\STIG_Remediation\PasswordExpiryFix.log"
if (!(Test-Path "C:\STIG_Remediation")) {
    New-Item -ItemType Directory -Force -Path "C:\STIG_Remediation" | Out-Null
}

# Connect to local computer's Users container
$Computer = [ADSI]"WinNT://$env:COMPUTERNAME"

# Get all local user accounts
$Users = $Computer.Children | Where-Object { $_.SchemaClassName -eq "User" }

foreach ($User in $Users) {
    $UserName = $User.Name

    # Skip built-in accounts
    if ($UserName -in @("Administrator", "Guest")) {
        continue
    }

    # Check if account is enabled
    $UserFlags = $User.UserFlags.Value
    $Disabled = $UserFlags -band 2
    $PasswordNeverExpires = $UserFlags -band 0x10000  # UF_DONT_EXPIRE_PASSWD

    if ($Disabled -eq 0 -and $PasswordNeverExpires -ne 0) {
        try {
            # Remove the "Password Never Expires" flag
            $User.UserFlags = $UserFlags -bxor 0x10000
            $User.SetInfo()

            $Message = "$(Get-Date -Format 'u') - Fixed: Password expiration enabled for account [$UserName]"
            Write-Output $Message
            Add-Content -Path $LogFile -Value $Message
        }
        catch {
            $ErrorMsg = "$(Get-Date -Format 'u') - ERROR: Could not update account [$UserName]. Error: $_"
            Write-Output $ErrorMsg
            Add-Content -Path $LogFile -Value $ErrorMsg
        }
    }
    else {
        $Message = "$(Get-Date -Format 'u') - No change needed: Account [$UserName] already compliant or disabled."
        Write-Output $Message
        Add-Content -Path $LogFile -Value $Message
    }
}

