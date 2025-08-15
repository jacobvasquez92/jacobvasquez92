<#
.SYNOPSIS
    Data Execution Prevention (DEP) must be configured to at least OptOut. This PowerShell script changes the value for "nx" to OptOut.

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-08-14
    Last Modified   : 2025-08-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000145

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Verify the DEP configuration.
    Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
    Enter "BCDEdit /enum {current}". (If using PowerShell "{current}" must be enclosed in quotes.)
    If the value for "nx" is not "OptOut", this is a finding.
    (The more restrictive configuration of "AlwaysOn" would not be a finding.) any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID- WN10-00-000145.ps1 
#>

# This script remediates STIG WN10-00-000145 by enabling the policy
BCDEDIT /set "{current}" nx OptOut
