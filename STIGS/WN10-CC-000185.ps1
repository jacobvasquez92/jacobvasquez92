<#
.SYNOPSIS
    This PowerShell script disables the autorun feature, is a key security control to prevent malicious code from executing automatically when removable media is inserted.

.NOTES
    Author          : Jacob Vasquez
    LinkedIn        : linkedin.com/in/jacob-vasquez-b46056257/
    GitHub          : github.com/jacobvasquez92
    Date Created    : 2025-08-07
    Last Modified   : 2025-08-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : STIG-ID-WN10-CC-000185

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    .NOTES
    - Requires administrative privileges to run.
    - The registry path is HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
    - The value is set to 1 to disable autorun.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000185.ps1
     
#>
# Check for administrative privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as an Administrator. Please right-click and 'Run as administrator'."
    exit
}

try {
    # Check if the registry path exists, create it if it doesn't
    if (-not (Test-Path $regPath)) {
        Write-Host "Registry path '$regPath' does not exist. Creating it now..." -ForegroundColor Yellow
        New-Item -Path $regPath -Force | Out-Null
    }

    # Get the current registry value
    $currentValue = Get-ItemProperty -Path $regPath -Name $regPropertyName -ErrorAction SilentlyContinue

    Write-Host "Current '$regPropertyName' value is: $($currentValue.$regPropertyName)"

    # Check if the value is configured correctly
    if ($currentValue.$regPropertyName -ne $requiredValue) {
        Write-Host "Autorun is not disabled. Remediating..." -ForegroundColor Yellow

        # Set the registry value to disable autorun
        Set-ItemProperty -Path $regPath -Name $regPropertyName -Value $requiredValue -Type DWORD -Force

        Write-Host "Successfully set '$regPropertyName' to '$requiredValue' (disabled)." -ForegroundColor Green

        # Verify the change
        $newValue = Get-ItemProperty -Path $regPath -Name $regPropertyName
        Write-Host "New '$regPropertyName' value is: $($newValue.$regPropertyName)" -ForegroundColor Green
    }
    else {
        Write-Host "The autorun behavior is already configured correctly. No changes needed." -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred while trying to set the autorun policy: $_"
}
