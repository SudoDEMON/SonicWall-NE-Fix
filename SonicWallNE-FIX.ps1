#Command to automate most of the items in https://www.sonicwall.com/support/knowledge-base/netextender-error-damaged-version-of-netextender-was-detected-on-your-computer/170707194358278/

#Check for Administrator privileges and if not, open powershell as admin and rerun the script
Write-Host "Checking for elevated privileges" 
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

# Set the working location to the same location as the script
Write-Host "Setting Working Directory to Script Root"
Set-Location $PSScriptRoot

#   Install 7zip module
Write-Host "Installing 7Zip Module for PowerShell"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name 'PSGallery' -SourceLocation "https://www.powershellgallery.com/api/v2" -InstallationPolicy Trusted
Install-Module -Name 7Zip4PowerShell -Force

#download cleaner tool from http://software.sonicwall.com/Netextender/Netextender%20Cleaner%20Tool.zip
Write-Host "Downloading SonicWall NetExtender Cleaner Tool"
$url = "http://software.sonicwall.com/Netextender/Netextender%20Cleaner%20Tool.zip"
$output = "$PSScriptRoot\cleaner.zip"
Invoke-WebRequest -Uri $url -OutFile $output

#download installation file from https://software.sonicwall.com/NetExtender/NetExtender-x64-10.2.322.MSI
#this may not be the most up to date file. Please check https://www.sonicwall.com/products/remote-access/vpn-clients/ for up to date install link
Write-Host "Downloading SonicWall NetExtender Installation"
$url = "https://software.sonicwall.com/NetExtender/NetExtender-x64-10.2.322.MSI"
$output = "$PSScriptRoot\NetExtender.msi"
Invoke-WebRequest -Uri $url -OutFile $output

#Extract files from cleaner.zip
Write-Host "Extracting files from cleaner.zip"
Expand-Archive -Path "$PSScriptRoot\cleaner.zip" -DestinationPath "$PSScriptRoot" -Force
Write-Host "Extracting files from NxCleaner.7z"
Expand-7zip -ArchiveFileName "$PSScriptRoot\NxCleaner.7z" -TargetPath "$PSScriptRoot"

# Uninstall SonicWall
Write-Host "Uninstalling SonicWall NetExtender"
Uninstall-Package -Name "SonicWall NetExtender" -Force -ForceBootStrap

# Disable Core Isolation
Write-Host "Disabling Core Isolation"
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0

# Run NetExtender Cleaner Tool
Write-Host "Running SonicWall Cleaner"
Start-Process -FilePath "NxCleaner.exe" -Verb RunAs

# Remove NetExtender VPN Folder
Write-Host "Removing SonicWall folder"
Remove-Item -Recurse -Force "C:\Program Files (x86)\SonicWall"

# Remove Registry Entries
Write-Host "Removing Registry Entries"
Remove-Item -Path "Registry::HKEY_CURRENT_USER\Software\SonicWall\" -Recurse
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\Software\SonicWall\" -Recurse
Remove-Item -Path "Registry::HKEY_USERS\.DEFAULT\SonicWall\" -Recurse
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\SonicWall\" -Recurse

# Change NoInteractiveServices from 1 to 0
Write-Host "Changing Registry to allow Interactive Services"
Set-ItemProperty -Path "Registry::HKEY_Local_Machine\System\CurrentControlSet\Control\Windows" -Name "NoInteractiveServices" -Value 0

# Commented out since we're installing manually
# Reinstall SonicWall NetExtender
#Write-Host "Installing SonicWall NetExtender"
#Start-Process ./NetExtender.msi -Wait

#Clean up files
Remove-Item -Force "$PSScriptRoot\cleaner.zip"
Remove-Item -Force "$PSScriptRoot\NxCleaner.7z"
Remove-Item -Force "$PSScriptRoot\NxCleaner.exe"

#Commenting out removing NetExtender.MSI since we're installing manually
#Remove-Item -Force "$PSScriptRoot\NetExtender.msi"

Read-Host -Prompt "Please Reboot your system. Press Enter to exit"
