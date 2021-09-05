#Checking if powershell is running as administrator
if ($false -eq ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')) {Write-Warning "Need to run as Administrator";break}

#Setting up powershell profile
Set-ExecutionPolicy -ExecutionPolicy Bypass
if ($false -eq (Test-Path C:\PSscript\)) {New-Item -Path 'C:\PSscript' -ItemType Directory}
if ($false -eq (Test-Path C:\PSscript\PsScripts.ps1)) {Move-Item PsScripts.ps1 C:\PSscript\PsScripts.ps1}
if ($false -eq (Test-Path C:\PSscript\cybercitywp.jpg)) {Move-Item .\cybercitywp.jpg -Destination C:\PSscript\}
$psprofile = ($PROFILE -split "\\")[-1]
$profilepath = $PROFILE.Trim($psprofile)
if ($false -eq (Test-Path $PROFILE)) {New-Item -Path $profilepath -Name $psprofile -ItemType File}
Get-Content .\PsProfile.ps1 > $PROFILE

#Installing posh-git and oh-my-posh
Install-Module posh-git -Scope CurrentUser
Install-Module oh-my-posh -Scope CurrentUser
Install-Module -Name PSReadLine -AllowPrerelease -Scope CurrentUser -Force -SkipPublisherCheck

#Downloading and installing Hack font for posh-git and oh-my-posh
Invoke-WebRequest https://github.com/ryanoasis/nerd-fonts/releases/download/v2.1.0/Hack.zip -OutFile .\Hack.zip -UseBasicParsing
Expand-Archive .\Hack.zip
cd .\CascadiaCode
Move-Item .\* C:\Windows\Fonts\
Set-ItemProperty registry::HKEY_CURRENT_USER\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe\ -name FaceName -Value "Hack NF"
Set-ItemProperty registry::HKEY_CURRENT_USER\Console\%SystemRoot%_SysWOW64_WindowsPowerShell_v1.0_powershell.exe\ -Name FaceName -Value "Hack NF"

#Cleaning up
Remove-Item .\Hack.zip
Remove-Item .\Hack
