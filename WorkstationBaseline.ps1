#Set TLS and Windows System for download software from chocolatey 
Set-ExecutionPolicy Bypass -Scope Process -Force; 
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

#download and install chocolatey software
choco feature enable -n allowGlobalConfirmation --yes=true
choco install vlc
choco install 7zip
choco install Firefox --params "/l:pl-PL"
choco install veracrypt
#choco install forticlientvpn
choco install adobereader
msiexec  /i "D:\ezd.AddIn.3.102.2.2.msi" /qn

########################
#download and install .NET Framework 4.8
Enable-WindowsOptionalFeature -Online -FeatureName NetFx4Extended-ASPNET45

#Block OneDrive
#Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\OneDrive -Name DisableLibrariesDefaultSaveToOneDrive -Value 0 -Force
#Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Value 0 -Force
#Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\OneDrive -Name DisableFileSync -Value 0 -Force
#New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\OneDrive -Name DisableMeteredNetworkFileSync -Value 0 -Force
#Set-ItemProperty -Path HKLM:\Software\Microsoft\OneDrive -Name PreventNetworkTrafficPreUserSignIn -Value 1 -Force

