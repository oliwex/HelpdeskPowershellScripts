###################################
##                              ###
##            secedit           ###
##                              ###
###################################
#region global

$folderName="test"
$path=$env:HOMEDRIVE+"\"+$folderName




#endregion global

#region filenames
#TODO create list


$seceditFile="secedit.cfg"
#endregion filenames

#region paths
#TODO create list

$seceditPath=$path+"\"+$seceditFile
#endregion paths


#region dictionary

$test1=@{
    "EnableAdminAccount" = "EnableAdminAccount";
    "EnableGuestAccount" = "EnableAdminAccount";

    "NewAdministratorName"="AdministratorName";
    "NewGuestName"="GuestName";
    "SeTakeOwnershipPrivilege"="Take ownership of files or other objects";
    "SeRemoteInteractiveLogonRight"="Allow log on through Remote Desktop Services";}

$policyList=[ordered]@{}


#endregion dictionary

#region functions
function Get-SeceditContent([string]$path)
{
    if (!(Test-Path $path))
    {
        New-Item -Path $path 
    }

    secedit /export /cfg $seceditPath
    $seceditContent=Get-Content -Path $seceditPath
    return $seceditContent
}

function Add-ElementToPolicyList($rawElement)
{
    $richElement=($rawElement).ToString().Replace(' ','').Split("=")
    $policyList.Add($richElement[0],$richElement[1])
}


#endregion functions


#code
Clear-Host

$seceditContent= Get-SeceditContent($path)

#region rozdzial1

Add-ElementToPolicyList($seceditContent | Select-String -Pattern EnableAdminAccount)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern EnableGuestAccount)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern NewAdministratorName)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern NewGuestName)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern SeTakeOwnershipPrivilege)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern SeRemoteInteractiveLogonRight)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern DontDisplayLastUserName)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern LegalNoticeCaption)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern LegalNoticeText)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern ConsentPromptBehaviorAdmin)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern ConsentPromptBehaviorUser)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern ClearPageFileAtShutdown)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern ForceUnlockLogon)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern CachedLogonsCount)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern PasswordExpiryWarning)

#grupy wbudowane#

<#
"Członkowie grupy Użytkownicy pulpitu zdalnego"
(Get-LocalGroupMember "Użytkownicy pulpitu zdalnego").Name
"Członkowie grupy Administratorzy: "
(Get-LocalGroupMember "Administratorzy").Name
#>

$policyList | Format-Table -AutoSize

#endregion rozdzial1


#region rozdzial2

#region firewall
$FirewallStatus = 0
$SysFirewallReg1 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
If ($SysFirewallReg1 -eq 1) {
$FirewallStatus = 1
}

$SysFirewallReg2 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
If ($SysFirewallReg2 -eq 1) {
$FirewallStatus = ($FirewallStatus + 1)
}

$SysFirewallReg3 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
If ($SysFirewallReg3 -eq 1) {
$FirewallStatus = ($FirewallStatus + 1)
}

If ($FirewallStatus -eq 3) {Write-Host "Compliant"}
ELSE {Write-Host "Non-Compliant"}


#lub
Get-NetFirewallProfile -PolicyStore ActiveStore | Select Enabled,LogFileName,LogMaxSizeKilobytes | fl *

#ipsec

Show-NetIPsecRule -PolicyStore ActiveStore | Select @{label="LocalAddress";expression={$_.LocalAddress}},@{label="RemoteAddress";expression={$_.RemoteAddress}},@{label="Auth1Level";expression={($_ | Get-NetIPsecPhase1AuthSet).Name}},@{label="Auth2Level";expression={($_ | Get-NetIPsecPhase2AuthSet).Name}}



#endregion firewall

#region podgladzdarzen

Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application | fl AutoBackupLogFiles,MaxSize,Retention
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup | fl AutoBackupLogFiles,MaxSize,Retention
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System | fl AutoBackupLogFiles,MaxSize,Retention
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security | fl AutoBackupLogFiles,MaxSize,Retention

#lub

Get-WinEvent -ListLog Security | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security | Select -ExpandProperty Retention}}
Get-WinEvent -ListLog Application | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application | Select -ExpandProperty Retention}}
Get-WinEvent -ListLog System | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System | Select -ExpandProperty Retention}}

#endregion podgladzdarzen

#region WindowsUpdate
Get-ItemProperty -PAth HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU | fl NoAutoUpdate,AuOptions,ScheduledInstallDay,ScheduledInstallTime #to wszystko w tej polityce

Get-ItemProperty -PAth HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU |fl UseWuServer #włączenie polityki
Get-ItemProperty -PAth HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate | fl WuServer,WUStatusServer,UpdateServiceUrlAlternate #servery alternatywne

Get-ItemProperty -PAth HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU
#endregion WindowsUpdate

#region Bitlocker
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE | fl ActiveDirectoryBackup
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE | fl DefaultRecoveryFolderPath
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE | fl EncryptionMethodNoDiffuser
#fixed disk
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE | fl DenyWriteAccess
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE | fl FDVPassphrase,FDVPassphraseComplexity,FDVPassphraseLength

#operating system disk
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE | fl UseAdvancedStartup,EnableBDEWithNoTP,UseTPM,UseTPMPIN,UseTPMKey,UseTPMKeyPIN
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE | fl OSEncryptionType

#endregion Bitlocker

#region DHCP i ip
#TODO Probowac powershellem
ipconfig /all | Select-String "DHCP wĄczone","Adres IPv4","Maska podsieci","Brama domylna","Serwer DHCP","Serwery DNS"

#lub
#ewentualnie zamazać dane
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE  | Select-Object DHCPServer,DHCPEnabled,@{label="IPAddress";expression={$_.ipaddress[0]}},@{label="DefaultIPGateway";expression={$_.DefaultIPGateway[0]}},@{label="IPSubnet";expression={$_.IPSubnet[0]}} 

#endregion DHCP i ip



#endregion rozdzial2


#region rozdzial3

#region Applocker


#TODO do weryfikacji - byłem mega zmęczony
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\windows\*.exe","C:\Program Files\*.exe" -User Wszyscy #wszyscy mogą odpalać z 2 folderów
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\Windows\System32\*.exe"  -User BUILTIN\Administratorzy #administratorzy mogą odpalać wszystkie pliki

Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\Program Files (x86)\Internet Explorer\iexplore.exe" -User Wszyscy #wybrane programy explorer,mozilla,chrome

#region ######### Aplikacje wbudowane w Win10#########
#Do testów-może być bardziej optymalne od powyższego
Get-AppLockerPolicy -Effective -Xml | Set-Content ('c:\test\curr.xml')
[xml]$cn = Get-Content C:\test\curr.xml
$cn.AppLockerPolicy.RuleCollection.Get(0).FilePublisherRule | Select UserOrGroupSid,Action,@{Label="PublisherName"; Expression={$_.Conditions.FilePublisherCondition.PublisherName}},@{Label="ProductName"; Expression={$_.Conditions.FilePublisherCondition.ProductName}},@{Label="BinaryName"; Expression={$_.Conditions.FilePublisherCondition.BinaryName}} | ft
$cn.AppLockerPolicy.RuleCollection.Get(2).FilePathRule | Select USerOrGroupSid,Action,@{Label="Path"; Expression={$_.Conditions.FilePathCondition.Path}}

#endregion ######### Aplikacje wbudowane w Win10#########




#region monitorowanie aplikacji
Get-AppLockerFileInformation -EventLog -Statistics | Select @{label="FilePath";expression={$_.FilePath.Path.Substring($_.FilePath.Path.LastIndexOf("\")+1)}}, Counter | sort Counter -Descending | fl *
#endregion

#endregion Applocker

#region Autorun
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer | fl NoAutorun
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer | fl NoDriveTypeAutoRun
#endregion Autorun

#region drivers
Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions | fl AllowUserDeviceClasses 
Get-ItemProperty HKCU:\Software\Policies\Microsoft\Windows\DriverSearching | fl DontSearchCD
Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows NT\Driver Signing" | fl BehaviorOnFailedVerify
#endregion drivers

#region magazynWymienny
Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices" | fl Deny_All

#pendrive podłączone
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | fl FriendlyName

#lub 

Get-PnpDevice -FriendlyName '*USB*'

#endregion magazynWymienny

#endregion rozdzial3

#region rozdzial4

#region registry
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System |fl DisableRegistryTools
#endregion registry

#region cmd
Get-ItemProperty HKCU:\Software\Policies\Microsoft\Windows\System |fl DisableCMD
#endregion cmd

#region managerZadan
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System |fl DisableTaskMgr
#endregion managerZadan

#region uslugi
Get-Service XblAuthManager,XblGameSave,XboxGipSvc,XboxNetApiSvc,AppIDSvc | Select Name,Status
Get-Service AppIDSvc | Select Name, StartType
#endregion uslugi

#region PowershellLog
Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging |fl EnableScriptBlockLogging
#endregion PowershellLog


#region polaczeniaZdalne
Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service |fl AllowUnencryptedTraffic

Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service |fl DisableRunAs

Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service |fl AllowBasic
#endregion polaczeniaZdalne

#region szyfrowanie pliku stronnicowanie
Get-ItemProperty HKLM:\System\CurrentControlSet\Policies |fl NtfsEncryptPagingFile
#endregion szyfrowanie pliku stronnicowanie


#endregion rozdzial4

#region rozdzial5

#panel
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization | fl NoLockScreenCamera
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization | fl NoLockScreenSlideShow
####brak nauki pisma ręcznego####
#####zezwalaj użytkownikom na włączanie rozpoznawania mowy online#####

#biometria
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures | fl EnhancedAntiSpoofing

#aparat
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Camera | fl AllowCamera

#microsoft edge
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BrowserEmulation | fl MSCompatibilityMode
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy | fl ClearBrowsingHistoryOnExit
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main | fl "FormSuggest Passwords" #sugerowanie hasel
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter | fl EnabledV9
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary | fl EnableExtendedBooksTelemetry
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main | fl PreventAccessToAboutFlagsInMicrosoftEdge
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main | fl PreventLiveTileDataCollection


#Windows Defender
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" | fl DisableAntiSpyware
Get-MpPreference | Select PUAProtection | fl
Get-MpPreference | Select DisableBehaviorMonitoring | fl
Get-MpPreference | Select DisableRemovableDriveScanning | fl
Get-MpPreference | Select EnableNetworkProtection | fl


#lokalizacja i czujniki
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors | fl DisableLocationScripting
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors | fl DisableLocation
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors | fl DisableSensors

#endregion rozdzial5

#region rozdzial6
Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | fl ScreenSaverIsSecure
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" | fl NoDispScrSavPage

#okres bezycznnosci
Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | fl ScreenSaveTimeOut
#endregion rozdzial6