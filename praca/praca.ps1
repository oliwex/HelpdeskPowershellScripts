###################################
##                              ###
##            secedit           ###
##                              ###
###################################
#region required
#Requires -Modules PSWindowsUpdate
#requires -Module hashdata

#endregion required

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

function New-HashTableWithDisabledValue($hashtableFromSystem)
{
#IN:$hashtableFromSystem-Get hashtable from system with system settings
#OUT:Returning hashtable with DISABLED value where null existed
    ($hashtableFromSystem.GetEnumerator()) | ForEach-Object {if ($_.Value -eq $null) { $hashtableFromSystem[$_.Name] = 'DISABLED' }}
    return $hashtableFromSystem
}
function UniwersalWrapper($powershellCommand)  #wrapper
{
#IN:$hashtableFromSystem-Get hashtable from system with system settings
#OUT:Returning hashtable with DISABLED value where null existed
    $result=New-HashTableWithDisabledValue(ConvertTo-Hashtable($poershellCommand))
    return $result
}

function New-BitlockerReport
{
#OUT:$result-hashtable with result of Bitlocker Report
$result=[ordered]@{}

if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\FVE)
{

$result=UniwersalWrapper(Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE | fl @{label="BitlockerActiveDirectoryBackup";expression={$_.ActiveDirectoryBackup}},
@{label="BitlockerRecoveryFilepath";expression={$_.DefaultRecoveryFolderPath}},
@{label="BitlockerEncryptionMethod";expression={$_.EncryptionMethodNoDiffuser}},
@{label="BitlockerPasswordOnFixed";expression={$_.FDVPassphrase}},
@{label="BitlockerPasswordOnFixedComplexity";expression={$_.FDVPassphraseComplexity}},
@{label="BitlockerPasswordOnFixedLength";expression={$_.FDVPassphraseLength}},
@{label="BitlockerAditionalAuthenticationOnStartup";expression={$_.UseAdvancedStartup}},
@{label="BitlockerWithoutTPM";expression={$_.EnableBDEWithNoTP}},
@{label="BitlockerWithTPM";expression={$_.UseTPM}},
@{label="BitlockerPINWithTPM";expression={$_.UseTPMPIN}},
@{label="BitlockerKeyWithTPM";expression={$_.UseTPMKey}},
@{label="BitlockerKeyAndPINWithTPM";expression={$_.UseTPMKeyPIN}},
@{label="BitlockerEncryptionMethod";expression={$_.OSEncryptionType}}
)

}
else
{
$result.add('BitlockerActiveDirectoryBackup','DISABLED')
$result.add('BitlockerRecoveryFilepath','DISABLED')
$result.add('BitlockerEncryptionMethod','DISABLED')
$result.add('BitlockerPasswordOnFixed','DISABLED')
$result.add('BitlockerPasswordOnFixedComplexity','DISABLED')
$result.add('BitlockerPasswordOnFixedLength','DISABLED')
$result.add('BitlockerAditionalAuthenticationOnStartup','DISABLED')
$result.add('BitlockerWithoutTPM','DISABLED')
$result.add('BitlockerWithTPM','DISABLED')
$result.add('BitlockerKeyWithTPM','DISABLED')
$result.add('BitlockerKeyAndPINWithTPM','DISABLED')
$result.add('BitlockerEncryptionMethod','DISABLED') 
}


if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE)
{
$value=Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE -Name FDVDenyWriteAccess
}
else
{
$value='DISABLED'
}
$result.add('BitlockerDenyWriteAccessToFixedDataDrivesWithoutBitlocker',$value) 
$result | ft -AutoSize

return $result
}

Function Test-RegistryValue 
{
param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 

    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                if ($PassThru) {
                    Get-ItemProperty $Path $Name
                } else {
                    $true
                }
            } else {
                $false
            }
        } else {
            $false
        }
    }
}

function Get-RegistryValueWithDisabledValue()
{
param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$ValueToCheck
        ,
        [Parameter(Position = 2, Mandatory = $true)]
        $HashtableRowName
        ,
        [Parameter(Position = 3, Mandatory = $true)]
        $HashtableResult
    ) 
    
    if (Test-RegistryValue -Path $Path -Name $valueToCheck)
    {
        $HashtableResult.Add($HashtableRowName,(Get-ItemPropertyValue $Path -Name $ValueToCheck))
    }
    else
    {
        $HashtableResult.Add($HashtableRowName,"DISABLED")

    }
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
<#
$domainProfileResult=UniWersalWrapper((Get-NetFirewallProfile -PolicyStore ActiveStore | Select Name,Enabled,@{label="LogFilePath";expression={$_.LogFileName}},@{label="LogSize";expression={$_.LogMaxSizeKilobytes}})[0])
$domainProfileResult
$privateProfileResult=UniWersalWrapper((Get-NetFirewallProfile -PolicyStore ActiveStore | Select Name,Enabled,@{label="LogFilePath";expression={$_.LogFileName}},@{label="LogSize";expression={$_.LogMaxSizeKilobytes}})[0])
$privateProfileResult
$publicProfileResult=UniWersalWrapper((Get-NetFirewallProfile -PolicyStore ActiveStore | Select Name,Enabled,@{label="LogFilePath";expression={$_.LogFileName}},@{label="LogSize";expression={$_.LogMaxSizeKilobytes}})[0])
$publicProfileResult
#>

#ipsec

#$result=UniwersalWrapper(((Show-NetIPsecRule -PolicyStore ActiveStore | Select @{label="LocalAddress";expression={$_ | Get-NetFirewallAddressFilter | select -ExpandProperty LocalAddress}},@{label="RemoteAddress";expression={$_ | Get-NetFirewallAddressFilter | select -ExpandProperty RemoteAddress}},@{label="Auth1Level";expression={($_ | Get-NetIPsecPhase1AuthSet).Name}},@{label="Auth2Level";expression={($_ | Get-NetIPsecPhase2AuthSet).Name}})[0]))
#$result


#endregion firewall

#region podgladzdarzen



#required -Module hashdata
<#
$result=UniwersalWrapper(Get-WinEvent -ListLog Application | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application | Select -ExpandProperty Retention}})
$result
$result=UniwersalWrapper(Get-WinEvent -ListLog Setup | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup | Select -ExpandProperty Retention}})
$result
$result=UniwersalWrapper(Get-WinEvent -ListLog System | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System | Select -ExpandProperty Retention}})
$result
$result=UniwersalWrapper(Get-WinEvent -ListLog Security | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security | Select -ExpandProperty Retention}})
$result
#>
#endregion podgladzdarzen

#region WindowsUpdate


#Install-Module -Name PSWindowsUpdate

#dziala w 70% procentach
<#
$wsusList=[ordered]@{
'AutoUpdate'='DISABLED';
'InstallUpdateType'='DISABLED';
'InstallDay'='DISABLED';
'InstallTime'='DISABLED';
'UseWsus'='DISABLED';
'WSUSServer1'='DISABLED';
'WSUSStatServer'='DISABLED';
'WSUSServer2'='DISABLED';
'WSUSGroupPolicy'='DISABLED';
'WSUSGroup'='DISABLED';
}
try
{
    $wsus=Get-WUSettings | 
    Select @{Label='AutoUpdate';Expression={$_.NoAutoUpdate}},
    @{Label='InstallUpdateType';Expression={$_.AuOptions.Substring(0,1)}},
    @{Label='InstallDay';Expression={$_.ScheduledInstallDay.Substring(0,1)}},
    @{Label='InstallTime';Expression={$_.ScheduledInstallTime}},
    @{Label='UseWsus';Expression={$_.UseWUServer}},
    @{Label='WSUSServer1';Expression={$_.WuServer}},
    @{Label='WSUSStatServer';Expression={$_.WUStatusServer}},
    @{Label='WSUSServer2';Expression={$_.UpdateServiceUrlAlternate}},
    @{Label='WSUSGroupPolicy';Expression={$_.TargetGroupEnabled}},
    @{Label='WSUSGroup';Expression={$_.TargetGroup}}
}
catch [System.NullReferenceException]
{      
            $wsus=Get-ItemProperty -PAth  HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU | fl @{Label='AutoUpdate';Expression={$_.NoAutoUpdate}},
            @{Label='InstallUpdateType';Expression={$_.AuOptions}},
            @{Label='InstallDay';Expression={$_.ScheduledInstallDay}},
            @{Label='InstallTime';Expression={$_.ScheduledInstallTime}}
        
            $wsus+=Get-ItemProperty -PAth HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate | fl @{Label='UseWsus';Expression={$_.WuServer}},
            @{Label='WSUSStatServer';Expression={$_.WUStatusServer}},
            @{Label='WSUSServer2';Expression={$_.UpdateServiceUrlAlternate}},
            @{Label='WSUSGroupPolicy';Expression={$_.TargetGroupEnabled}},
            @{Label='WSUSGroup';Expression={$_.TargetGroup}}
}
if ($wsus)
{
$i=0
$wsus.psobject.Properties.Where({$_.Value -ne $null}) | ForEach-Object { 
$wsusList.Item($i) = $_.Value
$i=$i+1 
}
}
$wsusList
#>


#endregion WindowsUpdate

#region Bitlocker
$bitlockerReport=New-BitlockerReport
$bitlockerReport
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
##################################
$=[ordered]@{}


Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueToCheck NoAutorun -HashtableRowName AutorunEnabled -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueToCheck NoDriveTypeAutoRun -HashtableRowName DefaultAutorunAction -HashtableResult $result

##################################

if (Test-RegistryKeyValue -Path HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions -Name AllowUserDeviceClasses)
{
    $result.Add("AllowUserDeviceClasses",(Get-ItemPropertyValue HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions -Name AllowUserDeviceClasses))
    
    if (Test-RegistryKeyValue -Path HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions\AllowUserDeviceClasses -Name 1)
    {
        $result.Remove("AllowUserDeviceClasses")
        $result.Add("AllowUserDeviceClasses", 'DISABLED') #Drivers classess exists 
    }
}
else
{
    $result.Add("AllowUserDeviceClasses","DISABLED")
}

Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\DriverSearching' -ValueToCheck DontSearchFloppies -HashtableRowName DontSearchInFloppiesForDrivers -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows NT\Driver Signing' -ValueToCheck BehaviorOnFailedVerify -HashtableRowName DigitalSignDrivers -HashtableResult $result
######################################
Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices' -ValueToCheck Deny_All -HashtableRowName DenyAccessToRemovableStorageAccess -HashtableResult $result

$result

######################################
#Lista podlaczonych pendrivow#
$usbList=(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select -ExpandProperty FriendlyName)
$usbList

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