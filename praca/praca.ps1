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
   $hashtableFromSystemTMP=($hashtableFromSystem.GetEnumerator()) | ? {$_.Value -eq $null}
   $hashtableFromSystemTMP | ForEach-Object {if ($_.Value -eq $null) { $hashtableFromSystem[$_.Name] = 'DISABLED' }}

    return $hashtableFromSystem
}

function UniwersalWrapper($powershellCommand)  #wrapper
{
#IN:$hashtableFromSystem-Get hashtable from system with system settings
#OUT:Returning hashtable with DISABLED value where null existed
    $result=New-HashTableWithDisabledValue(ConvertTo-Hashtable($powershellCommand))
    return $result
}

function New-FirewallReport
{
#OUT:Hashtable with FirewallReport
#domain
#private
#public

$domainProfileResult=UniwersalWrapper((Get-NetFirewallProfile -PolicyStore ActiveStore | Select Name,Enabled,@{label="LogFilePath";expression={$_.LogFileName}},@{label="LogSize";expression={$_.LogMaxSizeKilobytes}})[0])
$privateProfileResult=UniwersalWrapper((Get-NetFirewallProfile -PolicyStore ActiveStore | Select Name,Enabled,@{label="LogFilePath";expression={$_.LogFileName}},@{label="LogSize";expression={$_.LogMaxSizeKilobytes}})[1])
$publicProfileResult=UniwersalWrapper((Get-NetFirewallProfile -PolicyStore ActiveStore | Select Name,Enabled,@{label="LogFilePath";expression={$_.LogFileName}},@{label="LogSize";expression={$_.LogMaxSizeKilobytes}})[2])

$firewallReport=[ordered]@{
Domain=$domainProfileResult;
Private=$privateProfileResult;
Public=$publicProfileResult
}

return $firewallReport

}

function New-IpsecReport
{
#OUT:Hashtable with ipsec report
    $ipsecResult=UniwersalWrapper(((Show-NetIPsecRule -PolicyStore ActiveStore | Select @{label="LocalAddress";expression={$_ | Get-NetFirewallAddressFilter | select -ExpandProperty LocalAddress}},@{label="RemoteAddress";expression={$_ | Get-NetFirewallAddressFilter | select -ExpandProperty RemoteAddress}},@{label="Auth1Level";expression={($_ | Get-NetIPsecPhase1AuthSet).Name}},@{label="Auth2Level";expression={($_ | Get-NetIPsecPhase2AuthSet).Name}})[0]))
    return $ipsecResult
}

function New-LogReport
{
$applicationLogResult=UniwersalWrapper(Get-WinEvent -ListLog Application | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application | Select -ExpandProperty Retention}})

$setupLogResult=UniwersalWrapper(Get-WinEvent -ListLog Setup | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup | Select -ExpandProperty Retention}})
$systemLogResult=UniwersalWrapper(Get-WinEvent -ListLog System | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System | Select -ExpandProperty Retention}})
$securityLogResult=UniwersalWrapper(Get-WinEvent -ListLog Security | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security | Select -ExpandProperty Retention}})

$logReport=[ordered]@{
Application=$domainProfileResult;
Setup=$privateProfileResult;
System=$publicProfileResult;
Security=$securityLogResult
}

return $logReport
}

function New-BitlockerReport
{
#OUT:$result-hashtable with result of Bitlocker Report
$bitlockerReport=[ordered]@{}

Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck ActiveDirectoryBackup -HashtableRowName BitlockerActiveDirectoryBackup -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck DefaultRecoveryFolderPath -HashtableRowName BitlockerRecoveryFilepath -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck EncryptionMethodNoDiffuser -HashtableRowName BitlockerEncryptionMethod -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck FDVPassphrase -HashtableRowName BitlockerPasswordOnFixed -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck FDVPassphraseComplexity -HashtableRowName BitlockerPasswordOnFixedComplexity -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck FDVPassphraseLength -HashtableRowName BitlockerPasswordOnFixedLength -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseAdvancedStartup -HashtableRowName BitlockerAditionalAuthenticationOnStartup -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck EnableBDEWithNoTP -HashtableRowName BitlockerWithoutTPM -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseTPM -HashtableRowName BitlockerWithTPM -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseTPMPIN -HashtableRowName BitlockerPINWithTPM -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseTPMKey -HashtableRowName BitlockerKeyWithTPM -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseTPMKeyPIN -HashtableRowName BitlockerKeyAndPINWithTPM -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck OSEncryptionType -HashtableRowName BitlockerEncryptionMethod -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE -ValueToCheck FDVDenyWriteAccess -HashtableRowName BitlockerDenyWriteAccessToFixedDataDrivesWithoutBitlocker -HashtableResult $result

return $bitlockerReport
}

function New-WSUSReport
{
#OUT: Hashtable with wsusReport
    $wsusList=[ordered]@{}  
 
    try
    {

        $wsusList=UniwersalWrapper(Get-WUSettings | 
        Select @{Label='AutoUpdate';Expression={$_.NoAutoUpdate}},
        @{Label='InstallUpdateType';Expression={$_.AuOptions.Substring(0,1)}},
        @{Label='InstallDay';Expression={$_.ScheduledInstallDay.Substring(0,1)}},
        @{Label='InstallTime';Expression={$_.ScheduledInstallTime}},
        @{Label='UseWsus';Expression={$_.UseWUServer}},
        @{Label='WSUSServer1';Expression={$_.WuServer}},
        @{Label='WSUSStatServer';Expression={$_.WUStatusServer}},
        @{Label='WSUSServer2';Expression={$_.UpdateServiceUrlAlternate}},
        @{Label='WSUSGroupPolicy';Expression={$_.TargetGroupEnabled}},
        @{Label='WSUSGroup';Expression={$_.TargetGroup}})
    }
    catch [System.NullReferenceException]
    {      

        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck NoAutoUpdate -HashtableRowName AutoUpdate -HashtableResult $wsusList
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck AuOptions -HashtableRowName InstallUpdateType -HashtableResult $wsusList
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck ScheduledInstallDay -HashtableRowName InstallDay -HashtableResult $wsusList
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck ScheduledInstallTime -HashtableRowName InstallTime -HashtableResult $wsusList
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck UseWUServer -HashtableRowName UseWsus -HashtableResult $wsusList
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck WuServer -HashtableRowName WSUSServer1 -HashtableResult $wsusList
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck WUStatusServer -HashtableRowName WSUSStatServer -HashtableResult $wsusList
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck UpdateServiceUrlAlternate -HashtableRowName WSUSServer2 -HashtableResult $wsusList
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck TargetGroupEnabled -HashtableRowName WSUSGroupPolicy -HashtableResult $wsusList
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck TargetGroup -HashtableRowName WSUSGroup -HashtableResult $wsusList

    }

   return $wsusList
}


Function Test-RegistryValue 
{
param(

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

function New-AutorunReport
{
    $autorunReport=[ordered]@{}
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueToCheck NoAutorun -HashtableRowName AutorunEnabled -HashtableResult $autorunReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueToCheck NoDriveTypeAutoRun -HashtableRowName DefaultAutorunAction -HashtableResult $autorunReport
    return $autorunReport
}

function New-DriversReport
{
    $driversReport=[ordered]@{}
    if (Test-RegistryValue -Path HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions -Name AllowUserDeviceClasses)
    {
        $driversReport.Add("AllowUserDeviceClasses",(Get-ItemPropertyValue HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions -Name AllowUserDeviceClasses))
        Test-RegistryValue -Path HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions\AllowUserDeviceClasses -Name 1
        if (Test-RegistryValue -Path HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions\AllowUserDeviceClasses -Name 1)
        {
            $driversReport.Remove("AllowUserDeviceClasses")
            $driversReport.Add("AllowUserDeviceClasses", 'DISABLED') #Drivers classess exists 
        }
    }
    else
    {
        $result.Add("AllowUserDeviceClasses","DISABLED")
    }
    Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\DriverSearching' -ValueToCheck DontSearchFloppies -HashtableRowName DontSearchInFloppiesForDrivers -HashtableResult $driversReport
    Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows NT\Driver Signing' -ValueToCheck BehaviorOnFailedVerify -HashtableRowName DigitalSignDrivers -HashtableResult $driversReport
    return $driversReport
}

function New-RemovableStorageAccessReport
{
    $removableStorageAccessReport=[ordered]@{}
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices' -ValueToCheck Deny_All -HashtableRowName DenyAccessToRemovableStorageAccess -HashtableResult $removableStorageAccessReport
    return $removableStorageAccessReport
}
function New-USBHistoryList
{
    $usbList=(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select -ExpandProperty FriendlyName)
    return $usbList
}

function New-PanelReport
{
    $panelReport=[ordered]@{}
    #panel
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ValueToCheck NoLockScreenCamera -HashtableRowName NoLockScreenCamera -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ValueToCheck NoLockScreenSlideShow -HashtableRowName NoLockScreenSlideShow -HashtableResult $panelReport
    ####brak nauki pisma ręcznego####
    #####brak zezwalaj użytkownikom na włączanie rozpoznawania mowy online#####

    #biometria
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Camera' -ValueToCheck AllowCamera -HashtableRowName AllowCamera -HashtableResult $panelReport

    #aparat
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Camera' -ValueToCheck AllowCamera -HashtableRowName AllowCamera -HashtableResult $panelReport


    #microsoft edge
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BrowserEmulation' -ValueToCheck MSCompatibilityMode -HashtableRowName MSCompatibilityMode -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy' -ValueToCheck ClearBrowsingHistoryOnExit -HashtableRowName ClearBrowsingHistoryOnExit -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ValueToCheck 'FormSuggest Passwords' -HashtableRowName 'FormSuggest Passwords' -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -ValueToCheck EnabledV9 -HashtableRowName EnabledV9 -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary' -ValueToCheck EnableExtendedBooksTelemetry -HashtableRowName EnableExtendedBooksTelemetry -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ValueToCheck PreventAccessToAboutFlagsInMicrosoftEdge -HashtableRowName PreventAccessToAboutFlagsInMicrosoftEdge -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ValueToCheck PreventLiveTileDataCollection -HashtableRowName PreventLiveTileDataCollection -HashtableResult $panelReport

    #Windows Defender
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueToCheck DisableAntiSpyware -HashtableRowName DisableAntiSpyware -HashtableResult $panelReport
    $panelReport+=UniwersalWrapper(Get-MpPreference | Select PUAProtection,DisableBehaviorMonitoring,DisableRemovableDriveScanning,EnableNetworkProtection | fl)

    #lokalizacja i czujniki
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -ValueToCheck DisableLocationScripting -HashtableRowName DisableLocationScripting -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -ValueToCheck DisableLocation -HashtableRowName DisableLocation -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -ValueToCheck DisableSensors -HashtableRowName DisableSensors -HashtableResult $panelReport

    return $panelReport
}


function New-ScreenSaverReport
{
    $screensaverReport=[ordered]@{}
    Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -ValueToCheck ScreenSaverIsSecure -HashtableRowName ScreenSaverIsSecure -HashtableResult $screensaverReport
    Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ValueToCheck NoDispScrSavPage -HashtableRowName NoDispScrSavPage -HashtableResult $screensaverReport

    Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -ValueToCheck ScreenSaveTimeOut -HashtableRowName ScreenSaveTimeOut -HashtableResult $screensaverReport

    return $screensaverReport
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
$firewallReport=New-FirewallReport
$firewallReport.Domain.LogFilePath
#>

#ipsec

#$ipsecReport=New-IpsecReport
#$ipsecReport

#endregion firewall

#region podgladzdarzen

#$logReport=New-LogReport
#$logReport.Application.LogFilePath

#endregion podgladzdarzen

#region WindowsUpdate


#Install-Module -Name PSWindowsUpdate


$wsusList=New-WSUSReport
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
$ipAddress=UniwersalWrapper(Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE  | Select-Object @{label="IPAddress";expression={$_.ipaddress[0]}},@{label="IPSubnet";expression={$_.IPSubnet[0]}},MACAddress,@{label="DefaultIPGateway";expression={$_.DefaultIPGateway[0]}},DHCPServer,DHCPEnabled,DNSDomain,DNSServerSearchOrder)
$ipAddress
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

$exeRule=$cn.AppLockerPolicy.RuleCollection.Get(1)

foreach($element in $exeRule)
{
    $element.FilePublisherRule | Select Action,@{Label="UserOrGroupSid"; Expression={Resolve-CIdentity -SID ($_.UserOrGroupSid) | Select -ExpandProperty FullName}},@{Label="Product"; Expression={$_.Conditions.FilePublisherCondition.ProductName}},@{Label="PublisherName"; Expression={$_.Conditions.FilePublisherCondition.PublisherName}}
    $element.FilePathRule | Select Action,@{Label="UserOrGroupSid"; Expression={Resolve-CIdentity -SID ($_.UserOrGroupSid) | Select -ExpandProperty FullName}},@{Label="Product"; Expression={$_.Conditions.FilePathCondition.Path}},@{Label="PublisherName"; Expression={'PathRule'}}
}

$cn.AppLockerPolicy.RuleCollection.Get(2).FilePathRule | Select USerOrGroupSid,Action,@{Label="Path"; Expression={$_.Conditions.FilePathCondition.Path}}

#endregion ######### Aplikacje wbudowane w Win10#########




#region monitorowanie aplikacji
Get-AppLockerFileInformation -EventLog -Statistics | Select @{label="FilePath";expression={$_.FilePath.Path.Substring($_.FilePath.Path.LastIndexOf("\")+1)}}, Counter | sort Counter -Descending | fl *
#endregion

#endregion Applocker

#region Autorun
##################################
$autorunReport=New-AutorunReport
$autorunReport
##################################
$driversReport=New-DriversReport
$driversReport
######################################
$removableStorageAccessReport=New-RemovableStorageAccessReport
$removableStorageAccessReport
######################################
#Lista podlaczonych pendrivow#
$usbList=New-USBHistoryList
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
$panelReport=New-PanelRaport
$panelReport
#endregion rozdzial5

#region rozdzial6
$screensaverReport=New-ScreenSaverReport
$screensaverReport
#endregion rozdzial6

