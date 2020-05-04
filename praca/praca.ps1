
  
###################################
##                              ###
##            secedit           ###
##                              ###
###################################
#region required
#Requires -Module PSWindowsUpdate
#requires -Module hashdata
#requires -Module Carbon

#endregion required

#region global

$folderName="test"
$path=$env:HOMEDRIVE+"\"+$folderName




#endregion global

#region filenames
#TODO create list

$applockerFile="applocker.xml"
$seceditFile="secedit.cfg"
#endregion filenames

#region paths
#TODO create list
$applockerPath=$path+"\"+$applockerFile
$seceditPath=$path+"\"+$seceditFile
#endregion paths


#region dictionary
#TODO:


#endregion dictionary

#region functions
Function Prepare-Workplace
{
param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]$PathToWorkplace
     )
    Clear-Host
    if (!(Test-Path  $PathToWorkplace))
    {
        New-Item -Path $PathToWorkplace -ItemType Directory        
    }
    else
    {
        Remove-Item -Path $PathToWorkplace -Recurse -Force
    }
}




function Get-SeceditContent()
{
param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]$PathToSecedit
     )
    secedit /export /cfg $PathToSecedit
    $SeceditContent=Get-Content -Path $PathToSecedit
    return $SeceditContent
}

function Add-ElementToPolicyList()
{
param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]$SeceditElement
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        $PolicyTable
        
     )
    $richElement=($SeceditElement).Replace(' ','').Split("=")
    $PolicyTable.Add($richElement[0],$richElement[1])
}


function New-HashTableWithDisabledValue($hashtableFromSystem)
{
#IN:$hashtableFromSystem-Get hashtable from system with system settings
#OUT:Returning hashtable with DISABLED value where null existed
   $hashtableFromSystemTMP=($hashtableFromSystem.GetEnumerator()) | ? {$_.Value -eq $null}
   $hashtableFromSystemTMP | ForEach-Object {if ($_.Value -eq $null) { $hashtableFromSystem[$_.Name] = 'DISABLED' }}

    return $hashtableFromSystem
}

#Not for registry
function UniwersalWrapper($powershellCommand)  #wrapper
{
#IN:$hashtableFromSystem-Get hashtable from system with system settings
#OUT:Returning hashtable with DISABLED value where null existed
    $tmp=ConvertTo-Hashtable -InputObject $powershellCommand
    $result=New-HashTableWithDisabledValue($tmp)
    return $result
}
#For registry
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
function New-RightReport()
{
param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]$PathToSecedit
     )

    $policyTable=[ordered]@{}
    $SeceditContent=Get-SeceditContent -PathToSecedit $PathToSecedit

    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern SeTakeOwnershipPrivilege) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern SeRemoteInteractiveLogonRight) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern EnableAdminAccount) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern EnableGuestAccount) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern NewGuestName) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern NewAdministratorName) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern DontDisplayLastUserName) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern ForceUnlockLogon) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern CachedLogonsCount) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern PasswordExpiryWarning) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern LegalNoticeCaption) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern LegalNoticeText) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern ConsentPromptBehaviorUser) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern ConsentPromptBehaviorAdmin) -PolicyTable $policyTable
    Add-ElementToPolicyList -SeceditElement ($SeceditContent | Select-String -Pattern ClearPageFileAtShutdown) -PolicyTable $policyTable

    return $policyTable
}


function New-GroupReport()
{

$adminsGroup=(Get-LocalGroupMember 'Administratorzy').Name
$remoteaccessGroup=(Get-LocalGroupMember 'Użytkownicy zarządzania zdalnego').Name
$remoteaccessGroup=(Get-LocalGroupMember 'Administratorzy Domeny').Name

$groupTable=[ordered]@{
    Administrators=$adminsGroup;
    RemoteAccess=$remoteaccessGroup;
    DomainAdmins=$remoteaccessGroup
    }

    return $groupTable
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
{#OUT:Hashtable with ipsec report
    
    $ipsecResult=[ordered]@{}

    try
    {
        $ipsecTMP=((Show-NetIPsecRule -PolicyStore ActiveStore | Select @{label="LocalAddress";expression={$_ | Get-NetFirewallAddressFilter | select -ExpandProperty LocalAddress}},@{label="RemoteAddress";expression={$_ | Get-NetFirewallAddressFilter | select -ExpandProperty RemoteAddress}},@{label="Auth1Level";expression={($_ | Get-NetIPsecPhase1AuthSet).Name}},@{label="Auth2Level";expression={($_ | Get-NetIPsecPhase2AuthSet).Name}})[0])
        $ipsecResult=UniwersalWrapper($ipsecTMP)
    }
    catch [System.Management.Automation.RuntimeException]
    {
        $ipsecResult.Add('LocalAddress','DISABLED')
        $ipsecResult.Add('RemoteAddress','DISABLED')
        $ipsecResult.Add('Auth1Level','DISABLED')
        $ipsecResult.Add('Auth2Level','DISABLED')
    }    
    return $ipsecResult
}

function New-LogReport
{
    $applicationLogResult=UniwersalWrapper(Get-WinEvent -ListLog Application | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application | Select -ExpandProperty Retention}})
    $setupLogResult=UniwersalWrapper(Get-WinEvent -ListLog Setup | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup | Select -ExpandProperty Retention}})
    $systemLogResult=UniwersalWrapper(Get-WinEvent -ListLog System | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System | Select -ExpandProperty Retention}})
    $securityLogResult=UniwersalWrapper(Get-WinEvent -ListLog Security | Select LogName,@{label="MaximumSizeInBytes";expression={$_.MaximumSizeInBytes/1024}},LogMode,@{label="Retention";expression={Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security | Select -ExpandProperty Retention}})

    $logReport=[ordered]@{
    Application=$applicationLogResult;
    Setup=$setupLogResult;
    System=$systemLogResult;
    Security=$securityLogResult
}

return $logReport
}

function New-BitlockerReport
{
#OUT:$result-hashtable with result of Bitlocker Report
    $bitlockerReport=[ordered]@{}

    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck ActiveDirectoryBackup -HashtableRowName BitlockerActiveDirectoryBackup -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck DefaultRecoveryFolderPath -HashtableRowName BitlockerRecoveryFilepath -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck EncryptionMethodNoDiffuser -HashtableRowName BitlockerEncryptionMethod -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck FDVPassphrase -HashtableRowName BitlockerPasswordOnFixed -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck FDVPassphraseComplexity -HashtableRowName BitlockerPasswordOnFixedComplexity -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck FDVPassphraseLength -HashtableRowName BitlockerPasswordOnFixedLength -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseAdvancedStartup -HashtableRowName BitlockerAditionalAuthenticationOnStartup -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck EnableBDEWithNoTP -HashtableRowName BitlockerWithoutTPM -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseTPM -HashtableRowName BitlockerWithTPM -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseTPMPIN -HashtableRowName BitlockerPINWithTPM -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseTPMKey -HashtableRowName BitlockerKeyWithTPM -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck UseTPMKeyPIN -HashtableRowName BitlockerKeyAndPINWithTPM -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ValueToCheck OSEncryptionType -HashtableRowName BitlockerEncryptionMethodOnOperatingSystemDrive -HashtableResult $bitlockerReport
    Get-RegistryValueWithDisabledValue -Path HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE -ValueToCheck FDVDenyWriteAccess -HashtableRowName BitlockerDenyWriteAccessToFixedDataDrivesWithoutBitlocker -HashtableResult $bitlockerReport

    return $bitlockerReport
}

function New-NetworkReport
{
    $networkReport=UniwersalWrapper(Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE  | Select-Object @{label="IPAddress";expression={$_.ipaddress[0]}},@{label="IPSubnet";expression={$_.IPSubnet[0]}},MACAddress,@{label="DefaultIPGateway";expression={$_.DefaultIPGateway[0]}},DHCPServer,DHCPEnabled,DNSDomain,DNSServerSearchOrder | Select -First 1)
    return $networkReport
}


function New-ApplockerReport
{
param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]$Path
    )
    Get-AppLockerPolicy -Effective -Xml | Set-Content ($Path)
    [xml]$cn = Get-Content $Path

    $exeCollection=$cn.AppLockerPolicy.RuleCollection.Get(2) #dla windows7 jest 1
    $appxCollection=$cn.AppLockerPolicy.RuleCollection.Get(0)


    $exeRules=foreach($element in $exeCollection)
    {
        $element.FilePublisherRule | Select Action,@{Label="UserOrGroupSid"; Expression={Resolve-CIdentity -SID ($_.UserOrGroupSid) | Select -ExpandProperty FullName}},@{Label="Product"; Expression={$_.Conditions.FilePublisherCondition.ProductName}},@{Label="PublisherName"; Expression={$_.Conditions.FilePublisherCondition.PublisherName}}
        $element.FilePathRule | Select Action,@{Label="UserOrGroupSid"; Expression={Resolve-CIdentity -SID ($_.UserOrGroupSid) | Select -ExpandProperty FullName}},@{Label="Product"; Expression={$_.Conditions.FilePathCondition.Path}},@{Label="PublisherName"; Expression={'PathRule'}}
    }
    $appxRules=foreach($element in $appxCollection)
    {
        $element.FilePublisherRule | Select Action,@{Label="UserOrGroupSid"; Expression={Resolve-CIdentity -SID ($_.UserOrGroupSid) | Select -ExpandProperty FullName}},@{Label="Product"; Expression={$_.Conditions.FilePublisherCondition.ProductName}},@{Label="PublisherName"; Expression={$_.Conditions.FilePublisherCondition.PublisherName}}
    }


    $applockerReport=[ordered]@{}
    $applockerReport=$exeRules+$appxRules

    return $applockerReport
}

function New-ApplockerList
{
   $applockerlist=[ordered]@{}
   $applockerlist = ConvertTo-Hashtable (Get-AppLockerFileInformation -EventLog -Statistics | Select @{label="FilePath";expression={$_.FilePath.Path.Substring($_.FilePath.Path.LastIndexOf("\")+1)}}, Counter | sort Counter -Descending | fl *)
   return $applockerlist
}

function New-AutorunReport
{
    $autorunReport=[ordered]@{}
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueToCheck NoAutorun -HashtableRowName AutorunEnabled -HashtableResult $autorunReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueToCheck NoDriveTypeAutoRun -HashtableRowName DefaultAutorunAction -HashtableResult $autorunReport
    return $autorunReport
}

function New-WSUSReport
{
#OUT: Hashtable with wsusReport
    $wsusReport=[ordered]@{}  
 
    $wsusSettings=Get-WUSettings

    if ($wsusSettings)
    {
    
        $wsusSettings | Select @{Label='AutoUpdate';Expression={$_.NoAutoUpdate}},
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
    else
    {
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck NoAutoUpdate -HashtableRowName AutoUpdate -HashtableResult $wsusReport
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck AuOptions -HashtableRowName InstallUpdateType -HashtableResult $wsusReport
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck ScheduledInstallDay -HashtableRowName InstallDay -HashtableResult $wsusReport
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck ScheduledInstallTime -HashtableRowName InstallTime -HashtableResult $wsusReport
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueToCheck UseWUServer -HashtableRowName UseWsus -HashtableResult $wsusReport
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck WuServer -HashtableRowName WSUSServer1 -HashtableResult $wsusReport
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck WUStatusServer -HashtableRowName WSUSStatServer -HashtableResult $wsusReport
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck UpdateServiceUrlAlternate -HashtableRowName WSUSServer2 -HashtableResult $wsusReport
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck TargetGroupEnabled -HashtableRowName WSUSGroupPolicy -HashtableResult $wsusReport
        Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueToCheck TargetGroup -HashtableRowName WSUSGroup -HashtableResult $wsusReport

    }
return $wsusReport
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
        $driversReport.Add("AllowUserDeviceClasses","DISABLED")
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

function New-ToolReport
{
    #region rozdzial4
    $toolReport=[ordered]@{}
    #region registry
    Get-RegistryValueWithDisabledValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -ValueToCheck DisableRegistryTools -HashtableRowName DisableRegistryTools -HashtableResult $toolReport
    #endregion registry

    #region cmd
    Get-RegistryValueWithDisabledValue -Path HKCU:\Software\Policies\Microsoft\Windows\System -ValueToCheck DisableCMD -HashtableRowName DisableCMD -HashtableResult $toolReport
    #endregion cmd

    #region managerZadan
    Get-RegistryValueWithDisabledValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -ValueToCheck DisableTaskMgr -HashtableRowName DisableTaskMgr -HashtableResult $toolReport
    #endregion managerZadan

    #region PowershellLog
    Get-RegistryValueWithDisabledValue -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -ValueToCheck EnableScriptBlockLogging -HashtableRowName EnableScriptBlockLogging -HashtableResult $toolReport
    #endregion PowershellLog


    #region polaczeniaZdalne
    #allow unencrypted traffice
    Get-RegistryValueWithDisabledValue -Path HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service -ValueToCheck AllowUnencryptedTraffic -HashtableRowName AllowUnencryptedTraffic -HashtableResult $toolReport

    #disable token runas
    Get-RegistryValueWithDisabledValue -Path HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service -ValueToCheck DisableRunAs -HashtableRowName DisableRunAs -HashtableResult $toolReport

    #basic authentication
    Get-RegistryValueWithDisabledValue -Path HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service -ValueToCheck AllowBasic -HashtableRowName AllowBasic -HashtableResult $toolReport
    #endregion polaczeniaZdalne

    #region szyfrowanie pliku stronnicowanie
    Get-RegistryValueWithDisabledValue -Path HKLM:\System\CurrentControlSet\Policies -ValueToCheck NtfsEncryptPagingFile -HashtableRowName NtfsEncryptPagingFile -HashtableResult $toolReport
    #endregion szyfrowanie pliku stronnicowanie

    return $toolReport
}

function New-Service
{
    $serviceReport=Get-Service XblAuthManager,XblGameSave,XboxGipSvc,XboxNetApiSvc,AppIDSvc | Select Name,Status,StartType
    return $serviceReport
}

function New-PanelReport
{
    $panelReport=[ordered]@{}
    #panel
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ValueToCheck NoLockScreenCamera -HashtableRowName NoLockScreenCamera -HashtableResult $panelReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ValueToCheck NoLockScreenSlideShow -HashtableRowName NoLockScreenSlideShow -HashtableResult $panelReport
    ####brak nauki pisma ręcznego####
    #####brak zezwalaj użytkownikom na włączanie rozpoznawania mowy online#####

    #biometria-rozszerzone przeciwdziałanie przeciw podszywaniu się
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -ValueToCheck EnhancedAntiSpoofing -HashtableRowName EnhancedAntiSpoofing -HashtableResult $panelReport

    #aparat
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Camera' -ValueToCheck AllowCamera -HashtableRowName AllowCamera -HashtableResult $panelReport

    return $panelReport
}


function New-LocationReport
{
    $locationReport=[ordered]@{}
    
    #location and sensor
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -ValueToCheck DisableLocationScripting -HashtableRowName DisableLocationScripting -HashtableResult $locationReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -ValueToCheck DisableLocation -HashtableRowName DisableLocation -HashtableResult $locationReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -ValueToCheck DisableSensors -HashtableRowName DisableSensors -HashtableResult $locationReport
    
    return $locationReport
}

function New-DefenderReport
{
    $defenderReport=[ordered]@{}

    #Windows Defender
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueToCheck DisableAntiSpyware -HashtableRowName DisableAntiSpyware -HashtableResult $defenderReport
    $defenderReport+=UniwersalWrapper(Get-MpPreference | Select PUAProtection,DisableBehaviorMonitoring,DisableRemovableDriveScanning,EnableNetworkProtection)
    
    return $defenderReport
}

function New-EdgeReport
{
    $edgeReport=[ordered]@{}
    
    #microsoft edge
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BrowserEmulation' -ValueToCheck MSCompatibilityMode -HashtableRowName MSCompatibilityMode -HashtableResult $edgeReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy' -ValueToCheck ClearBrowsingHistoryOnExit -HashtableRowName ClearBrowsingHistoryOnExit -HashtableResult $edgeReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ValueToCheck 'FormSuggest Passwords' -HashtableRowName 'FormSuggest Passwords' -HashtableResult $edgeReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -ValueToCheck EnabledV9 -HashtableRowName EnabledV9 -HashtableResult $edgeReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary' -ValueToCheck EnableExtendedBooksTelemetry -HashtableRowName EnableExtendedBooksTelemetry -HashtableResult $edgeReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ValueToCheck PreventAccessToAboutFlagsInMicrosoftEdge -HashtableRowName PreventAccessToAboutFlagsInMicrosoftEdge -HashtableResult $edgeReport
    Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ValueToCheck PreventLiveTileDataCollection -HashtableRowName PreventLiveTileDataCollection -HashtableResult $edgeReport

    return $edgeReport
}


function New-ScreenSaverReport
{
    $screensaverReport=[ordered]@{}
    Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -ValueToCheck ScreenSaverIsSecure -HashtableRowName ScreenSaverIsSecure -HashtableResult $screensaverReport
    Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ValueToCheck NoDispScrSavPage -HashtableRowName NoDispScrSavPage -HashtableResult $screensaverReport

    Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -ValueToCheck ScreenSaveTimeOut -HashtableRowName ScreenSaveTimeOut -HashtableResult $screensaverReport

    return $screensaverReport
}

Function Delete-Workplace
{
param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]$PathToWorkplace
     )

     Remove-Item -Path $PathToWorkplace -Recurse -Force

}

#endregion functions


#code




Function Main
{
param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]$path,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$seceditPath
     )



#region startscript
Prepare-Workplace -PathToWorkplace $path
#endregion startscript

#region rozdzial1
$rightReport=New-RightReport -PathToSecedit $seceditPath

#grupy wbudowane#
$groupReport=New-GroupReport

#endregion rozdzial1


#region rozdzial2

#region firewall
$firewallReport=New-FirewallReport

#ipsec

$ipsecReport=New-IpsecReport

#endregion firewall

#region podgladzdarzen
$logReport=New-LogReport

#endregion podgladzdarzen

#region WindowsUpdate
$wsusReport=New-WSUSReport

#endregion WindowsUpdate

#region Bitlocker
$bitlockerReport=New-BitlockerReport

#endregion Bitlocker

#region DHCP i ip
$networkReport = New-NetworkReport


#endregion DHCP i ip

#endregion rozdzial2


#region rozdzial3

#region Applocker
if (((Get-WmiObject Win32_OperatingSystem).Caption -like '*Enterprise*') -XOR ((Get-WmiObject Win32_OperatingSystem).Caption -like '*Education*'))
{
    $applockerReport=New-ApplockerReport -Path $path


#endregion 

#region monitorowanie aplikacji
$applockerList=New-ApplockerList


#endregion
}
#endregion Applocker

#region Autorun
##################################
$autorunReport=New-AutorunReport

##################################
$driverReport=New-DriversReport

######################################
$removableStorageAccessReport=New-RemovableStorageAccessReport

######################################
#Lista podlaczonych pendrivow#
$usbList=New-USBHistoryList

#endregion magazynWymienny

#endregion rozdzial3

#region rozdzial4

#region uslugi
$service=New-Service


#endregion uslugi

#region narzedzia
$toolReport=New-ToolReport

#endregion narzedzie

#endregion rozdzial4

#region rozdzial5
$panelReport=New-PanelReport


$locationReport=New-LocationReport


$defenderReport=New-DefenderReport


$edgeReport=New-EdgeReport


#endregion rozdzial5

#region rozdzial6
$screensaverReport=New-ScreenSaverReport

#endregion rozdzial6

#region endscript
Delete-Workplace -PathToWorkplace $path
#endregion endscript


$hashtableFromSystem=[ordered]@{
RightReport=$rightReport;
GroupReport=$groupReport;
FirewallReport=$firewallReport;
IpSecReport=$ipsecReport;
LogReport=$logReport;
WsusReport=$wsusReport;
BitlockerReport=$bitlockerReport;
NetworkReport=$networkReport;
ApplockerReport=$applockerReport;
ApplockerList=$applockerList;
AutorunReport=$autorunReport;
DriverReport=$driverReport;
RemovableStorageAccessReport=$removableStorageAccessReport;
USBHistory=$usbList;
Services=$service;
ToolReport=$toolReport;
PanelReport=$panelReport;
LocationReport=$locationReport;
DefenderReport=$defenderReport;
EdgeReport=$edgeReport;
ScreensaverReport=$screensaverReport;
}

return $hashtableFromSystem

}
$result=Invoke-Command  -scriptblock ${function:Main} -argumentlist $path, $seceditPath

$result
