function Get-BasicComputerInfo
{
    $computerInfo=Get-ComputerInfo | Select * 
    
    $basic=$computerInfo | Select-Object Windows*,TimeZone,LogonServer,PowerPlatformRole
    switch($basic.PowerPlatformRole)
    {
        "AppliancePC" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified an appliance PC role"}
        "Desktop" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a desktop role"}
        "EnterpriseServer" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified an enterprise server role"}
        "MaximumEnumValue" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - Max enum value"}
        "Mobile" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a mobile role (for example, a laptop)"}
        "PerformanceServer" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a performance server role"}
        "Slate" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a tablet form factor role"}
        "SOHOServer" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a single office/home office (SOHO) server role"}
        "Unspecified" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - UnspecifieThe OEM did not specify a specific role"}
        "Workstation" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a workstation role"}
    }

    $bios=$computerInfo | Select-Object Bios*
    switch($bios.BiosFirmwareType)
    {
        "Bios"{$bios.BiosFirmwareType="$($bios.BiosFirmwareType) - The computer booted in legacy BIOS mode"}
        "Max"{$bios.BiosFirmwareType="$($bios.BiosFirmwareType) - Not implemented"}
        "Uefi"{$bios.BiosFirmwareType="$($bios.BiosFirmwareType) - The computer booted in UEFI mode"}
        "Unknown"{$bios.BiosFirmwareType="$($bios.BiosFirmwareType) - The firmware type is unknown"}
    }

    if($bios.BiosSMBIOSMajorVersion -eq $null)
    {
        $bios.BiosSMBIOSMajorVersion="SMBIOS Major Version not found"
    }
    if($bios.BiosSMBIOSMinorVersion -eq $null)
    {
        $bios.BiosSMBIOSMinorVersion="SMBIOS Minor Version not found"
    }
    if($bios.BiosSMBIOSPresent -eq $true)
    {
        $bios.BiosSMBIOSPresent="SMBIOS is available on this computer system"
    }
    
    $bios.BiosSoftwareElementState="$($bios.BiosSoftwareElementState) - Software element is $($bios.BiosSoftwareElementState)"

    $computerSystem=$computerInfo | Select-Object Cs*
    
    $computerSystem.CsAdminPasswordStatus="$($computerSystem.CsAdminPasswordStatus) - Hardware security is $($computerSystem.CsAdminPasswordStatus)"

    if ($computerSystem.CsAutomaticManagedPagefile)
    {
        $computerSystem.CsAutomaticManagedPagefile="System manages the pagefile.sys file"
    }
    else
    {
        $computerSystem.CsAutomaticManagedPagefile="System is not managing the pagefile.sys file"
    }

    if ($computerSystem.CsAutomaticResetBootOption)
    {
        $computerSystem.CsAutomaticResetBootOption="Automatic reset boot option is enabled"
    }
    else
    {
        $computerSystem.CsAutomaticResetBootOption="Automatic reset boot option is disabled"
    }

    if ($computerSystem.CsAutomaticResetCapability)
    {
        $computerSystem.CsAutomaticResetCapability="Automatic reset is enabled"
    }
    else
    {
        $computerSystem.CsAutomaticResetCapability="Automatic reset is disabled"
    }
    #
    switch($computerSystem.CsBootOptionOnLimit)
    {
        "DoNotReboot" {$computerSystem.CsBootOptionOnLimit = "$($computerSystem.CsBootOptionOnLimit) - do not reboot"}
        "OperatingSystem" {$computerSystem.CsBootOptionOnLimit = "$($computerSystem.CsBootOptionOnLimit) - Boot into operating system"}
        "SystemUtilities" {$computerSystem.CsBootOptionOnLimit = "$($computerSystem.CsBootOptionOnLimit) - Boot into system utilites"}
    }
    #
    switch($computerSystem.CsBootOptionOnWatchdog)
    {
        "DoNotReboot" {$computerSystem.CsBootOptionOnWatchdog = "$($computerSystem.CsBootOptionOnWatchdog) - do not reboot"}
        "OperatingSystem" {$computerSystem.CsBootOptionOnWatchdog = "$($computerSystem.CsBootOptionOnWatchdog) - Boot into operating system"}
        "SystemUtilities" {$computerSystem.CsBootOptionOnWatchdog = "$($computerSystem.CsBootOptionOnWatchdog) - Boot into system utilites"}
    }

    if ( $computerSystem.CsBootROMSupported)
    {
        $computerSystem.CsBootROMSupported = "Boot ROM is supported"
    }
    else
    {
        $computerSystem.CsBootROMSupported = "Boot ROM is not supported"
    }

    if($computerSystem.CsChassisBootupState -like "Other")
    {
        $computerSystem.CsChassisBootupState = "$($computerSystem.CsChassisBootupState) - The element is something other than in documentation" 
    }
    else
    {
        $computerSystem.CsChassisBootupState = "$($computerSystem.CsChassisBootupState) - The element is in $($computerSystem.CsChassisBootupState) state" 
    }
    
    if ($computerSystem.CsCurrentTimeZone -ne $null)
    {
        $calc=$computerSystem.CsCurrentTimeZone / 60
        $computerSystem.CsCurrentTimeZone = "$calc h is from London time"
    }

    if ($computerSystem.CsDaylightInEffect)
    {
        $computerSystem.CsDaylightInEffect = "Daylight saving mode is ON"
    }
    else
    {
        $computerSystem.CsDaylightInEffect = "Daylight saving mode is OFF"
    }

    switch($computerSystem.CsDomainRole)
    {
        "BackupDomainController" {$computerSystem.CsDomainRole = "Computer is Backup Domain Controller"}
        "MemberServer" {$computerSystem.CsDomainRole = "Computer is Member Server of Domain"}
        "MemberWorkstation" {$computerSystem.CsDomainRole = "Computer is Member Workstation of Domain"}
        "PrimaryDomainController" {$computerSystem.CsDomainRole = "Computer is Primary Domain Controller"}
        "StandaloneServer" {$computerSystem.CsDomainRole = "Computer is Standalone Server"}
        "StandaloneWorkstation" {$computerSystem.CsDomainRole = "Computer is Standalone Workstation"}
    }
    switch($computerSystem.CsEnableDaylightSavingsTime)
    {
        "True"{$computerSystem.CsEnableDaylightSavingsTime="Daylight saving time is enabled.System time is change 1 hour forward or backward when daylight saving time is started or ended."}
        "False"{$computerSystem.CsEnableDaylightSavingsTime="Daylight saving time is disabled."}
        ""{$computerSystem.CsEnableDaylightSavingsTime="State of daylight saving time is unknown"}
    }
    
    $computerSystem.CsFrontPanelResetStatus="Hardware security setting for the reset button on front Panel is $($computerSystem.CsFrontPanelResetStatus)"

    $computerSystem.CsKeyboardPasswordStatus="Hardware security setting for keyboard password status is $($computerSystem.CsKeyboardPasswordStatus)"

    if ($computerSystem.CsPauseAfterReset -eq -1)
    {
        $computerSystem.CsPauseAfterReset="Time Delay before reboot is initaited value is unknown"
    }
    else
    {
        $calc=$computerSystem.CsPauseAfterReset/1000
        $computerSystem.CsPauseAfterReset="$calc seconds before reboot is initaited"
    }

    switch($computerSystem.CsPCSystemType)
    {
        "AppliancePC" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified an appliance PC role"}
        "Desktop" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a desktop role"}
        "EnterpriseServer" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified an enterprise server role"}
        "MaximumEnumValue" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - Max enum value"}
        "Mobile" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a mobile role (for example, a laptop)"}
        "PerformanceServer" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a performance server role"}
        "Slate" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a tablet form factor role"}
        "SOHOServer" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a single office/home office (SOHO) server role"}
        "Unspecified" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - UnspecifieThe OEM did not specify a specific role"}
        "Workstation" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a workstation role"}
    }

    switch($computerSystem.CsPCSystemTypeEx)
    {
        "AppliancePC" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified an appliance PC role"}
        "Desktop" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a desktop role"}
        "EnterpriseServer" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified an enterprise server role"}
        "MaximumEnumValue" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - Max enum value"}
        "Mobile" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a mobile role (for example, a laptop)"}
        "PerformanceServer" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a performance server role"}
        "Slate" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a tablet form factor role"}
        "SOHOServer" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a single office/home office (SOHO) server role"}
        "Unspecified" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - UnspecifieThe OEM did not specify a specific role"}
        "Workstation" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a workstation role"}
    }
    if ($computerSystem.CsPowerManagementSupported)
    {
        $computerSystem.CsPowerManagementSupported="Device can be power managed. Property does not indicate that power management features are not enabled currently, but it indicates that the device is capable of power management."       
    }
    else
    {
         $computerSystem.CsPowerManagementSupported="Device cannot be power managed."   
    }
    $computerSystem.CsPowerOnPasswordStatus="$($computerSystem.CsPowerOnPasswordStatus) - Hardware security setting for PowerOn Password Status is $($computerSystem.CsPowerOnPasswordStatus)"

    $computerSystem.CsPowerState="$($computerSystem.CsPowerState) - Current power state of computer is  $($computerSystem.CsPowerState)"

    #CsPowerSupplyState

    $os=$computerInfo | Select-Object OsName,OsType,OsVersion,OsBuildNumber,OsBootDevice,OsSystemDevice,OsSystemDirectory,OsSystemDrive,OsWindowsDirectory,OsCountryCode,OsCurrentTimeZone,OsLastBootUpTime,OsUptime,OsDataExecutionPrevention,OsDataExecutionPrevention32bitApplications,OsDataExecutionPreventionDrivers,OsDataExecutionPreventionSupportPolicy,OsTotalVisibleMemorySize,OsFreePhysicalMemory,OsTotalVirtualMemorySize,OsFreeVirtualMemory,OsInUserVirtualMemory,OsTotalSwapSpaceSize,OsSizeStoredInPagingFiles,OsFreeSpaceInPagingFiles,OsManufacturer,OsMaxNumberOfProcesses,OsOrganization,OsArchitecture,OsLanguage,OsPortableOperatingSystem,OsProductType,OsRegisteredUser
    $hyperV=$computerInfo | Select-Object HyperVisorPresent,HyperVRequirementDataExecutionPreventionAvailable,HyperVRequirementSecondLevelAddressTranslation,HyperVRequirementVirtualizationFirmwareEnabled,HyperVRequirementVMMonitorModeExtensions
    $deviceGuard=$computerInfo | Select-Object DeviceGuardSmartStatus,DeviceGuardRequiredSecurityProperties,DeviceGuardAvailableSecurityProperties,DeviceGuardSecurityServicesConfigured,DeviceGuardSecurityServicesRunning,DeviceGuardCodeIntegrityPolicyEnforcementStatus,DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus

    $basicInformation = [PSCustomObject]@{
        BasicInformation = $basic
        Bios             = $bios
        ComputerSystem   = $computerSystem
        OperatingSystem  = $os
        HyperV           = $hyperV
        DeviceGuard      = $deviceGuard
    }
    $basicInformation
}
function Get-HardwareInfo
{
    $hardwareInformation = [PSCustomObject]@{
        Controller1394 = Get-1394Controller
        BaseBoard = Get-BaseBoard
        Battery = Get-Battery
        Bios             = Get-BIOS
        Bus = Get-Bus
        CacheMemory = Get-CacheMemory
        CDROM = Get-CDROMDrive
        CompactDisc = Get-CompactDisc
        Desktop = Get-Desktop
        DesktopMonitor = Get-DesktopMonitor
        DiskDrive = Get-DiskDrive
        DiskPartition = Get-DiskPartition
        Fan=Get-Fan
        Glide = Get-GlidePoint
        HeatPipe = Get-HeatPipe
        IDE=Get-IDEController
        InfraredDevice=Get-InfraredDevice
        Keyboard = Get-Keyboard
        LocalDisk=Get-LocalDisk
        LogicalDisk=Get-LogicalDisk
        MemoryArray=Get-MemoryArray
        MemoryDevice=Get-MemoryDevice
        MotherBoardDevice=Get-MotherboardDevice
        Mouse=Get-Mouse
        NetworkAdapter=Get-NetworkAdapterSysInfo
        NetworkAdapterConfiguration=Get-NetworkAdapterConfiguration
        NetworkDrive=Get-NetworkDrive
        OperatingSystem=Get-OperatingSystem
        OpticalSensor=Get-OpticalSensor
        PhysicalMemory=Get-PhysicalMemory
        PhysicalMemoryArray=Get-PhysicalMemoryArray
        PointingDevice=Get-PointingDevice
        PortableBattery=Get-PortableBattery
        PrinterConfiguration=Get-PrinterConfiguration
        Processor=Get-Processor
        RAMDisk=Get-RAMDisk
        Refrigeration=Get-Refrigeration
        RemovableDisk=Get-RemovableDisk
        SCSIController=Get-SCSIControllerSysInfo
        SoundDevice=Get-SoundDevice
        SystemEnclousure=Get-SystemEnclosure
        TapeDrive=Get-TapeDrive
        TemperatureProbe=Get-TemperatureProbe
        TouchPad=Get-TouchPad
        TouchScreen=Get-TouchScreen
        TrackBall=Get-TrackBall
        TrackPoint=Get-TrackPoint
        USBController=Get-USBController
        VideoController=Get-VideoController
        VoltageProbe=Get-VoltageProbe
    }
    $hardwareInformation
}
function Get-MotherBoard
{
Get-CimInstance Win32_BaseBoard | Select-Object * -ExcludeProperty CreationClassNAme,PSComputerName,Cim*

}


function New-HTMLTable()
{
    [CmdletBinding()]
    param (
    [Parameter(HelpMessage="Table content,Position=0")]
    [Alias("TableContent","TC")]
    $content
    )

    $output="<table><tr><td>KEY</td><td>VALUE</td></tr>"
    $content.PSObject.Properties | ForEach-Object { 
        $output += "<tr><td>$($_.Name)</td><td>$($_.Value)</td></tr>"
    }
    $output += "</table>"
    return $output
}


$HTMLBody1 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).BasicInformation)
$HTMLBody2 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).Bios)
$HTMLBody3 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).ComputerSystem)
$HTMLBody4 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).OperatingSystem)
$HTMLBody5 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).HyperV)
$HTMLBody6 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).DeviceGuard)

$HTMLBody7 = New-HTMLTable -TableContent $(Get-MotherBoard)
############################################################################################################
function New-JSScript()
{
$script=@"
    <script>
    function changeContent(content) 
    {
        document.getElementById('lama').innerHTML = content;
    }
    function myAccFunc() 
    {
        var x = document.getElementById("demoAcc");
        if (x.className.indexOf("w3-show") == -1) 
        {
            x.className += " w3-show";
            x.previousElementSibling.className += " w3-green";
        } 
        else 
        {
            x.className = x.className.replace(" w3-show", "");
            x.previousElementSibling.className =
            x.previousElementSibling.className.replace(" w3-green", "");
        }
    }
        </script>
"@
return $script
}

function New-HTMLHead()
{
$head=@"
    <head>
        <title>W3.CSS</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    </head>
"@
return $head
}


function New-HTMLBody()
{
$report=@"
<!DOCTYPE html>
<html>
$(New-HTMLHead)
<body>
    <div class="w3-sidebar w3-bar-block w3-light-grey w3-card" style="width:160px;">
        <a href="#" class="w3-bar-item w3-button">Link 1</a>
        
        <div class="w3-bar-item w3-button" onclick="myAccFunc()">
            Accordion <i class="fa fa-caret-down"></i>
        </div>
        
        <div id="demoAcc" class="w3-hide w3-white w3-card-4">
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody1')">BasicInformation</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody2')">Bios</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody3')">ComputerSystem</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody4')">OperatingSystem</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody5')">HyperV</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody6')">DeviceGuard</a>
        </div>
        
        <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody7')">MotherBoard</a>
        
        <a class="w3-bar-item w3-button" >Link 3</a>
        
    </div>
    
    <div class="w3-container" id="lama" style="margin-left:160px">
    adsdsa
    </div>
$(New-JSScript)
</body>
</html>
"@

return $report
}
New-HTMLBody | Out-File "test.html"