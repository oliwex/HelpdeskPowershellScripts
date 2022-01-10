
function Get-BasicComputerInfo
{
    $computerInfo=Get-ComputerInfo
    $basic=$computerInfo | Select-Object WindowsEditionId,WindowsInstallationType,WindowsInstallDateFromRegistry,WindowsProductName,WindowsRegisteredOrganization,WindowsRegisteredOwner,WindowsSystemRoot,TimeZone,LogonServer,PowerPlatformRole
    $bios=$computerInfo | Select-Object BiosInstallDate,BiosManufacturer,BiosName,BiosReleaseDate,BiosSeralNumber,BiosStatus,BiosSystemMajorVersion,BiosSystemMinorVersion
    $computerSystem=$computerInfo | Select-Object CsCaption,CsChassisSKUNumber,CsCurrentTimeZone,CsDescription,CsDNSHostName,CsDomain,CsDomainRole,CsManufacturer,CsModel,CsName,CsNumberOfLogicalProcessors,CsNumberOfProcessors,CsPartOfDomain,CsPCSystemType,CsPowerManagementSupported,CsPowerOnPasswordStatus,CsPowerState,CsSystemFamily,CsSystemType,CsThermalState,CsTotalPhysicalMemory,CsPhysicallyInstalledMemory,CsUserName
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

$($(Get-HardwareInfo).DesktopMonitor)

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
        
        <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody1')">Link 2</a>
        
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