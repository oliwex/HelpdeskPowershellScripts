param(
$softwareList,
$filesSystem
)


###################BEFORE FUNCTIONS#####################
Set-ExecutionPolicy -ExecutionPolicy Bypass

##################TOOL FUNCTIONS########################
function Test-RegistryKeyValueExist 
{

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    if ( -not (Test-Path -Path $Path -PathType Container) ) {
        return $false
    }
    $properties = Get-ItemProperty -Path $Path 
    if ( -not $properties )  {
        return $false
    }
    $member = Get-Member -InputObject $properties -Name $Name
    if ( $member ) {
        return $true
    }
    else {
        return $false
    }
}

function Prepare-Workplace
{
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,HelpMessage="Path",Position=0)]
    [String]$path,
    [Parameter(Mandatory=$true,HelpMessage="GroupName",Position=1)]
    [String]$folder
)

    New-Item –Path $path –Name $folder -ItemType RegistryKey
    $finalPath=Join-Path -Path $path -ChildPath $folder

    "HARDWARE","QUOTA","SOFTWARE","FILESHARE","NETWORK","PRINTER","SERVICE","FIREWALL","LOG","DEFENDER" | foreach-Object {
    New-Item –Path $finalPath –Name $_ -ItemType RegistryKey
    }
}

function Save-ToRegistry2Level
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="Path",Position=0)]
        [String]$pathToRegistry,
        [Parameter(Mandatory=$true,HelpMessage="DataToSave",Position=1)]
        $hashtableData
    )

    foreach ($dataElement in $hashtableData.Keys) 
    {
        $dataName = $hashtableData[$dataElement]
        $keyPath = Join-Path $pathToRegistry -ChildPath $dataElement
        New-Item -Path $pathToRegistry -Name $dataElement -ItemType RegistryKey
    
        foreach ($property in $dataName.PSObject.Properties) 
        {
            New-ItemProperty -Path $keyPath -Name $property.Name -Value $property.Value -Force
        }
    }
}

function Save-ToRegistry1Level
{
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,HelpMessage="Path",Position=0)]
    [String]$pathToRegistry,
    [Parameter(Mandatory=$true,HelpMessage="DataToSave",Position=1)]
    $hashtableData
)

    foreach ($element in $hashtableData.Keys)
    {
        New-ItemProperty -Path $pathToRegistry -Name $element -Value $hashtableData[$element] -Force
    }
}

function Get-Registry1LevelData
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="Path",Position=0)]
        [String]$pathToRegistry
    )
    $registryLevel1Data=[ordered]@{}
    $reg=Get-ItemProperty -Path $pathToRegistry
    $reg.PSObject.Properties  | Where-Object {$_.Name -NotLike "PS*"} | ForEach-Object { $registryLevel1Data.Add($_.Name,$_.Value)}
    return $registryLevel1Data
}

function Get-Registry2LevelData
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="Path",Position=0)]
        [String]$pathToRegistry
    )
    $registryLevel2Data=[ordered]@{}
    $elements=Get-ChildItem -Path $pathToRegistry | Select-Object -ExpandProperty Name | ForEach-Object { $_.Substring($_.LastIndexOf("\")+1)}
    foreach($element in $elements)
    {
        $fullPath=Join-Path -Path $pathToRegistry -ChildPath $element
        $data=Get-Registry1LevelData -pathToRegistry $fullPath
        $registryLevel2Data.Add($element,$data)
    }
    return $registryLevel2Data
}

Function Compare-Hashtables1Level
{
param(

        [Parameter(Position = 0, Mandatory = $true)]
        $fromSystem
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        $fromRegistry
    )
     
    $resultObject = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($element in $fromRegistry.Keys)
    {
        if($fromRegistry[$element] -eq $fromSystem[$element])
        {
            $state="NOTCHANGED"
        }
        else
        {
            $state="CHANGED"
        }
        $object = [PSCustomObject]@{
        ELEMENT       = $element
        STATUS       = $state
        CURRENT_STATE = $fromSystem[$element]
        }
        $resultObject.Add($object)
    }

return $resultObject
}

Function Compare-Hashtables2Level
{
param(

        [Parameter(Position = 0, Mandatory = $true)]
        $fromSystem
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        $fromRegistry
    )
    $resultHashtable=[ordered]@{}

    foreach ($element in $fromSystem.Keys)
    {
        $tmp1=$($fromSystem.$element) 
        $tmp2=$($fromRegistry.$element)
        $tmp1=ConvertTo-Hashtable -object $tmp1
        $result=Compare-Hashtables1Level -fromSystem $tmp1 -fromRegistry $tmp2
        $resultHashtable.Add($element,$result)
    }
return $resultHashtable
}

function ConvertTo-Hashtable
{
  param(
        [Parameter(Position = 0, Mandatory = $true)]
        $object
        )

$applicationHashtable=[ordered]@{}
$object.psobject.properties | Foreach { $applicationHashtable[$_.Name] = $_.Value }

return $applicationHashtable 
}

######################FUNCTIONS#########################

function Get-ComputerReport 
{
    $computerReport = [ordered]@{
        "Disk"            = Get-Disk | Where-Object {$_.Number -eq 0 } | Select-Object FriendlyName, @{Name = "Size"; Expression = { (($_.Size)/1GB), "GB" -join " "} }
        "Processor"       = Get-CimInstance -Class Win32_Processor | Select-Object Name, @{Name = "TDP"; Expression = { $_.MaxClockSpeed } }
        "Memory"          = Get-CimInstance Win32_ComputerSystem | Select-Object @{Name="RAM";Expression={ [MATH]::Round(($_.TotalPhysicalMemory / 1GB),2), "GB" -join " "}}
        "VideoController" = Get-CimInstance Win32_VideoController | Where-Object { $_.DeviceId -eq "VideoController1" } | Select-Object Name, @{Name = "RAM"; Expression = { ($_.AdapterRam / 1GB), "GB" -join " " } }
    }

    return $computerReport
}

function Get-QuotaReport 
{
    ##requires Carbon
    $unitList ="KB", "MB", "GB", "TB", "PB", "EB"
    $path="HKLM:\Software\Policies\Microsoft\Windows NT"

    $path=Join-Path -Path $path -ChildPath "DiskQuota"
    $pathExist=Test-Path -Path $path

    if ($pathExist)
    {
        $quotaReport = Get-ItemProperty -Path $path | Select-Object Enable, Enforce, Limit, LimitUnits, Threshold, ThresholdUnits
        $quotaReport = [ordered]@{
            "enable"         = $quotaReport.Enable
            "enforce"        = $quotaReport.Enforce 
            "limit"          = $quotaReport.Limit 
            "LimitUnits"     = $unitList[$quotaReport.LimitUnits - 1] 
            "Threshold"      = $quotaReport.Threshold
            "ThresholdUnits" = $unitList[$quotaReport.ThresholdUnits - 1] 
        }
    }
    else 
    {
        $quotaReport = [ordered]@{
            "enable"         ="UNSET" 
            "enforce"        ="UNSET" 
            "limit"          ="UNSET" 
            "LimitUnits"     ="UNSET" 
            "Threshold"      ="UNSET"
            "ThresholdUnits" = "UNSET"
        }
    }
    return $quotaReport
}

function Get-SoftwareReport
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,HelpMessage="SoftwareList",Position=0)]
    $softwareList
    )

    ##requires Carbon
    $programList = [ordered]@{}

    $32bitPath = "HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall" 
    $64bitPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

    foreach ($programName in $softwareList.Keys)
    {
        $32bitPathProgram=Join-Path -Path $32bitPath -ChildPath $programName
        $64bitPathProgram=Join-Path -Path $64bitPath -ChildPath $programName

        $32bitTest=Test-RegistryKeyValueExist -Path $32bitPathProgram -Name DisplayName
        $64bitTest=Test-RegistryKeyValueExist -Path $64bitPathProgram -Name DisplayName

        if ($64bitTest) #Test 64bit
        {
            $programInfo=Get-ChildItem $64bitPath | Get-ItemProperty | Select-Object DisplayName, Version, InstallDate, Publisher, InstallLocation| Where-Object { ($_.DisplayName -like "*$programName*") -and ($_.Publisher -like "*$($softwareList[$programName])*") }
            $programList.Add($programName,$programInfo)
        }
        elseif ($32bitTest) #Test 32bit
        {
            $programInfo=Get-ChildItem $32bitPath | Get-ItemProperty | Select-Object DisplayName, Version, InstallDate, Publisher, InstallLocation | Where-Object { ($_.DisplayName -like "*$programName*") -and ($_.Publisher -like "*$($softwareList[$programName])*") }
            $programList.Add($programName,$programInfo)
        }
        else
        {
            $programList.Add($programName,"UNSET")
        }
    }

    return $programList
}

function Get-NetworkReport
{

    $deviceId=Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"} | Select -ExpandProperty DeviceId
    $DHCPStatus=Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$deviceId" | Select-Object -ExpandProperty EnableDHCP

    if ($DHCPStatus -eq 1)
    {
        #Przypisane DHCP
        $networkInfo=Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$deviceId" | Select-Object @{Name="IPAddress";Expression={$_.DhcpIpAddress}},@{Name="SubnetMask";Expression={$_.DHCPSubnetMask}},@{Name="DefaultGateway";Expression={$_.DHCPDefaultGateway}},@{Name="NameServer";Expression={$_.DHCPNameServer}},@{Name="DHCPServer";Expression={$_.DHCPServer}}
    }
    else
    {
        #Przypisane Manualnie
        $networkInfo=Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$deviceId" | Select-Object  @{Name="IPAddress";Expression={$_.IPAddress}},@{Name="SubnetMask";Expression={$_.SubnetMask}},@{Name="DefaultGateway";Expression={$_.DefaultGateway}},@{Name="NameServer";Expression={$_.NameServer}},@{Name="DHCPServer";Expression={"UNSET"}}
    }

    $network = [ordered]@{
            IPAddress        = $networkInfo.IPAddress
            SubnetMask       = $networkInfo.SubnetMask
            DefaultGateway   = $networkInfo.DefaultGateway
            NameServer       = $networkInfo.NameServer
            DHCPServer       = $networkInfo.DHCPServer
            }

    return $network
}

function Get-PrinterReport
{
    $printer=Get-Printer | Where-Object {(($_.PortName -like "*USB*") -or ($_.PortName -like "192.168.*.*")) -and ($_.DeviceType -eq "Print")} | Select Name,Type,DriverName,PortName,Shared,Published
    $printReport = [ordered]@{}
    foreach ($print in $printer)
    {
        $printReport.Add($print.Name,$print)
    }
    return $printReport
}

function Get-ServiceReport 
{
    $services = Get-Service wuauserv, AppIDSvc, WinDefend, mpssvc, W32Time | Select-Object Name, Status, StartType 
    $serviceReport = [ordered]@{
        "AppIDSvc"  = $services[0]
        "mpssvc"    = $services[1] 
        "W32Time"   = $services[2]
        "WinDefend" = $services[3]
        "wuauserv"  = $services[4]  
    }
    return $serviceReport
}

function Get-FirewallReport 
{
    $firewallReportArray=(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, @{label = "LogFilePath"; expression = { $_.LogFileName } }, @{label = "LogSize"; expression = { $_.LogMaxSizeKilobytes } })
    $firewallReport = [ordered]@{
        Domain  = $firewallReportArray[0]
        Private = $firewallReportArray[1]
        Public  = $firewallReportArray[2]
    }
    return $firewallReport
}

function Get-DefenderReport
{
    $paths="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates","HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"

    $defenderReport = [ordered]@{
        "Windows Defender Status"           = $null
        "Potentially Unwanted Apps"         = $null
        "Removable Drives Scanning"         = $null
        "Scan All Files and Attachments"    = $null
        "Security Update days"              = $null
        "Spyware Update Days"               = $null
    }
    
    $status=Get-ItemProperty -Path $paths[1] | Select @{Name="Windows Defender";Expression={$_.DisableAntiSpyware}}
    if (-not ($status -eq 1))
    {
        $defenderReport["Windows Defender Status"]="SET"
    }
    else
    {
        $defenderReport["Windows Defender Status"]="UNSET"
    }

    $status=Get-MpPreference | Select-Object PUAProtection,DisableRemovableDriveScanning,DisableIOAVProtection  #b,c,d 
    if ($status.PUAProtection -eq 0)
    {
        $defenderReport["Potentially Unwanted Apps"]="UNSET"
    }
    elseif ($status.PUAProtection -eq 1)
    {
        $defenderReport["Potentially Unwanted Apps"]="BLOCK"
    }
    elseif ($status.PUAProtection -eq 2)
    {
        $defenderReport["Potentially Unwanted Apps"]="AUDIT"
    }

    if (-not ($status.DisableRemovableDriveScanning -eq "True"))
    {
        $defenderReport["Removable Drives Scanning"]="SET"
    }
    else
    {
        $defenderReport["Removable Drives Scanning"]="UNSET"
    }

    if (-not ($status.DisableIOAVProtection -eq "True"))
    {
        $defenderReport["Scan All Files and Attachments"]="SET"
    }
    else
    {
        $defenderReport["Scan All Files and Attachments"]="UNSET"
    }

    $test=Test-RegistryKeyValueExist -Path $paths[0] -Name "AVSignatureDue"

    if ($test)
    {
        $defenderElement=Get-ItemProperty -Path $paths[0] | Select-Object @{Name="Security updates days";expression={$_.AVSignatureDue}},@{Name="Spyware update days";expression={$_.ASSignatureDue}}
        $defenderReport["Security Update days"]=$defenderElement."Security updates days"
        $defenderReport["Spyware Update Days"]=$defenderElement."Spyware Update Days"
    }
    else
    {
        $defenderReport["Security Update days"]="UNSET"
        $defenderReport["Spyware Update Days"]="UNSET"
    }

    return $defenderReport
}

function Get-LogReport 
{
    $logs="Application","Setup","System","Security"
    $logReport = [ordered]@{}

    $logs | ForEach-Object {

        $testRetention=Test-RegistryKeyValueExist -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$_  -Name "Retention"

        if ($testRetention)
        {
            
            $logReportValue=Get-WinEvent -ListLog $_ | Select-Object LogName, @{label = "MaximumSizeInBytes"; expression = { $_.MaximumSizeInBytes / 1024 } }, LogMode, @{label = "Retention"; expression = {"SET"} }
        }
        else
        {
            $logReportValue=Get-WinEvent -ListLog $_ | Select-Object LogName, @{label = "MaximumSizeInBytes"; expression = { $_.MaximumSizeInBytes / 1024 } }, LogMode, @{label = "Retention"; expression = {"UNSET"} }
        }
        $logReport.Add($_,$logReportValue)
    }

    return $logReport
}


######################MAIN###########################

$hardwareSystem=Get-ComputerReport


$quotaSystem=Get-QuotaReport
$softwareSystem=Get-SoftwareReport -softwareList $softwareList
#tu można umieścić zmienną $filesSystem która ma hashtable oznaczającą sprawdzenie udziałów sieciowych
$networkSystem=Get-NetworkReport
$printerSystem=Get-PrinterReport
$serviceSystem=Get-ServiceReport
$firewallSystem=Get-FirewallReport
$defenderSystem=Get-DefenderReport
$logSystem=Get-LogReport



$fullReport=[ordered]@{}

$testRegistry=Test-Path -Path HKLM:\SYSTEM\TEST



if ($testRegistry)
{
    #element istnieje

    #odczyt danych z rejestru
    #porównanie danych z rejestru wraz z porównaniem danych z systemu, dane wyjściowe są zapisywane w zmiennych
    $hardwareRegistry=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\HARDWARE"
    $hardwareReport=Compare-Hashtables2Level -fromSystem $hardwareSystem -fromRegistry $hardwareRegistry

    $quotaRegistry=Get-Registry1LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\QUOTA"
    $quotaReport=Compare-Hashtables1Level -fromSystem $quotaSystem -fromRegistry $quotaRegistry

    $softwareRegistry=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\SOFTWARE"
    $softwareReport=Compare-Hashtables2Level -fromSystem $softwareSystem -fromRegistry $softwareRegistry

    $filesRegistry=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\FILESHARE"
    $filesReport=Compare-Hashtables2Level -fromSystem $filesSystem -fromRegistry $filesRegistry

    $networkRegistry=Get-Registry1LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\NETWORK"
    $networkReport=Compare-Hashtables1Level -fromSystem $networkSystem -fromRegistry $networkRegistry

    $printerRegistry=Get-Registry1LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\PRINTER"
    $printerReport=Compare-Hashtables1Level -fromSystem $printerSystem -fromRegistry $printerRegistry

    $serviceRegistry=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\SERVICE"
    $serviceReport=Compare-Hashtables2Level -fromSystem $serviceSystem -fromRegistry $serviceRegistry

    $firewallRegistry=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\FIREWALL"
    $firewallReport=Compare-Hashtables2Level -fromSystem $firewallSystem -fromRegistry $firewallRegistry

    $defenderRegistry=Get-Registry1LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\DEFENDER"
    $defenderReport=Compare-Hashtables1Level -fromSystem $defenderSystem -fromRegistry $defenderRegistry

    $logRegistry=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\LOG"
    $logReport=Compare-Hashtables2Level -fromSystem $logSystem -fromRegistry $logRegistry

    #przeslanie danych do stacji roboczej
    $fullReport=[ordered]@{
    HARDWARE=$hardwareReport;
    QUOTA=$quotaReport;
    SOFTWARE=$softwareReport;
    FILESHARE=$filesReport;
    NETWORK=$networkReport;
    PRINTER=$printerReport;
    SERVICE=$serviceReport;
    FIREWALL=$firewallReport;
    DEFENDER=$defenderReport;
    LOG=$logReport;
    FIRST=$false
    }

}
else
{
    #element nie istnieje
    #zapis do rejestru jako konfiguracja startowa

    Prepare-Workplace -path HKLM:\SYSTEM -folder TEST
    Save-ToRegistry2Level -pathToRegistry "HKLM:\SYSTEM\TEST\HARDWARE" -hashtableData $hardwareSystem
    Save-ToRegistry1Level -pathToRegistry "HKLM:\SYSTEM\TEST\QUOTA" -hashtableData $quotaSystem
    Save-ToRegistry2Level -pathToRegistry "HKLM:\SYSTEM\TEST\SOFTWARE" -hashtableData $softwareSystem
    Save-ToRegistry2Level -pathToRegistry "HKLM:\SYSTEM\TEST\FILESHARE" -hashtableData $filesSystem
    Save-ToRegistry1Level -pathToRegistry "HKLM:\SYSTEM\TEST\NETWORK" -hashtableData $networkSystem
    Save-ToRegistry1Level -pathToRegistry "HKLM:\SYSTEM\TEST\PRINTER" -hashtableData $printerSystem
    Save-ToRegistry2Level -pathToRegistry "HKLM:\SYSTEM\TEST\SERVICE" -hashtableData $serviceSystem
    Save-ToRegistry2Level -pathToRegistry "HKLM:\SYSTEM\TEST\FIREWALL" -hashtableData $firewallSystem
    Save-ToRegistry1Level -pathToRegistry "HKLM:\SYSTEM\TEST\DEFENDER" -hashtableData $defenderSystem
    Save-ToRegistry2Level -pathToRegistry "HKLM:\SYSTEM\TEST\LOG" -hashtableData $logSystem

    #Odczyt danych z rejestru
    $hardwareReport=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\HARDWARE"
    $quotaReport=Get-Registry1LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\QUOTA"
    $softwareReport=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\SOFTWARE"
    $filesReport=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\FILESHARE"
    $networkReport=Get-Registry1LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\NETWORK"
    $printerReport=Get-Registry1LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\PRINTER"
    $serviceReport=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\SERVICE"
    $firewallReport=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\FIREWALL"
    $defenderReport=Get-Registry1LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\DEFENDER"
    $logReport=Get-Registry2LevelData -pathToRegistry "HKLM:\SYSTEM\TEST\LOG"

    #przeslanie danych do stacji roboczej
    $fullReport=[ordered]@{
    HARDWARE=$hardwareReport;
    QUOTA=$quotaReport;
    SOFTWARE=$softwareReport;
    FILESHARE=$filesReport;
    NETWORK=$networkReport;
    PRINTER=$printerReport;
    SERVICE=$serviceReport;
    FIREWALL=$firewallReport;
    DEFENDER=$defenderReport;
    LOG=$logReport;
    FIRST=$true
    }
}

return $fullReport
