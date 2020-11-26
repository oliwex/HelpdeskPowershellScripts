param(
$softwareList,
$filesSystem
)

$softwareList
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

    $softwareReport = [ordered]@{}

    $32bitPath = "HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\" 
    $64bitPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
    
    foreach ($programName in $softwareList.Keys)
    {

        $32bitElementName=(Get-ChildItem $32bitPath | Get-ItemProperty | Where-Object { ($_.DisplayName -like "*$programName*") -and ($_.Publisher -like "*$($softwareList[$programName])*") }).PSChildName | Select-Object -Last 1
        $32bitPathProgram=Join-Path -Path $32bitPath -ChildPath $32bitElementName
        
        $64bitElementName=(Get-ChildItem $64bitPath | Get-ItemProperty | Where-Object { ($_.DisplayName -like "*$programName*") -and ($_.Publisher -like "*$($softwareList[$programName])*") }).PSChildName | Select-Object -Last 1
        $64bitPathProgram=Join-Path -Path $64bitPath -ChildPath $64bitElementName

        $32bitTest=Test-RegistryKeyValueExist -Path $32bitPathProgram -Name DisplayName
        $64bitTest=Test-RegistryKeyValueExist -Path $64bitPathProgram -Name DisplayName
        
        if ($64bitTest) #Test 64bit
        {
            $programInfo=Get-ItemProperty $64bitPathProgram | Select-Object DisplayName, Version, InstallDate, Publisher, InstallLocation
            $softwareReport.Add($programName,$programInfo)
        }
        elseif ($32bitTest) #Test 32bit
        {
            $programInfo=Get-ItemProperty $32bitPathProgram | Select-Object DisplayName, Version, InstallDate, Publisher, InstallLocation 
            $softwareReport.Add($programName,$programInfo)
        }
        else
        {
            $softwareReport.Add($programName,"UNSET")
        }
    }

   return $softwareReport
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

$fullReport=[ordered]@{
    HARDWARE=$hardwareSystem;
    QUOTA=$quotaSystem;
    SOFTWARE=$softwareSystem;
    FILESHARE=$filesSystem;
    NETWORK=$networkSystem;
    PRINTER=$printerSystem;
    SERVICE=$serviceSystem;
    FIREWALL=$firewallSystem;
    DEFENDER=$defenderSystem;
    LOG=$logReport;
    FIRST=$false
    }

#############################################################################################
#############################################################################################
#############################################################################################
$header = @"
<style>

    h1 {

        font-family: Arial, Helvetica, sans-serif;
        color: #e68a00;
        font-size: 28px;

    }

    
    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;

    }

    
    
   table {
		font-size: 12px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }
    


    #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;

    }



    .StopStatus {

        color: #ff0000;
    }
    
  
    .RunningStatus {

        color: #008000;
    }




</style>
"@
####################################################################################################
####################################################################################################
####################################################################################################
function New-ReportElement
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,HelpMessage="ReportElement",Position=1)]
    $reportElement
    )
    $reportElement=[PSCustomObject]$reportElement | ConvertTo-Html -As Table -Fragment
    return $reportElement 
}


####################################################################################################
####################################################################################################
####################################################################################################

$reportTitle="<h1>Computer name: HOST1</h1>"


#HARDWARE
$hardwareReportTitle="<h2>Hardware Report</h2>"
$disk=New-ReportElement -reportElement $($fullReport.HARDWARE).Disk
$processor=New-ReportElement -reportElement $($fullReport.HARDWARE).Processor
$memory=New-ReportElement -reportElement $($fullReport.HARDWARE).Memory
$videoController=New-ReportElement -reportElement $($fullReport.HARDWARE).VideOController
$hardwareReport = ConvertTo-HTML -Body "<div class='hardware'>$hardwareReportTitle $disk $processor $memory $videoController</div>"  


#QUOTA
$title="<h2>Quota Report</h2>"
$element=New-ReportElement -reportElement $fullReport.QUOTA
$nquotaReport = ConvertTo-HTML -Body "<div class='quota'>$title $element</div>"


#SOFTWARE
#FILESHARE


#NETWORK
$title="<h2>Network Report</h2>"
$element=New-ReportElement -reportElement $fullReport.NETWORK
$networkReport = ConvertTo-HTML -Body "<div class='network'>$title $element</div>"

#PRINTER
$title="<h2>Printer Report</h2>"
$element=New-ReportElement -reportElement $fullReport.PRINTER
$printerReport = ConvertTo-HTML -Body "<div class='printer'>$title $element</div>"

#SERVICE
$serviceReportTitle="<h2>Service Report</h2>"
$AppIDSvc=New-ReportElement -reportElement $($fullReport.SERVICE).AppIDSvc
$mpssvc=New-ReportElement -reportElement $($fullReport.SERVICE).mpssvc
$W32Time=New-ReportElement -reportElement $($fullReport.SERVICE).W32Time
$WinDefend=New-ReportElement -reportElement $($fullReport.SERVICE).WinDefend
$wuauserv=New-ReportElement -reportElement $($fullReport.SERVICE).wuauserv
$serviceReport = ConvertTo-HTML -Body "<div class='service'>$serviceReportTitle $AppIDSvc $mpssvc $W32Time $WinDefend $wuauserv</div>"  

#FIREWALL
$firewallReportTitle="<h2>Firewall Report</h2>"
$domain=New-ReportElement -reportElement $($fullReport.FIREWALL).Domain
$private=New-ReportElement -reportElement $($fullReport.FIREWALL).Private
$public=New-ReportElement -reportElement $($fullReport.FIREWALL).Public
$firewallReport = ConvertTo-HTML -Body "<div class='firewall'>$firewallReportTitle $domain $private $public</div>"  

#DEFENDER
$title="<h2>Defender Report</h2>"
$element=New-ReportElement -reportElement $fullReport.DEFENDER
$defenderReport = ConvertTo-HTML -Body "<div class='defender'>$title $element</div>"


#MERGE
$report = ConvertTo-HTML -Head $header -Body "<div class='report'>$hardwareReport $quotaReport $networkReport $printerReport $serviceReport $firewallReport $defenderReport</div>"  
$report | Out-File C:\Basic-Computer-Information-Report.html


