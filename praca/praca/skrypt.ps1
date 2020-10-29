###################BEFORE FUNCTIONS#####################
Set-ExecutionPolicy -ExecutionPolicy Bypass

function Prepare-Modules
{

    $moduleList=Get-Module -Name Carbon,NTFSSecurity,SysInfo | Select -ExpandProperty Name

    $isCarbonExist=$moduleList.Contains("Carbon")
    $isNTFSSecExist=$moduleList.Contains("NTFSSecurity")
    $isSysInfoExist=$moduleList.Contains("SysInfo")

    if (-not($isCarbonExist -and $isNTFSSecExist -AND $isSysInfoExist))
    {
        Install-Module -Name Carbon,NTFSSecurity,SysInfo -AllowClobber -Force
    }

    $moduleList=Get-InstalledModule -Name Carbon,NTFSSecurity,SysInfo | Select -ExpandProperty Name

    $isCarbonExist=$moduleList.Contains("Carbon")
    $isNTFSSecExist=$moduleList.Contains("NTFSSecurity")
    $isSysInfoExist=$moduleList.Contains("SysInfo")

    if (-not($isCarbonExist -and $isNTFSSecExist -AND $isSysInfoExist))
    {
        Import-Module -Name Carbon,NTFSSecurity,SysInfo
    }
}
Prepare-Modules

######################FUNCTIONS#########################

function Get-ComputerReport 
{
##requires SysInfo
    $computerReport = [ordered]@{
        "Disk"            = Get-DiskDrive | Select-Object Caption, @{Name = "Size"; Expression = { [Math]::Round(($_.Size / 1GB), 2), "GB" -join " " } }
        "Processor"       = Get-Processor | Select-Object Name, @{Name = "TDP"; Expression = { $_.MaxClockSpeed } }
        "Memory"          = Get-PhysicalMemoryArray | Select-Object @{Name = "RAM"; Expression = { ($_.MaxCapacity / 1MB), "GB" -join " " } }
        "VideoController" = Get-VideoController | Where-Object { $_.DeviceId -eq "VideoController1" } | Select-Object Name, @{Name = "RAM"; Expression = { ($_.AdapterRam / 1GB), "GB" -join " " } }
    }

    return $computerReport
}

function Get-QuotaReport 
{
    ##requires Carbon
    $unitList ="KB", "MB", "GB", "TB", "PB", "EB"
    $path="HKLM:\Software\Policies\Microsoft\Windows NT"

    $pathExist=Test-RegistryKeyValue -Path $path -Name "DiskQuota"

    $path=Join-Path -Path $path -ChildPath "DiskQuota"

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

        $32bitTest=Test-RegistryKeyValue -Path $32bitPathProgram -Name DisplayName
        $64bitTest=Test-RegistryKeyValue -Path $64bitPathProgram -Name DisplayName
    

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
    $DHCPStatus=Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$id" | Select-Object -ExpandProperty EnableDHCP

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

function Get-PrintReport
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


    $test=Test-RegistryKeyValue -Path $paths[0] -Name "AVSignatureDue"
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
        $testRetention=Test-RegistryKeyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$_ -Name "Retention"
        
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
Get-ComputerReport
"-----------------"
Get-QuotaReport
"-----------------"
Get-SoftwareReport -softwareList $args[0]
"-----------------"
$args[1]
"-----------------"
Get-NetworkReport
"-----------------"
Get-PrintReport
"-----------------"
Get-ServiceReport
"-----------------"
Get-FirewallReport
"-----------------"
Get-DefenderReport
"-----------------"
Get-LogReport
