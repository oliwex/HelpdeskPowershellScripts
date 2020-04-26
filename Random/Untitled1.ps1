$result=[ordered]@{}

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
   
##################################

Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueToCheck NoAutorun -HashtableRowName AutorunEnabled -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueToCheck NoDriveTypeAutoRun -HashtableRowName DefaultAutorun -HashtableResult $result

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

Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\DriverSearching' -ValueToCheck DontSearchFloppies -HashtableRowName DontSearchFloppiesForDrivers -HashtableResult $result
Get-RegistryValueWithDisabledValue -Path 'HKCU:\Software\Policies\Microsoft\Windows NT\Driver Signing' -ValueToCheck BehaviorOnFailedVerify -HashtableRowName BehaviorOnFailedVerify -HashtableResult $result
######################################
Get-RegistryValueWithDisabledValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices' -ValueToCheck Deny_All -HashtableRowName DenyAll -HashtableResult $result

$result

######################################
#Lista podlaczonych pendrivow#
$usbList=(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select -ExpandProperty FriendlyName)
$usbList









