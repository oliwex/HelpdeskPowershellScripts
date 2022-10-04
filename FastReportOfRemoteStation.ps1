Invoke-Command -ComputerName computerName {
    [PsCustomObject]@{
        SYSTEM=(Get-WmiObject Win32_OperatingSystem).Caption
        SPRZET=(Get-WmiObject Win32_ComputerSystem).SystemFamily
        PAMIEC=(Get-WmiObject Win32_PhysicalMemory).Capacity
    }
}