ComputerName | ForEach-Object {

$memory =  $(Get-WmiObject -Class WIN32_OperatingSystem -ComputerName $($_))
$memoryPercentage = ((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory)*100)/ $memory.TotalVisibleMemorySize)
$processList = Get-WmiObject WIN32_PROCESS -ComputerName $($_)  | Sort-Object -Property ws -Descending | Select-Object -first 5 processname, @{Name="Mem Usage(MB)";Expression={[math]::round($_.ws / 1mb)}}

    [PsCustomObject]@{
    Computer=$($_)
    MemoryPercentage=$memoryPercentage
    ProcessList=$processList
    }
}