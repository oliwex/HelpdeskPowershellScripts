
While($true)
{
    $datetime=Get-Date -Format "HH.mm.ss.ffff_dd.MM.yyyy"
    $testPing=Test-Connection computer -Quiet
    $memory =  $(Get-WmiObject -Class WIN32_OperatingSystem -ComputerName computer)
    $memoryPercentage = ((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory)*100)/ $memory.TotalVisibleMemorySize)
    $processList = Get-WmiObject WIN32_PROCESS -ComputerName computer  | Sort-Object -Property ws -Descending | Select-Object -first 5 processname, @{Name="Mem Usage(MB)";Expression={[math]::round($_.ws / 1mb)}}
    
    $object=[PsCustomObject]@{
        DATA=$datetime
        COMPUTER="computer"
        PING=$testPing
        MEMORY_PERCENTAGE=$memoryPercentage -f 00.00
        PROCESS_LIST=$processList
    } 
    $object >> C:\lama\computer.txt
    $object
    Start-Sleep -Seconds 10
}