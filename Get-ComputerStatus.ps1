function Get-ComputerStatus {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "ComputerName to check",Position=0,ValueFromPipeline)]
        [Alias("Computer")]
        [string]$computerName
    )
    begin{}
    process{
        $memory =  $(Get-WmiObject -Class WIN32_OperatingSystem -ComputerName $computerName)
        $memoryPercentage = [math]::round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory)*100)/ $memory.TotalVisibleMemorySize,5)
        $processList = Get-WmiObject WIN32_PROCESS -ComputerName $computerName  | Sort-Object -Property ws -Descending | Select-Object -first 5 processname, @{Name="Mem Usage(MB)";Expression={[math]::round($_.ws / 1mb)}}

        [PSCustomObject]@{
            COMPUTERNAME = $computerName
            CONNECTION = $(Test-Path "\\$computerName\C$")
            PROCENT_PAMIECI=$memoryPercentage
            LISTA_PROCESOW=$processList
        }
    }
    end{}
}

while($true)
{
    Write-Host "$(Get-Date -Format "HH:mm_dd.MM.yyyy")" -ForegroundColor Green
    Get-Content -Path "D:\lista_stacji.txt" | Get-ComputerStatus
}
