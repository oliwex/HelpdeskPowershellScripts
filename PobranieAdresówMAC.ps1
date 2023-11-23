Get-Content -Path "D:\lista_stacji.txt" | ForEach-Object {
    [PsCustomObject]@{
        NAZWA=$($_)
        MAC=(Get-CimInstance -ComputerName $($_) -Query 'Select * From Win32_NetworkAdapter Where NetConnectionStatus=2').MacAddress
    }
} | Tee-Object -FilePath MAC.txt
