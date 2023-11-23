Get-Content -Path "D:\lista_stacji.txt" | ForEach {
    [PsCustomObject]@{
        ComputerName = $_
        ProfileCount = (Get-CimInstance Win32_UserProfile -Filter "Special=False AND Loaded=False" -ComputerName $_).Count
    }
} | Sort-Object -Descending ProfileCount 
