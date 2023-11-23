$starsze=30
Get-Content -Path "D:\lista_stacji.txt" | ForEach-Object {
    if ((Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $($_)).Caption -like "*7*")
    {
        Get-WmiObject -class Win32_UserProfile -ComputerName $($_) | Where-Object {($_.Special -eq $false) -and ($_.Loaded -eq $false) -and ($_.LocalPath -notlike "*user*") -and ($_.LocalPath -notlike "*Administrator*") -and ($_.LastUseTime -lt $((Get-Date).AddDays(-$starsze)))} | Select-Object LocalPath 
    }
    else 
    {
        Get-CimInstance -class Win32_UserProfile -ComputerName $($_) | Where-Object {($_.Special -eq $false) -and ($_.Loaded -eq $false) -and ($_.LocalPath -notlike "*user*") -and ($_.LocalPath -notlike "*Administrator*") -and ($_.LastUseTime -lt $((Get-Date).AddDays(-$starsze)))} | Select-Object LocalPath 
    }  
}
