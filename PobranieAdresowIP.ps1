$path=Read-Host "Podaj sciezke do listy stacji"


Get-Content -Path $path |ForEach-Object {
    [PsCustomObject]@{
        NAZWA=$($_)
        IP=((nslookup $($_) | Select-String Address)[1]).ToString().Substring(10)
    }

} | Ft -AutoSize