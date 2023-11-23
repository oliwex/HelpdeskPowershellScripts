$sciezka=Read-Host "Podaj sciezke do pliku"
Get-Content $sciezka | Foreach-Object {
[PsCustomObject]@{
KOMPUTER=$($_)
POLOCZENIE=$(Test-Connection $($_) -Count 3 -Quiet)
}
} | Out-File "D:\lama.txt"