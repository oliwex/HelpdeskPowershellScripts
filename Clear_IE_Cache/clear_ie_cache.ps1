$path=Read-Host "Podaj scieżkę: "
$computers=Get-Content -Path $path

foreach($computer in $computers)
{
    Invoke-Command -ComputerName $computer -ScriptBlock { 
    $version = (Get-WmiObject -Class Win32_OperatingSystem).Version
    if ($version -eq "6.1") {
        Get-ChildItem -Path "C:\Users" -Directory | ForEach-Object {
            if (Test-Path "$($_.FullName)\AppData\Local\Microsoft\Windows\Temporary Internet Files") {
                Remove-Item "$($_.FullName)\AppData\Local\Microsoft\Windows\Temporary Internet Files" -Recurse -Force -Verbose
            }
            if (Test-Path "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Cookies") {
                Remove-Item "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Cookies" -Recurse -Force -Verbose
            }
        }
    } else {
        Get-ChildItem -Path "C:\Users" -Directory | ForEach-Object {
            if (Test-Path "$($_.FullName)\AppData\Local\Microsoft\Windows\INetCache") {
                Remove-Item "$($_.FullName)\AppData\Local\Microsoft\Windows\INetCache" -Recurse -Force -Verbose
            }
            if (Test-Path "$($_.FullName)\AppData\Local\Microsoft\Windows\INetCookies") {
                Remove-Item "$($_.FullName)\AppData\Local\Microsoft\Windows\INetCookies" -Recurse -Force -Verbose
            }
        }
    }
    }
}

Start-Sleep -Seconds 10