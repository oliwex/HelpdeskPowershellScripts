#Skrypt raportujący nazwę komputera, adres IP, System


$path=Get-Content -Path "C:\lama.txt" 

Get-Content -Path $path | ForEach-Object {

    [PsCustomObject]@{
        Nazwa=$($_)
        IP=((Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $($_) -Filter 'IPEnabled = True').IpAddress[0])
        System=((Get-CimInstance Win32_OperatingSystem -ComputerName $($_)).Caption)
    }

} | Format-Table -AutoSize


