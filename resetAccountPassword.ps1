$user=Read-Host "Podaj login: "
$password=Read-Host "Podaj has³o: "
Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
Read-Host "The password have been resetg!!!"