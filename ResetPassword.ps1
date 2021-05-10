$user=Read-Host "Give me login: "
$password=Read-Host "Give me password: "
Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force) -Credential
Read-Host "The password have been reset!!!"