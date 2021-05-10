$computerName=Read-Host "Give me computerName: "
$computerType=Read-Host "Give me type:(L/SR)"

if ($computerType -eq "L")
{
    "LAPTOP"
    Get-ADComputer $computerName | Move-ADObject -TargetPath "OU=Laptopy,OU=Urzadzenia,DC=gif,DC=gov,DC=pl"
}
else
{
    "Stacja Robocza"
    Get-ADComputer $computerName | Move-ADObject -TargetPath "OU=Stacje Robocze,OU=Urzadzenia,DC=gif,DC=gov,DC=pl"
}


