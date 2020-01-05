$userLogin=Read-Host "Give me login: "
$check=Get-AdUser -Identity $userLogin -Properties LockedOut | Select LockedOut
if ($check -eq $true)
{
    Unlock-ADAccount -Identity $userLogin
    "Account is blocked"
}
else
{
    Clear-Host
    "Account is not blocked"
}
Read-Host